use shroudb_acl::{AclRequirement, Scope};

/// Parsed Stash wire protocol command.
#[derive(Debug)]
pub enum StashCommand {
    /// Authenticate this connection with a token.
    Auth {
        token: String,
    },

    /// Store an encrypted blob.
    Store {
        id: String,
        data: Vec<u8>,
        keyring: Option<String>,
        content_type: Option<String>,
        client_encrypted: bool,
        wrapped_dek: Option<String>,
    },

    /// Retrieve and decrypt a blob.
    Retrieve {
        id: String,
    },

    /// Inspect blob metadata without decrypting.
    Inspect {
        id: String,
    },

    /// Re-wrap a blob's DEK under the current Cipher key version.
    Rewrap {
        id: String,
    },

    /// Revoke a blob (hard crypto-shred by default, --soft for soft revoke).
    Revoke {
        id: String,
        soft: bool,
    },

    /// List blobs for the current tenant.
    List {
        limit: Option<usize>,
    },

    // Operational
    Health,
    Ping,
    CommandList,
}

impl StashCommand {
    /// The ACL requirement for this command.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            StashCommand::Auth { .. }
            | StashCommand::Health
            | StashCommand::Ping
            | StashCommand::CommandList => AclRequirement::None,

            // Write operations
            StashCommand::Store { id, .. }
            | StashCommand::Rewrap { id }
            | StashCommand::Revoke { id, .. } => AclRequirement::Namespace {
                ns: format!("stash.{id}"),
                scope: Scope::Write,
                tenant_override: None,
            },

            // Read operations
            StashCommand::Retrieve { id } | StashCommand::Inspect { id } => {
                AclRequirement::Namespace {
                    ns: format!("stash.{id}"),
                    scope: Scope::Read,
                    tenant_override: None,
                }
            }

            StashCommand::List { .. } => AclRequirement::Namespace {
                ns: "stash.*".to_string(),
                scope: Scope::Read,
                tenant_override: None,
            },
        }
    }
}

/// Parse raw RESP3 command arguments into a StashCommand.
pub fn parse_command(args: &[&str]) -> Result<StashCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "AUTH" => parse_auth(args),
        "STORE" => parse_store(args),
        "RETRIEVE" => parse_retrieve(args),
        "INSPECT" => parse_inspect(args),
        "REWRAP" => {
            if args.len() < 2 {
                return Err("REWRAP <id>".into());
            }
            Ok(StashCommand::Rewrap {
                id: args[1].to_string(),
            })
        }
        "REVOKE" => parse_revoke(args),
        "LIST" => parse_list(args),
        "HEALTH" => Ok(StashCommand::Health),
        "PING" => Ok(StashCommand::Ping),
        "COMMAND" => Ok(StashCommand::CommandList),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_auth(args: &[&str]) -> Result<StashCommand, String> {
    if args.len() < 2 {
        return Err("AUTH <token>".into());
    }
    Ok(StashCommand::Auth {
        token: args[1].to_string(),
    })
}

fn parse_store(args: &[&str]) -> Result<StashCommand, String> {
    // STORE <id> <data_b64> [KEYRING <name>] [CONTENT_TYPE <mime>] [CLIENT_ENCRYPTED <wrapped_dek>]
    if args.len() < 3 {
        return Err(
            "STORE <id> <data_b64> [KEYRING <name>] [CONTENT_TYPE <mime>] [CLIENT_ENCRYPTED <wrapped_dek>]"
                .into(),
        );
    }

    let id = args[1].to_string();

    // Data is base64-encoded on the wire.
    let data = base64::engine::general_purpose::STANDARD
        .decode(args[2])
        .map_err(|e| format!("invalid base64 data: {e}"))?;

    let keyring = find_option(args, "KEYRING").map(String::from);
    let content_type = find_option(args, "CONTENT_TYPE").map(String::from);

    let (client_encrypted, wrapped_dek) = match find_option(args, "CLIENT_ENCRYPTED") {
        Some(dek) => (true, Some(dek.to_string())),
        None => (false, None),
    };

    Ok(StashCommand::Store {
        id,
        data,
        keyring,
        content_type,
        client_encrypted,
        wrapped_dek,
    })
}

use base64::Engine as _;

fn parse_retrieve(args: &[&str]) -> Result<StashCommand, String> {
    if args.len() < 2 {
        return Err("RETRIEVE <id>".into());
    }
    Ok(StashCommand::Retrieve {
        id: args[1].to_string(),
    })
}

fn parse_inspect(args: &[&str]) -> Result<StashCommand, String> {
    if args.len() < 2 {
        return Err("INSPECT <id>".into());
    }
    Ok(StashCommand::Inspect {
        id: args[1].to_string(),
    })
}

fn parse_revoke(args: &[&str]) -> Result<StashCommand, String> {
    if args.len() < 2 {
        return Err("REVOKE <id> [SOFT]".into());
    }
    let soft = has_flag(args, "SOFT");
    Ok(StashCommand::Revoke {
        id: args[1].to_string(),
        soft,
    })
}

fn parse_list(args: &[&str]) -> Result<StashCommand, String> {
    let limit = find_option(args, "LIMIT")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|e| format!("invalid LIMIT value: {e}"))
        })
        .transpose()?;
    Ok(StashCommand::List { limit })
}

/// Find an optional keyword argument: `KEY value` in the args list.
fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

/// Check if a flag is present in the args.
fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_store_minimal() {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let cmd = parse_command(&["STORE", "blob-1", &data_b64]).unwrap();
        match cmd {
            StashCommand::Store {
                id,
                data,
                keyring,
                content_type,
                client_encrypted,
                wrapped_dek,
            } => {
                assert_eq!(id, "blob-1");
                assert_eq!(data, b"hello");
                assert!(keyring.is_none());
                assert!(content_type.is_none());
                assert!(!client_encrypted);
                assert!(wrapped_dek.is_none());
            }
            _ => panic!("expected Store command"),
        }
    }

    #[test]
    fn parse_store_with_options() {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"data");
        let cmd = parse_command(&[
            "STORE",
            "blob-2",
            &data_b64,
            "KEYRING",
            "custom-kr",
            "CONTENT_TYPE",
            "image/png",
        ])
        .unwrap();

        match cmd {
            StashCommand::Store {
                keyring,
                content_type,
                ..
            } => {
                assert_eq!(keyring.as_deref(), Some("custom-kr"));
                assert_eq!(content_type.as_deref(), Some("image/png"));
            }
            _ => panic!("expected Store command"),
        }
    }

    #[test]
    fn parse_store_client_encrypted() {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"encrypted-data");
        let cmd = parse_command(&[
            "STORE",
            "ce-1",
            &data_b64,
            "CLIENT_ENCRYPTED",
            "wrapped-dek-value",
        ])
        .unwrap();

        match cmd {
            StashCommand::Store {
                client_encrypted,
                wrapped_dek,
                ..
            } => {
                assert!(client_encrypted);
                assert_eq!(wrapped_dek.as_deref(), Some("wrapped-dek-value"));
            }
            _ => panic!("expected Store command"),
        }
    }

    #[test]
    fn parse_store_invalid_base64() {
        let err = parse_command(&["STORE", "blob", "not-valid-b64!!!"]).unwrap_err();
        assert!(err.contains("base64"));
    }

    #[test]
    fn parse_retrieve() {
        let cmd = parse_command(&["RETRIEVE", "blob-1"]).unwrap();
        assert!(matches!(cmd, StashCommand::Retrieve { id } if id == "blob-1"));
    }

    #[test]
    fn parse_inspect() {
        let cmd = parse_command(&["INSPECT", "blob-1"]).unwrap();
        assert!(matches!(cmd, StashCommand::Inspect { id } if id == "blob-1"));
    }

    #[test]
    fn parse_revoke_hard() {
        let cmd = parse_command(&["REVOKE", "blob-1"]).unwrap();
        assert!(matches!(cmd, StashCommand::Revoke { id, soft: false } if id == "blob-1"));
    }

    #[test]
    fn parse_revoke_soft() {
        let cmd = parse_command(&["REVOKE", "blob-1", "SOFT"]).unwrap();
        assert!(matches!(cmd, StashCommand::Revoke { id, soft: true } if id == "blob-1"));
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, StashCommand::Health));
    }

    #[test]
    fn parse_ping() {
        let cmd = parse_command(&["PING"]).unwrap();
        assert!(matches!(cmd, StashCommand::Ping));
    }

    #[test]
    fn parse_command_list() {
        let cmd = parse_command(&["COMMAND"]).unwrap();
        assert!(matches!(cmd, StashCommand::CommandList));
    }

    #[test]
    fn parse_unknown_command() {
        let err = parse_command(&["NOPE"]).unwrap_err();
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn parse_empty_command() {
        let err = parse_command(&[]).unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_missing_args() {
        assert!(parse_command(&["STORE"]).is_err());
        assert!(parse_command(&["RETRIEVE"]).is_err());
        assert!(parse_command(&["INSPECT"]).is_err());
        assert!(parse_command(&["REVOKE"]).is_err());
        assert!(parse_command(&["AUTH"]).is_err());
    }

    #[test]
    fn acl_requirements() {
        let cmd = StashCommand::Health;
        assert!(matches!(cmd.acl_requirement(), AclRequirement::None));

        let cmd = StashCommand::Store {
            id: "test".into(),
            data: vec![],
            keyring: None,
            content_type: None,
            client_encrypted: false,
            wrapped_dek: None,
        };
        assert!(matches!(
            cmd.acl_requirement(),
            AclRequirement::Namespace {
                scope: Scope::Write,
                ..
            }
        ));

        let cmd = StashCommand::Retrieve { id: "test".into() };
        assert!(matches!(
            cmd.acl_requirement(),
            AclRequirement::Namespace {
                scope: Scope::Read,
                ..
            }
        ));

        let cmd = StashCommand::Revoke {
            id: "test".into(),
            soft: false,
        };
        assert!(matches!(
            cmd.acl_requirement(),
            AclRequirement::Namespace {
                scope: Scope::Write,
                ..
            }
        ));
    }

    #[test]
    fn case_insensitive_commands() {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(b"test");
        assert!(parse_command(&["store", "id", &data_b64]).is_ok());
        assert!(parse_command(&["RETRIEVE", "id"]).is_ok());
        assert!(parse_command(&["inspect", "id"]).is_ok());
        assert!(parse_command(&["Revoke", "id"]).is_ok());
        assert!(parse_command(&["health"]).is_ok());
        assert!(parse_command(&["ping"]).is_ok());
    }
}
