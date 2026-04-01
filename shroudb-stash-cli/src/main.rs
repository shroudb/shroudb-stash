use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use shroudb_stash_client::StashClient;

#[derive(Parser)]
#[command(name = "shroudb-stash-cli", about = "Stash CLI")]
struct Cli {
    /// Server address.
    #[arg(long, default_value = "127.0.0.1:6699", env = "STASH_ADDR")]
    addr: String,

    /// Command to execute. If omitted, starts interactive mode.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut client = StashClient::connect(&cli.addr)
        .await
        .with_context(|| format!("failed to connect to {}", cli.addr))?;

    if cli.command.is_empty() {
        interactive(&mut client).await
    } else {
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

async fn execute(client: &mut StashClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await.context("health check failed")?;
            println!("OK");
        }
        "PING" => {
            println!("PONG");
        }
        "STORE" if args.len() >= 3 => {
            let id = args[1];
            // args[2] is either a file path (prefixed with @) or base64 data
            let data = if args[2].starts_with('@') {
                std::fs::read(&args[2][1..])
                    .with_context(|| format!("failed to read file: {}", &args[2][1..]))?
            } else {
                STANDARD
                    .decode(args[2])
                    .context("data must be base64-encoded or @filepath")?
            };

            let keyring = find_option(args, "KEYRING");
            let content_type = find_option(args, "CONTENT_TYPE");

            if let Some(wrapped_dek) = find_option(args, "CLIENT_ENCRYPTED") {
                let result = client
                    .store_client_encrypted(id, &data, wrapped_dek, content_type)
                    .await
                    .context("store failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "id": result.id,
                        "s3_key": result.s3_key,
                        "client_encrypted": result.client_encrypted,
                    }))?
                );
            } else {
                let result = client
                    .store(id, &data, keyring, content_type)
                    .await
                    .context("store failed")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "id": result.id,
                        "s3_key": result.s3_key,
                        "keyring": result.keyring,
                        "key_version": result.key_version,
                        "plaintext_size": result.plaintext_size,
                        "encrypted_size": result.encrypted_size,
                    }))?
                );
            }
        }
        "RETRIEVE" if args.len() >= 2 => {
            let result = client.retrieve(args[1]).await.context("retrieve failed")?;

            // Write blob to stdout or file
            let output_path = find_option(args, "OUTPUT");
            if let Some(path) = output_path {
                std::fs::write(path, &result.data)
                    .with_context(|| format!("failed to write to {path}"))?;
                eprintln!(
                    "wrote {} bytes to {path} (content_type: {})",
                    result.data.len(),
                    result.content_type.as_deref().unwrap_or("unknown")
                );
            } else {
                // Print base64 to stdout
                println!("{}", STANDARD.encode(&result.data));
            }
        }
        "INSPECT" if args.len() >= 2 => {
            let result = client.inspect(args[1]).await.context("inspect failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": result.id,
                    "blob_status": result.blob_status,
                    "content_type": result.content_type,
                    "plaintext_size": result.plaintext_size,
                    "encrypted_size": result.encrypted_size,
                    "keyring": result.keyring,
                    "key_version": result.key_version,
                    "client_encrypted": result.client_encrypted,
                    "viewer_count": result.viewer_count,
                    "created_at": result.created_at,
                    "updated_at": result.updated_at,
                }))?
            );
        }
        "REVOKE" if args.len() >= 2 => {
            let soft = has_flag(args, "SOFT");
            let result = client
                .revoke(args[1], soft)
                .await
                .context("revoke failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": result.id,
                    "revoke_mode": result.revoke_mode,
                }))?
            );
        }
        _ => anyhow::bail!("unknown command: {}", args.join(" ")),
    }

    Ok(())
}

async fn interactive(client: &mut StashClient) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    eprint!("stash> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("stash> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("stash> ");
    }
    Ok(())
}

/// Split a command line by whitespace, preserving JSON objects in braces.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;

    for ch in input.chars() {
        match ch {
            '{' | '[' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' | ']' => {
                brace_depth -= 1;
                current.push(ch);
            }
            ' ' | '\t' if brace_depth == 0 => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn find_option<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    let upper = key.to_uppercase();
    args.windows(2)
        .find(|w| w[0].to_uppercase() == upper)
        .map(|w| w[1])
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_simple() {
        let args = shell_split("STORE my-doc SGVsbG8=");
        assert_eq!(args, vec!["STORE", "my-doc", "SGVsbG8="]);
    }

    #[test]
    fn shell_split_with_options() {
        let args = shell_split("STORE my-doc SGVsbG8= CONTENT_TYPE image/png KEYRING custom");
        assert_eq!(
            args,
            vec![
                "STORE",
                "my-doc",
                "SGVsbG8=",
                "CONTENT_TYPE",
                "image/png",
                "KEYRING",
                "custom"
            ]
        );
    }
}
