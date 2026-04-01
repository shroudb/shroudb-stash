use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;

use crate::object_store::{BoxFut, ObjectMeta, ObjectStore, ObjectStoreError};

/// S3-compatible object store implementation.
///
/// Scoped to a single bucket at construction time. Supports AWS S3, MinIO, R2,
/// and any S3-compatible endpoint.
pub struct S3ObjectStore {
    client: Client,
    bucket: String,
}

/// Configuration for constructing an S3ObjectStore.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    /// Custom endpoint URL for S3-compatible services (MinIO, R2, etc.).
    /// If `None`, uses the default AWS endpoint for the region.
    pub endpoint: Option<String>,
}

impl S3ObjectStore {
    /// Create a new S3ObjectStore from config.
    ///
    /// Uses the default AWS credential chain (env vars, instance profile, etc.).
    pub async fn new(config: S3Config) -> Result<Self, ObjectStoreError> {
        let mut aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));

        if let Some(ref endpoint) = config.endpoint {
            aws_config = aws_config.endpoint_url(endpoint);
        }

        let sdk_config = aws_config.load().await;

        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(config.endpoint.is_some());

        let client = Client::from_conf(s3_config.build());

        // Verify bucket access with a HEAD request.
        client
            .head_bucket()
            .bucket(&config.bucket)
            .send()
            .await
            .map_err(|e| ObjectStoreError::ConnectionFailed {
                detail: format!("cannot access bucket '{}': {e}", config.bucket),
            })?;

        tracing::info!(
            bucket = %config.bucket,
            region = %config.region,
            endpoint = config.endpoint.as_deref().unwrap_or("default"),
            "S3 object store connected"
        );

        Ok(Self {
            client,
            bucket: config.bucket,
        })
    }

    /// Create an S3ObjectStore with a pre-built client (for testing or custom config).
    pub fn with_client(client: Client, bucket: String) -> Self {
        Self { client, bucket }
    }
}

impl ObjectStore for S3ObjectStore {
    fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> BoxFut<'_, ()> {
        let key = key.to_string();
        let body = ByteStream::from(data.to_vec());
        let content_type = content_type.map(String::from);
        Box::pin(async move {
            let mut req = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .body(body);

            if let Some(ct) = content_type {
                req = req.content_type(ct);
            }

            req.send()
                .await
                .map_err(|e| ObjectStoreError::Internal(format!("S3 PUT {key}: {e}")))?;
            Ok(())
        })
    }

    fn get(&self, key: &str) -> BoxFut<'_, Vec<u8>> {
        let key = key.to_string();
        Box::pin(async move {
            let resp = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
                .map_err(|e| {
                    let msg = format!("{e}");
                    if msg.contains("NoSuchKey") || msg.contains("404") {
                        ObjectStoreError::NotFound { key: key.clone() }
                    } else {
                        ObjectStoreError::Internal(format!("S3 GET {key}: {e}"))
                    }
                })?;

            let bytes = resp
                .body
                .collect()
                .await
                .map_err(|e| ObjectStoreError::Internal(format!("S3 GET {key} body: {e}")))?
                .into_bytes()
                .to_vec();

            Ok(bytes)
        })
    }

    fn delete(&self, key: &str) -> BoxFut<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
                .map_err(|e| ObjectStoreError::Internal(format!("S3 DELETE {key}: {e}")))?;
            Ok(())
        })
    }

    fn head(&self, key: &str) -> BoxFut<'_, ObjectMeta> {
        let key = key.to_string();
        Box::pin(async move {
            let resp = self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
                .map_err(|e| {
                    let msg = format!("{e}");
                    if msg.contains("NotFound") || msg.contains("404") {
                        ObjectStoreError::NotFound { key: key.clone() }
                    } else {
                        ObjectStoreError::Internal(format!("S3 HEAD {key}: {e}"))
                    }
                })?;

            Ok(ObjectMeta {
                size: resp.content_length().unwrap_or(0) as u64,
                content_type: resp.content_type().map(String::from),
            })
        })
    }
}
