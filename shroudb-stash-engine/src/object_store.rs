use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// Metadata returned by a HEAD operation.
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub size: u64,
    pub content_type: Option<String>,
}

/// Errors from object store operations.
#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("object not found: {key}")]
    NotFound { key: String },

    #[error("access denied: {detail}")]
    AccessDenied { detail: String },

    #[error("connection failed: {detail}")]
    ConnectionFailed { detail: String },

    #[error("object store error: {0}")]
    Internal(String),
}

/// Boxed future type for ObjectStore trait methods.
pub type BoxFut<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ObjectStoreError>> + Send + 'a>>;

/// Abstraction over an S3-compatible object store.
///
/// Implementations are scoped to a single bucket at construction time.
/// Keys are relative paths within the bucket.
pub trait ObjectStore: Send + Sync {
    /// Upload an object. Overwrites if the key already exists.
    fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> BoxFut<'_, ()>;

    /// Download an object's bytes.
    fn get(&self, key: &str) -> BoxFut<'_, Vec<u8>>;

    /// Delete an object. Returns Ok even if the key doesn't exist (idempotent).
    fn delete(&self, key: &str) -> BoxFut<'_, ()>;

    /// Get object metadata without downloading the body.
    fn head(&self, key: &str) -> BoxFut<'_, ObjectMeta>;
}

/// In-memory object store for testing.
///
/// Thread-safe via `tokio::sync::RwLock`. Not intended for production use.
pub struct InMemoryObjectStore {
    objects: tokio::sync::RwLock<HashMap<String, StoredObject>>,
}

struct StoredObject {
    data: Vec<u8>,
    content_type: Option<String>,
}

impl InMemoryObjectStore {
    pub fn new() -> Self {
        Self {
            objects: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Return the number of objects currently stored.
    pub async fn len(&self) -> usize {
        self.objects.read().await.len()
    }

    /// Check if the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.objects.read().await.is_empty()
    }

    /// Check if a key exists.
    pub async fn contains_key(&self, key: &str) -> bool {
        self.objects.read().await.contains_key(key)
    }
}

impl Default for InMemoryObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore for InMemoryObjectStore {
    fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> BoxFut<'_, ()> {
        let key = key.to_string();
        let data = data.to_vec();
        let content_type = content_type.map(String::from);
        Box::pin(async move {
            self.objects.write().await.insert(
                key,
                StoredObject {
                    data,
                    content_type,
                },
            );
            Ok(())
        })
    }

    fn get(&self, key: &str) -> BoxFut<'_, Vec<u8>> {
        let key = key.to_string();
        Box::pin(async move {
            let guard = self.objects.read().await;
            match guard.get(&key) {
                Some(obj) => Ok(obj.data.clone()),
                None => Err(ObjectStoreError::NotFound { key }),
            }
        })
    }

    fn delete(&self, key: &str) -> BoxFut<'_, ()> {
        let key = key.to_string();
        Box::pin(async move {
            self.objects.write().await.remove(&key);
            Ok(())
        })
    }

    fn head(&self, key: &str) -> BoxFut<'_, ObjectMeta> {
        let key = key.to_string();
        Box::pin(async move {
            let guard = self.objects.read().await;
            match guard.get(&key) {
                Some(obj) => Ok(ObjectMeta {
                    size: obj.data.len() as u64,
                    content_type: obj.content_type.clone(),
                }),
                None => Err(ObjectStoreError::NotFound { key }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_put_get_delete() {
        let store = InMemoryObjectStore::new();
        assert!(store.is_empty().await);

        store
            .put("test/key", b"hello world", Some("text/plain"))
            .await
            .unwrap();
        assert_eq!(store.len().await, 1);
        assert!(store.contains_key("test/key").await);

        let data = store.get("test/key").await.unwrap();
        assert_eq!(data, b"hello world");

        let meta = store.head("test/key").await.unwrap();
        assert_eq!(meta.size, 11);
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));

        store.delete("test/key").await.unwrap();
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn in_memory_get_not_found() {
        let store = InMemoryObjectStore::new();
        let err = store.get("nonexistent").await.unwrap_err();
        assert!(matches!(err, ObjectStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn in_memory_delete_idempotent() {
        let store = InMemoryObjectStore::new();
        // Deleting a nonexistent key should not error.
        store.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn in_memory_put_overwrites() {
        let store = InMemoryObjectStore::new();
        store.put("key", b"v1", None).await.unwrap();
        store.put("key", b"v2", None).await.unwrap();
        let data = store.get("key").await.unwrap();
        assert_eq!(data, b"v2");
        assert_eq!(store.len().await, 1);
    }
}
