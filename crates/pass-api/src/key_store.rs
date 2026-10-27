//! Where the core keeps the key of an open database.
//!
//! The core does not hold it itself: it asks through `KeyStoreService`, so each platform decides where
//! the key lives (`pass-rust-core/src/db/key_secure.rs`). This implementation keeps keys in the
//! process, and only for as long as the database is open - closing or locking a database makes the
//! core delete its key. Nothing is written to disk.
//!
//! Android Keystore and unlocking by biometrics are a separate piece of work (v1 p.3): they need a key
//! that outlives the process, which is a different lifetime and a different threat model than this.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use kdbx_rust_core::db_service::{KeyStoreOperation, KeyStoreService};
use kdbx_rust_core::error::Result;

#[derive(Default)]
struct InMemoryKeyStore {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyStoreService for InMemoryKeyStore {
    fn store_key(&mut self, db_key: &str, val: Vec<u8>) -> Result<()> {
        self.keys.insert(db_key.to_string(), val);
        Ok(())
    }

    fn get_key(&self, db_key: &str) -> Option<Vec<u8>> {
        self.keys.get(db_key).cloned()
    }

    fn delete_key(&mut self, db_key: &str) -> Result<()> {
        self.keys.remove(db_key);
        Ok(())
    }

    fn copy_key(&mut self, source_db_key: &str, target_db_key: &str) -> Result<()> {
        if let Some(key) = self.keys.get(source_db_key).cloned() {
            self.keys.insert(target_db_key.to_string(), key);
        }
        Ok(())
    }
}

/// Hands the core its key store. Called once, from `crate::init`.
pub(crate) fn install() {
    KeyStoreOperation::init(Arc::new(Mutex::new(InMemoryKeyStore::default())));
}

#[cfg(test)]
mod tests {
    use super::InMemoryKeyStore;
    use kdbx_rust_core::db_service::KeyStoreService;

    #[test]
    fn a_stored_key_is_returned_and_a_deleted_one_is_not() {
        let mut store = InMemoryKeyStore::default();
        store.store_key("db-1", vec![1, 2, 3]).unwrap();

        assert_eq!(store.get_key("db-1"), Some(vec![1, 2, 3]));
        assert_eq!(store.get_key("db-2"), None);

        store.delete_key("db-1").unwrap();
        assert_eq!(store.get_key("db-1"), None);
    }

    #[test]
    fn copying_leaves_the_source_in_place() {
        let mut store = InMemoryKeyStore::default();
        store.store_key("db-1", vec![7]).unwrap();

        store.copy_key("db-1", "db-2").unwrap();

        assert_eq!(store.get_key("db-1"), Some(vec![7]));
        assert_eq!(store.get_key("db-2"), Some(vec![7]));
    }

    // Save-as copies the key of a database that may not be open; the core treats that as a no-op
    #[test]
    fn copying_a_key_that_is_not_there_is_not_an_error() {
        let mut store = InMemoryKeyStore::default();
        assert!(store.copy_key("missing", "db-2").is_ok());
        assert_eq!(store.get_key("db-2"), None);
    }
}
