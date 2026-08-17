//! SQLite handle for the coordinator's durable continuation record store.
//!
//! The implementation of [`visa_coordinator::RecordStore`] lives in
//! [`crate::adapters`].  This module owns only the database handle; core
//! records are serialized there with postcard into the coordinator tables.

use std::fmt;

use crate::db::ReferenceDatabase;

#[derive(Clone)]
pub struct RecordStore {
    pub(crate) database: ReferenceDatabase,
}

impl fmt::Debug for RecordStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RecordStore").finish_non_exhaustive()
    }
}

impl RecordStore {
    pub fn new(database: ReferenceDatabase) -> Self {
        Self { database }
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }
}
