//! Product ownership authority core for vISA 0.1.
//!
//! This crate deliberately contains no D-Bus or systemd code. Its sole mutation
//! entry point accepts an already-admitted caller and exact ownership-RPC bytes,
//! then commits the authority transition and byte-identical replay response in
//! one SQLite `BEGIN IMMEDIATE` transaction.

mod proposal;
mod receipt;
mod state;
mod store;

pub use proposal::{
    AbortProposalV1, CommitProposalV1, ProposalCodecError, ReserveProposalV1, SealProposalV1,
    decode_abort_proposal, decode_commit_proposal, decode_reserve_proposal, decode_seal_proposal,
    encode_abort_proposal, encode_commit_proposal, encode_reserve_proposal, encode_seal_proposal,
};
pub use receipt::{
    AdmittedReceipt, LocalReceiptAuthenticator, PinnedLocalReceiptAuthenticator,
    ReceiptAdmissionError, admit_receipt, receipt_artifact,
};
pub use store::{
    AuthorityStore, DurabilityReport, OwnershipServiceIdentity, StoreBinding, StoreBootstrap,
    StoreLimits,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipServiceError {
    InvalidRequest,
    CallerBindingConflict,
    RequestIdConflict,
    Capacity,
    StoreBusy,
    StoreMismatch,
    Integrity,
    Storage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SqliteFailureClass {
    Busy,
    Unique,
    Integrity,
    Other,
}

pub(crate) fn classify_sqlite_error(error: &rusqlite::Error) -> SqliteFailureClass {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            SqliteFailureClass::Busy
        }
        Some(rusqlite::ErrorCode::ConstraintViolation) => {
            let extended_code = match error {
                rusqlite::Error::SqliteFailure(failure, _) => failure.extended_code,
                _ => return SqliteFailureClass::Integrity,
            };
            if matches!(
                extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    | rusqlite::ffi::SQLITE_CONSTRAINT_ROWID
            ) {
                SqliteFailureClass::Unique
            } else {
                SqliteFailureClass::Integrity
            }
        }
        _ => SqliteFailureClass::Other,
    }
}

#[cfg(test)]
mod tests;
