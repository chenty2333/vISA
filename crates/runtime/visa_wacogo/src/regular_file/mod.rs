mod adapter;
mod error;
mod host;
mod state;

pub use adapter::WacogoRegularFileAdapter;
pub use visa_component_adapter::{
    PortableRegularFileState, REGULAR_FILE_COMPONENT_STATE_ENCODING, RegularFileAdapterError,
    RegularFileCallResult, RegularFileComponentState, RegularFileFailure,
    RegularFileStateCodecError, RegularFileWorkloadFailure, RegularFileWorkloadPhase,
};
pub use visa_profile::{
    FileDurability, FileLockState, RegularFileOperation, RegularFileResult, RegularFileState,
};
