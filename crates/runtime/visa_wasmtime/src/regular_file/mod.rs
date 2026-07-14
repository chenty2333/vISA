mod adapter;
mod bindings;
mod error;
mod host;
mod state;

pub use adapter::{PreparedRegularFileComponent, RegularFileAdapter, RegularFileCallResult};
pub use error::{RegularFileAdapterError, RegularFileFailure, RegularFileWorkloadFailure};
pub use host::RegularFileStoreState;
pub use visa_component_adapter::{
    PortableRegularFileState, REGULAR_FILE_COMPONENT_STATE_ENCODING, RegularFileComponentState,
    RegularFileStateCodecError, RegularFileWorkloadPhase,
};
pub use visa_profile::{
    FileDurability, FileLockState, RegularFileOperation, RegularFileResult, RegularFileState,
};
