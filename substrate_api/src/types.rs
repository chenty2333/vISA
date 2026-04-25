use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub type Generation = u64;

macro_rules! handle {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name {
            pub id: u64,
            pub generation: Generation,
        }

        impl $name {
            pub const fn new(id: u64, generation: Generation) -> Self {
                Self { id, generation }
            }

            pub const fn is_valid(self) -> bool {
                self.id != 0 && self.generation != 0
            }
        }
    };
}

handle!(StoreRef);
handle!(ArtifactImageRef);
handle!(CodeObjectRef);
handle!(PublishedCodeRef);
handle!(WaitTokenRef);
handle!(UserMemoryHandle);
handle!(WindowLeaseRef);
handle!(MmioRegionRef);
handle!(DmaBufferCapability);
handle!(IrqLine);
handle!(SnapshotBarrierRef);
handle!(CapabilityHandle);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualTime {
    pub ticks: u64,
}

impl VirtualTime {
    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl WindowPerms {
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaAllocRequest {
    pub device: u64,
    pub bytes: usize,
    pub alignment: usize,
}

impl DmaAllocRequest {
    pub const fn new(device: u64, bytes: usize, alignment: usize) -> Self {
        Self {
            device,
            bytes,
            alignment,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateRequester {
    pub subject: String,
    pub artifact: Option<ArtifactImageRef>,
    pub store: Option<StoreRef>,
}

impl SubstrateRequester {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            artifact: None,
            store: None,
        }
    }

    pub fn with_artifact(mut self, artifact: ArtifactImageRef) -> Self {
        self.artifact = Some(artifact);
        self
    }

    pub fn with_store(mut self, store: StoreRef) -> Self {
        self.store = Some(store);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubstrateEvent {
    Unsupported {
        authority: &'static str,
        operation: &'static str,
        requester: Option<SubstrateRequester>,
    },
    CapabilityDenied {
        authority: &'static str,
        operation: &'static str,
        requester: Option<SubstrateRequester>,
        capability: Option<CapabilityHandle>,
    },
}

impl SubstrateEvent {
    pub fn unsupported(
        authority: &'static str,
        operation: &'static str,
        requester: Option<SubstrateRequester>,
    ) -> Self {
        Self::Unsupported {
            authority,
            operation,
            requester,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubstrateError {
    Unsupported {
        authority: &'static str,
        operation: &'static str,
    },
    Denied {
        capability: Option<CapabilityHandle>,
    },
    GenerationMismatch {
        expected: Generation,
        actual: Option<Generation>,
    },
    InvalidObject {
        object: &'static str,
    },
    HardwareFault {
        authority: &'static str,
        detail: &'static str,
    },
    ContractViolation {
        detail: &'static str,
    },
}

impl SubstrateError {
    pub const fn unsupported(authority: &'static str, operation: &'static str) -> Self {
        Self::Unsupported {
            authority,
            operation,
        }
    }

    pub const fn denied(capability: Option<CapabilityHandle>) -> Self {
        Self::Denied { capability }
    }
}

impl fmt::Display for SubstrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported {
                authority,
                operation,
            } => write!(f, "{authority}::{operation} is unsupported"),
            Self::Denied { capability } => match capability {
                Some(capability) => write!(
                    f,
                    "capability denied id={} generation={}",
                    capability.id, capability.generation
                ),
                None => f.write_str("capability denied"),
            },
            Self::GenerationMismatch { expected, actual } => match actual {
                Some(actual) => {
                    write!(f, "generation mismatch expected={expected} actual={actual}")
                }
                None => write!(f, "generation mismatch expected={expected} actual=missing"),
            },
            Self::InvalidObject { object } => write!(f, "invalid substrate object {object}"),
            Self::HardwareFault { authority, detail } => {
                write!(f, "{authority} hardware fault: {detail}")
            }
            Self::ContractViolation { detail } => {
                write!(f, "substrate contract violation: {detail}")
            }
        }
    }
}

pub type SubstrateResult<T> = Result<T, SubstrateError>;

pub type GuestBytes = Vec<u8>;
