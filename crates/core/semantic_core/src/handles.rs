use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceHandle {
    pub id: ResourceId,
    pub generation: Generation,
}

impl ResourceHandle {
    pub const fn new(id: ResourceId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitHandle {
    pub id: WaitId,
    pub generation: Generation,
}

impl WaitHandle {
    pub const fn new(id: WaitId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreHandle {
    pub id: StoreId,
    pub generation: Generation,
}

impl StoreHandle {
    pub const fn new(id: StoreId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationCheckError {
    Missing,
    Dead { actual: Generation },
    GenerationMismatch { expected: Generation, actual: Option<Generation> },
}

impl GenerationCheckError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Dead { .. } => "dead",
            Self::GenerationMismatch { .. } => "generation-mismatch",
        }
    }
}
