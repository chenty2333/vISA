use alloc::vec::Vec;

use crate::*;

pub struct NoConsole;
impl ConsoleAuthority for NoConsole {}

pub struct NoTimer;
impl TimerAuthority for NoTimer {}

pub struct NoGuestMemory;
impl GuestMemoryAuthority for NoGuestMemory {}

pub struct NoDmw;
impl DmwAuthority for NoDmw {}

pub struct NoArtifactAuthority;
impl ArtifactAuthority for NoArtifactAuthority {}

pub struct NoCodePublisher;
impl CodePublisherAuthority for NoCodePublisher {}

pub struct NoMmio;
impl MmioAuthority for NoMmio {}

pub struct NoDma;
impl DmaAuthority for NoDma {}

pub struct NoIrq;
impl IrqAuthority for NoIrq {}

pub struct NoSnapshot;
impl SnapshotAuthority for NoSnapshot {}

#[derive(Clone, Debug, Default)]
pub struct SimpleEventQueue {
    events: Vec<SubstrateEvent>,
}

impl SimpleEventQueue {
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl EventQueueAuthority for SimpleEventQueue {
    fn push_event(&mut self, event: SubstrateEvent) -> SubstrateResult<()> {
        self.events.push(event);
        Ok(())
    }

    fn pop_event(&mut self) -> Option<SubstrateEvent> {
        if self.events.is_empty() { None } else { Some(self.events.remove(0)) }
    }
}
