use visa_abi::{ERR_EAGAIN, ERR_EFAULT};

pub struct ReplaySnapshotState {
    last_cursor: u64,
}

impl ReplaySnapshotState {
    pub const fn new() -> Self {
        Self { last_cursor: 0 }
    }

    pub fn validate_barrier(
        &self,
        _pending_waits: u32,
        active_transactions: u32,
        active_dmw_leases: u32,
        pending_dma: u32,
    ) -> Result<(), i32> {
        if active_dmw_leases != 0 || pending_dma != 0 {
            return Err(ERR_EFAULT);
        }
        if active_transactions != 0 {
            return Err(ERR_EAGAIN);
        }
        Ok(())
    }

    pub fn replay_until(&mut self, cursor: u64) -> u64 {
        self.last_cursor = cursor;
        self.last_cursor
    }

    pub fn last_replay_cursor(&self) -> u64 {
        self.last_cursor
    }
}

impl Default for ReplaySnapshotState {
    fn default() -> Self {
        Self::new()
    }
}
