use visa_abi::{ERR_EINVAL, ERR_EIO};

pub const FAKE_BLOCK_BACKEND_PROFILE: &str = "fake-block-v1";
pub const FAKE_BLOCK_BACKEND_PROVIDER: &str = "service_core";
pub const FAKE_BLOCK_BACKEND_SEED: u64 = 0x766d_6f73_626c_6b31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeBlockBackendConfig {
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub deterministic_seed: u64,
}

impl FakeBlockBackendConfig {
    pub const fn blk0() -> Self {
        Self {
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: FAKE_BLOCK_BACKEND_SEED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeBlockOperation {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeBlockBackendEvent {
    pub sequence: u64,
    pub operation: FakeBlockOperation,
    pub start_sector: u64,
    pub sector_count: u32,
    pub byte_len: u64,
}

pub struct FakeBlockBackend {
    config: FakeBlockBackendConfig,
    next_sequence: u64,
}

impl FakeBlockBackend {
    pub const fn new(config: FakeBlockBackendConfig) -> Self {
        Self { config, next_sequence: 1 }
    }

    pub const fn config(&self) -> FakeBlockBackendConfig {
        self.config
    }

    pub fn submit_request(
        &mut self,
        operation: FakeBlockOperation,
        start_sector: u64,
        sector_count: u32,
    ) -> Result<FakeBlockBackendEvent, i32> {
        if sector_count == 0 || sector_count > self.config.max_transfer_sectors {
            return Err(ERR_EINVAL);
        }
        if operation == FakeBlockOperation::Write && self.config.read_only {
            return Err(ERR_EIO);
        }
        let end_sector = start_sector.checked_add(sector_count as u64).ok_or(ERR_EINVAL)?;
        if end_sector > self.config.sector_count {
            return Err(ERR_EINVAL);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(FakeBlockBackendEvent {
            sequence,
            operation,
            start_sector,
            sector_count,
            byte_len: sector_count as u64 * self.config.sector_size as u64,
        })
    }
}

impl Default for FakeBlockBackend {
    fn default() -> Self {
        Self::new(FakeBlockBackendConfig::blk0())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_block_backend_accepts_bounded_read_and_write_requests() {
        let mut backend = FakeBlockBackend::default();
        let read = backend.submit_request(FakeBlockOperation::Read, 64, 8).unwrap();
        assert_eq!(read.sequence, 1);
        assert_eq!(read.byte_len, 4096);

        let write = backend.submit_request(FakeBlockOperation::Write, 72, 8).unwrap();
        assert_eq!(write.sequence, 2);
        assert_eq!(write.byte_len, 4096);
    }

    #[test]
    fn fake_block_backend_rejects_out_of_bounds_or_read_only_writes() {
        let mut backend = FakeBlockBackend::default();
        assert_eq!(backend.submit_request(FakeBlockOperation::Read, 4090, 8), Err(ERR_EINVAL));
        assert_eq!(backend.submit_request(FakeBlockOperation::Read, 0, 129), Err(ERR_EINVAL));

        let mut read_only = FakeBlockBackend::new(FakeBlockBackendConfig {
            read_only: true,
            ..FakeBlockBackendConfig::blk0()
        });
        assert_eq!(read_only.submit_request(FakeBlockOperation::Write, 0, 1), Err(ERR_EIO));
    }
}
