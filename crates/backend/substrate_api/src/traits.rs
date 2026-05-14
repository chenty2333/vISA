use crate::*;

pub trait ConsoleAuthority {
    fn console_write(&mut self, _bytes: &[u8]) -> SubstrateResult<usize> {
        Err(SubstrateError::unsupported("ConsoleAuthority", "console_write"))
    }
}

pub trait TimerAuthority {
    fn now(&self) -> SubstrateResult<VirtualTime> {
        Err(SubstrateError::unsupported("TimerAuthority", "now"))
    }

    fn arm_timer(&mut self, _deadline: VirtualTime, _token: WaitTokenRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("TimerAuthority", "arm_timer"))
    }
}

pub trait EventQueueAuthority {
    fn push_event(&mut self, _event: SubstrateEvent) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("EventQueueAuthority", "push_event"))
    }

    fn pop_event(&mut self) -> Option<SubstrateEvent> {
        None
    }
}

pub trait GuestMemoryAuthority {
    fn copyin(
        &self,
        _mem: UserMemoryHandle,
        _ptr: u64,
        _len: usize,
    ) -> SubstrateResult<GuestBytes> {
        Err(SubstrateError::unsupported("GuestMemoryAuthority", "copyin"))
    }

    fn copyout(&mut self, _mem: UserMemoryHandle, _ptr: u64, _data: &[u8]) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("GuestMemoryAuthority", "copyout"))
    }
}

pub trait DmwAuthority {
    fn map_user_window(
        &mut self,
        _mem: UserMemoryHandle,
        _ptr: u64,
        _len: usize,
        _perms: WindowPerms,
    ) -> SubstrateResult<WindowLeaseRef> {
        Err(SubstrateError::unsupported("DmwAuthority", "map_user_window"))
    }

    fn unmap_user_window(&mut self, _lease: WindowLeaseRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("DmwAuthority", "unmap_user_window"))
    }
}

pub trait ArtifactAuthority {
    fn load_artifact_image(&mut self, _artifact: ArtifactImageRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("ArtifactAuthority", "load_artifact_image"))
    }
}

pub trait CodePublisherAuthority {
    fn publish_code(
        &mut self,
        _artifact: ArtifactImageRef,
        _code: CodeObjectRef,
    ) -> SubstrateResult<PublishedCodeRef> {
        Err(SubstrateError::unsupported("CodePublisherAuthority", "publish_code"))
    }

    fn unpublish_code(&mut self, _code: PublishedCodeRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("CodePublisherAuthority", "unpublish_code"))
    }
}

pub trait MmioAuthority {
    fn mmio_read32(&self, _region: MmioRegionRef, _offset: u64) -> SubstrateResult<u32> {
        Err(SubstrateError::unsupported("MmioAuthority", "mmio_read32"))
    }

    fn mmio_write32(
        &mut self,
        _region: MmioRegionRef,
        _offset: u64,
        _value: u32,
    ) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("MmioAuthority", "mmio_write32"))
    }
}

pub trait DmaAuthority {
    fn dma_alloc(&mut self, _req: DmaAllocRequest) -> SubstrateResult<DmaBufferCapability> {
        Err(SubstrateError::unsupported("DmaAuthority", "dma_alloc"))
    }

    fn dma_free(&mut self, _cap: DmaBufferCapability) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("DmaAuthority", "dma_free"))
    }
}

pub trait IrqAuthority {
    fn irq_ack(&mut self, _irq: IrqLine) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("IrqAuthority", "irq_ack"))
    }

    fn irq_mask(&mut self, _irq: IrqLine) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("IrqAuthority", "irq_mask"))
    }

    fn irq_unmask(&mut self, _irq: IrqLine) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("IrqAuthority", "irq_unmask"))
    }
}

pub trait SnapshotAuthority {
    fn enter_snapshot_barrier(&mut self) -> SubstrateResult<SnapshotBarrierRef> {
        Err(SubstrateError::unsupported("SnapshotAuthority", "enter_snapshot_barrier"))
    }

    fn exit_snapshot_barrier(&mut self, _barrier: SnapshotBarrierRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("SnapshotAuthority", "exit_snapshot_barrier"))
    }
}

/// Page table management authority.
/// Provides low-level physical frame allocation, mapping, and TLB operations.
/// This is substrate capability — semantic policy (COW vs SIGSEGV vs demand page)
/// is decided by GuestMemoryManager::classify_fault(), NOT by this trait.
pub trait PageTableAuthority {
    fn alloc_frame(&mut self) -> SubstrateResult<u64> {
        Err(SubstrateError::unsupported("PageTableAuthority", "alloc_frame"))
    }

    fn map_page(&mut self, va: u64, phys: u64, writable: bool, executable: bool) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PageTableAuthority", "map_page"))
    }

    fn unmap_page(&mut self, va: u64) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PageTableAuthority", "unmap_page"))
    }

    fn protect_page(&mut self, va: u64, writable: bool, executable: bool) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PageTableAuthority", "protect_page"))
    }

    fn copy_frame(&mut self, src_phys: u64, dst_phys: u64, len: usize) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PageTableAuthority", "copy_frame"))
    }

    fn flush_tlb(&mut self, va: u64) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PageTableAuthority", "flush_tlb"))
    }
}

/// Packet device backend abstraction.
/// Provides raw Ethernet frame transmit/receive capability.
/// Concrete implementations: TAP device (host dev), virtio-net (real substrate).
pub trait PacketDeviceBackend {
    fn init(&mut self, _mac: [u8; 6]) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PacketDeviceBackend", "init"))
    }

    fn submit_tx(&mut self, _frame: &[u8]) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported("PacketDeviceBackend", "submit_tx"))
    }

    fn poll_rx(&mut self, _out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
        Err(SubstrateError::unsupported("PacketDeviceBackend", "poll_rx"))
    }

    fn mtu(&self) -> usize {
        1500
    }
}

/// A slot in a caller-provided RX buffer ring for zero-copy frame reception.
pub struct PacketFrameSlot {
    pub data: [u8; 2048],
    pub len: u16,
}

impl PacketFrameSlot {
    pub const fn new() -> Self {
        Self { data: [0u8; 2048], len: 0 }
    }
}
