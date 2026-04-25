use crate::*;

pub trait ConsoleAuthority {
    fn console_write(&mut self, _bytes: &[u8]) -> SubstrateResult<usize> {
        Err(SubstrateError::unsupported(
            "ConsoleAuthority",
            "console_write",
        ))
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
        Err(SubstrateError::unsupported(
            "EventQueueAuthority",
            "push_event",
        ))
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
        Err(SubstrateError::unsupported(
            "GuestMemoryAuthority",
            "copyin",
        ))
    }

    fn copyout(&mut self, _mem: UserMemoryHandle, _ptr: u64, _data: &[u8]) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported(
            "GuestMemoryAuthority",
            "copyout",
        ))
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
        Err(SubstrateError::unsupported(
            "DmwAuthority",
            "map_user_window",
        ))
    }

    fn unmap_user_window(&mut self, _lease: WindowLeaseRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported(
            "DmwAuthority",
            "unmap_user_window",
        ))
    }
}

pub trait ArtifactAuthority {
    fn load_artifact_image(&mut self, _artifact: ArtifactImageRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported(
            "ArtifactAuthority",
            "load_artifact_image",
        ))
    }
}

pub trait CodePublisherAuthority {
    fn publish_code(
        &mut self,
        _artifact: ArtifactImageRef,
        _code: CodeObjectRef,
    ) -> SubstrateResult<PublishedCodeRef> {
        Err(SubstrateError::unsupported(
            "CodePublisherAuthority",
            "publish_code",
        ))
    }

    fn unpublish_code(&mut self, _code: PublishedCodeRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported(
            "CodePublisherAuthority",
            "unpublish_code",
        ))
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
        Err(SubstrateError::unsupported(
            "SnapshotAuthority",
            "enter_snapshot_barrier",
        ))
    }

    fn exit_snapshot_barrier(&mut self, _barrier: SnapshotBarrierRef) -> SubstrateResult<()> {
        Err(SubstrateError::unsupported(
            "SnapshotAuthority",
            "exit_snapshot_barrier",
        ))
    }
}
