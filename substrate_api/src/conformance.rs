use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceError {
    pub check: &'static str,
    pub detail: &'static str,
}

impl ConformanceError {
    const fn new(check: &'static str, detail: &'static str) -> Self {
        Self { check, detail }
    }
}

pub type ConformanceResult = Result<(), ConformanceError>;

pub fn unsupported_is_reported<T>(
    check: &'static str,
    result: SubstrateResult<T>,
    authority: &'static str,
    operation: &'static str,
) -> ConformanceResult {
    match result {
        Err(SubstrateError::Unsupported {
            authority: actual_authority,
            operation: actual_operation,
        }) if actual_authority == authority && actual_operation == operation => Ok(()),
        Err(_) => Err(ConformanceError::new(
            check,
            "operation failed with the wrong error class",
        )),
        Ok(_) => Err(ConformanceError::new(
            check,
            "operation unexpectedly succeeded",
        )),
    }
}

pub fn console_write_smoke<A: ConsoleAuthority>(
    authority: &mut A,
    bytes: &[u8],
) -> ConformanceResult {
    match authority.console_write(bytes) {
        Ok(written) if written == bytes.len() => Ok(()),
        Ok(_) => Err(ConformanceError::new(
            "console_write_smoke",
            "console authority returned a partial write",
        )),
        Err(_) => Err(ConformanceError::new(
            "console_write_smoke",
            "console authority rejected a basic write",
        )),
    }
}

pub fn event_queue_fifo_or_declared_order<Q: EventQueueAuthority>(
    queue: &mut Q,
) -> ConformanceResult {
    let first = SubstrateEvent::unsupported("DmaAuthority", "dma_alloc", None);
    let second = SubstrateEvent::unsupported("IrqAuthority", "irq_ack", None);
    queue
        .push_event(first.clone())
        .map_err(|_| ConformanceError::new("event_queue_fifo", "first push failed"))?;
    queue
        .push_event(second.clone())
        .map_err(|_| ConformanceError::new("event_queue_fifo", "second push failed"))?;

    if queue.pop_event() != Some(first) {
        return Err(ConformanceError::new(
            "event_queue_fifo",
            "first event did not pop first",
        ));
    }
    if queue.pop_event() != Some(second) {
        return Err(ConformanceError::new(
            "event_queue_fifo",
            "second event did not pop second",
        ));
    }
    Ok(())
}

pub fn capability_denied_event_is_visible<Q: EventQueueAuthority>(
    queue: &mut Q,
) -> ConformanceResult {
    let event = SubstrateEvent::CapabilityDenied {
        authority: "DmaAuthority",
        operation: "dma_alloc",
        requester: Some(SubstrateRequester::new("driver.fake_net")),
        capability: Some(CapabilityHandle::new(7, 2)),
    };
    queue
        .push_event(event.clone())
        .map_err(|_| ConformanceError::new("capability_denied_event", "event push failed"))?;
    match queue.pop_event() {
        Some(actual) if actual == event => Ok(()),
        Some(_) => Err(ConformanceError::new(
            "capability_denied_event",
            "event payload changed in queue",
        )),
        None => Err(ConformanceError::new(
            "capability_denied_event",
            "event queue returned no event",
        )),
    }
}

pub fn dmw_unsupported_is_reported<A: DmwAuthority>(authority: &mut A) -> ConformanceResult {
    unsupported_is_reported(
        "dmw_unsupported",
        authority.map_user_window(UserMemoryHandle::new(1, 1), 0x1000, 16, WindowPerms::READ),
        "DmwAuthority",
        "map_user_window",
    )
}

pub fn dma_unsupported_is_reported<A: DmaAuthority>(authority: &mut A) -> ConformanceResult {
    unsupported_is_reported(
        "dma_unsupported",
        authority.dma_alloc(DmaAllocRequest::new(1, 4096, 4096)),
        "DmaAuthority",
        "dma_alloc",
    )
}
