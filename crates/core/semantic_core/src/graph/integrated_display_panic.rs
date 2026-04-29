use target_abi::{PANIC_RECORD_MAX_LEN, PANIC_RING_SIZE};

use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_display_panic(
        &self,
        integrated: IntegratedDisplayPanicId,
        scenario: &str,
        substrate_panic_event: EventId,
        display_panic_last_frame: DisplayPanicLastFrameId,
        display_panic_last_frame_generation: Generation,
        panic_ring_bytes: u32,
        panic_record_max_bytes: u32,
        panic_ring_oldest_seq: u64,
        panic_ring_newest_seq: u64,
        panic_ring_record_count: u32,
        panic_ring_lost_count: u64,
        jsonl_frame_count: u32,
        contract_panic_summary_records: u32,
        last_frame_summary_records: u32,
        corrupt_record_count: u32,
        truncated_record_count: u32,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        self.validate_integrated_display_panic_candidate(
            integrated,
            scenario,
            substrate_panic_event,
            display_panic_last_frame,
            display_panic_last_frame_generation,
            panic_ring_bytes,
            panic_record_max_bytes,
            panic_ring_oldest_seq,
            panic_ring_newest_seq,
            panic_ring_record_count,
            panic_ring_lost_count,
            jsonl_frame_count,
            contract_panic_summary_records,
            last_frame_summary_records,
            corrupt_record_count,
            truncated_record_count,
            invariant_checks,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_integrated_display_panic_candidate(
        &self,
        integrated: IntegratedDisplayPanicId,
        scenario: &str,
        substrate_panic_event: EventId,
        display_panic_last_frame: DisplayPanicLastFrameId,
        display_panic_last_frame_generation: Generation,
        panic_ring_bytes: u32,
        panic_record_max_bytes: u32,
        panic_ring_oldest_seq: u64,
        panic_ring_newest_seq: u64,
        panic_ring_record_count: u32,
        panic_ring_lost_count: u64,
        jsonl_frame_count: u32,
        contract_panic_summary_records: u32,
        last_frame_summary_records: u32,
        corrupt_record_count: u32,
        truncated_record_count: u32,
        invariant_checks: u32,
        allow_existing_integrated: Option<IntegratedDisplayPanicId>,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated display panic id=0 is invalid");
        }
        if self
            .integrated_display_panics
            .iter()
            .any(|record| record.id == integrated && Some(record.id) != allow_existing_integrated)
        {
            return Err("integrated display panic evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated display panic scenario is empty");
        }
        if substrate_panic_event == 0
            || display_panic_last_frame_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated display panic refs must carry generations and events");
        }
        if panic_ring_bytes != PANIC_RING_SIZE as u32
            || panic_record_max_bytes != PANIC_RECORD_MAX_LEN as u32
            || panic_ring_oldest_seq == 0
            || panic_ring_newest_seq < panic_ring_oldest_seq
            || panic_ring_record_count < 2
            || panic_ring_newest_seq.saturating_sub(panic_ring_oldest_seq).saturating_add(1)
                < u64::from(panic_ring_record_count)
            || panic_ring_lost_count != 0
            || jsonl_frame_count < panic_ring_record_count.saturating_add(2)
            || contract_panic_summary_records == 0
            || last_frame_summary_records == 0
            || corrupt_record_count != 0
            || truncated_record_count != 0
        {
            return Err("integrated display panic requires clean panic-ring extraction evidence");
        }

        let Some(frame) = self.domains.display.display_panic_last_frames.iter().find(|record| {
            record.id == display_panic_last_frame
                && record.generation == display_panic_last_frame_generation
        }) else {
            return Err("integrated display panic missing last-frame evidence");
        };
        if frame.state != DisplayPanicLastFrameState::Recorded
            || frame.raw_framebuffer_bytes_exported
            || frame.summary_record_bytes == 0
            || frame.summary_record_bytes > panic_record_max_bytes
            || frame.panic_record_kind != "contract-panic-summary-v1"
        {
            return Err("integrated display panic requires bounded display panic summary");
        }
        if !self.event_log.events.iter().any(|event| {
            event.id == substrate_panic_event
                && matches!(
                    &event.kind,
                    EventKind::SubstratePanic {
                        panic_epoch,
                        panic_cpu,
                        panic_reason_code,
                        ..
                    } if *panic_epoch == frame.panic_epoch
                        && *panic_cpu == frame.panic_cpu
                        && *panic_reason_code == frame.panic_reason_code
                )
        }) {
            return Err("integrated display panic missing substrate panic event");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_display_panic_with_id(
        &mut self,
        integrated: IntegratedDisplayPanicId,
        scenario: &str,
        substrate_panic_event: EventId,
        display_panic_last_frame: DisplayPanicLastFrameId,
        display_panic_last_frame_generation: Generation,
        panic_ring_bytes: u32,
        panic_record_max_bytes: u32,
        panic_ring_oldest_seq: u64,
        panic_ring_newest_seq: u64,
        panic_ring_record_count: u32,
        panic_ring_lost_count: u64,
        jsonl_frame_count: u32,
        contract_panic_summary_records: u32,
        last_frame_summary_records: u32,
        corrupt_record_count: u32,
        truncated_record_count: u32,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_display_panic(
                integrated,
                scenario,
                substrate_panic_event,
                display_panic_last_frame,
                display_panic_last_frame_generation,
                panic_ring_bytes,
                panic_record_max_bytes,
                panic_ring_oldest_seq,
                panic_ring_newest_seq,
                panic_ring_record_count,
                panic_ring_lost_count,
                jsonl_frame_count,
                contract_panic_summary_records,
                last_frame_summary_records,
                corrupt_record_count,
                truncated_record_count,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }
        let Some(frame) = self.domains.display.display_panic_last_frames.iter().find(|record| {
            record.id == display_panic_last_frame
                && record.generation == display_panic_last_frame_generation
        }) else {
            return false;
        };
        let generation = 1;
        let substrate_panic_epoch = frame.panic_epoch;
        let substrate_panic_cpu = frame.panic_cpu;
        let substrate_panic_reason_code = frame.panic_reason_code;
        let summary_record_bytes = frame.summary_record_bytes;
        let raw_framebuffer_bytes_exported = frame.raw_framebuffer_bytes_exported;
        let panic_path_allocates = false;
        self.next_integrated_display_panic_id =
            self.next_integrated_display_panic_id.max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedDisplayPanicRecorded {
                scenario: scenario.to_string(),
                integrated,
                substrate_panic_event,
                display_panic_last_frame,
                display_panic_last_frame_generation,
                panic_ring_record_count,
                panic_ring_lost_count,
                jsonl_frame_count,
                contract_panic_summary_records,
                last_frame_summary_records,
                corrupt_record_count,
                truncated_record_count,
                invariant_checks,
                generation,
            },
        );
        self.integrated_display_panics.push(IntegratedDisplayPanicRecord {
            id: integrated,
            scenario: scenario.to_string(),
            substrate_panic_event,
            substrate_panic_epoch,
            substrate_panic_cpu,
            substrate_panic_reason_code,
            display_panic_last_frame,
            display_panic_last_frame_generation,
            panic_ring_bytes,
            panic_record_max_bytes,
            panic_ring_oldest_seq,
            panic_ring_newest_seq,
            panic_ring_record_count,
            panic_ring_lost_count,
            jsonl_frame_count,
            contract_panic_summary_records,
            last_frame_summary_records,
            corrupt_record_count,
            truncated_record_count,
            summary_record_bytes,
            raw_framebuffer_bytes_exported,
            panic_path_allocates,
            invariant_checks,
            generation,
            state: IntegratedDisplayPanicState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn integrated_display_panics(&self) -> &[IntegratedDisplayPanicRecord] {
        &self.integrated_display_panics
    }

    pub fn integrated_display_panic_count(&self) -> usize {
        self.integrated_display_panics.len()
    }

    pub fn check_integrated_display_panic_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_display_panics {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplayPanicState::Recorded
                || record.substrate_panic_event == 0
                || record.display_panic_last_frame_generation == 0
                || record.panic_ring_bytes != PANIC_RING_SIZE as u32
                || record.panic_record_max_bytes != PANIC_RECORD_MAX_LEN as u32
                || record.panic_ring_oldest_seq == 0
                || record.panic_ring_newest_seq < record.panic_ring_oldest_seq
                || record.panic_ring_record_count < 2
                || record
                    .panic_ring_newest_seq
                    .saturating_sub(record.panic_ring_oldest_seq)
                    .saturating_add(1)
                    < u64::from(record.panic_ring_record_count)
                || record.panic_ring_lost_count != 0
                || record.jsonl_frame_count < record.panic_ring_record_count.saturating_add(2)
                || record.contract_panic_summary_records == 0
                || record.last_frame_summary_records == 0
                || record.corrupt_record_count != 0
                || record.truncated_record_count != 0
                || record.summary_record_bytes == 0
                || record.summary_record_bytes > record.panic_record_max_bytes
                || record.raw_framebuffer_bytes_exported
                || record.panic_path_allocates
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                return Err(SemanticInvariantError::IntegratedDisplayPanicInvalid {
                    integrated: record.id,
                });
            }
            if self
                .validate_integrated_display_panic_candidate(
                    record.id,
                    &record.scenario,
                    record.substrate_panic_event,
                    record.display_panic_last_frame,
                    record.display_panic_last_frame_generation,
                    record.panic_ring_bytes,
                    record.panic_record_max_bytes,
                    record.panic_ring_oldest_seq,
                    record.panic_ring_newest_seq,
                    record.panic_ring_record_count,
                    record.panic_ring_lost_count,
                    record.jsonl_frame_count,
                    record.contract_panic_summary_records,
                    record.last_frame_summary_records,
                    record.corrupt_record_count,
                    record.truncated_record_count,
                    record.invariant_checks,
                    Some(record.id),
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedDisplayPanicInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedDisplayPanicRecorded {
                            scenario,
                            integrated,
                            substrate_panic_event,
                            display_panic_last_frame,
                            display_panic_last_frame_generation,
                            panic_ring_record_count,
                            panic_ring_lost_count,
                            jsonl_frame_count,
                            contract_panic_summary_records,
                            last_frame_summary_records,
                            corrupt_record_count,
                            truncated_record_count,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *substrate_panic_event == record.substrate_panic_event
                            && *display_panic_last_frame == record.display_panic_last_frame
                            && *display_panic_last_frame_generation
                                == record.display_panic_last_frame_generation
                            && *panic_ring_record_count == record.panic_ring_record_count
                            && *panic_ring_lost_count == record.panic_ring_lost_count
                            && *jsonl_frame_count == record.jsonl_frame_count
                            && *contract_panic_summary_records
                                == record.contract_panic_summary_records
                            && *last_frame_summary_records == record.last_frame_summary_records
                            && *corrupt_record_count == record.corrupt_record_count
                            && *truncated_record_count == record.truncated_record_count
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IntegratedDisplayPanicMissingEvent {
                    integrated: record.id,
                });
            }
        }
        Ok(())
    }
}
