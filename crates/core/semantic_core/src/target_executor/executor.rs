use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetExecutorError {
    StoreNotRunning,
    CodeObjectNotBound,
    ActivationMissing,
    ActivationNotRunning,
    ActivationStoreMismatch,
    CodeObjectMismatch,
    HostcallFrameMismatch,
    HostcallSubjectMismatch,
    HostcallAbiMismatch,
    HostcallNotDeclared,
    CapabilityDenied,
    DmwLeaseActive,
    DmwLeaseMissing,
    PendingCleanupActive,
    CleanupTransactionMissing,
    CleanupStoreMismatch,
}

impl TargetExecutorError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreNotRunning => "store is not running",
            Self::CodeObjectNotBound => "code object is not bound to the store",
            Self::ActivationMissing => "activation is missing",
            Self::ActivationNotRunning => "activation is not running",
            Self::ActivationStoreMismatch => "activation/store mismatch",
            Self::CodeObjectMismatch => "activation/code object attribution mismatch",
            Self::HostcallFrameMismatch => "hostcall frame does not match declared hostcall",
            Self::HostcallSubjectMismatch => "hostcall subject does not match code object package",
            Self::HostcallAbiMismatch => "hostcall frame ABI version mismatch",
            Self::HostcallNotDeclared => "hostcall is not declared by code object",
            Self::CapabilityDenied => "hostcall capability gate denied access",
            Self::DmwLeaseActive => "active DMW lease cannot cross exit boundary",
            Self::DmwLeaseMissing => "DMW lease is missing",
            Self::PendingCleanupActive => "pending cleanup transaction blocks this boundary",
            Self::CleanupTransactionMissing => "cleanup transaction is missing",
            Self::CleanupStoreMismatch => "cleanup transaction targets a different store",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetExecutor {
    next_activation_id: ActivationId,
    next_trap_id: TargetTrapId,
    next_hostcall_trace_id: HostcallTraceId,
    next_cleanup_id: CleanupTransactionId,
    next_lease_id: DmwLeaseId,
    next_event_id: EventId,
    activations: Vec<ActivationRecord>,
    traps: Vec<TargetTrapRecord>,
    dmw_leases: Vec<DmwLeaseRecord>,
    hostcall_trace: Vec<HostcallTraceRecord>,
    cleanup_transactions: Vec<FaultCleanupTransaction>,
    tombstones: Vec<TombstoneRecord>,
    event_log: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PreparedHostcallDispatch {
    activation_index: usize,
    frame: HostcallFrame,
    spec: HostcallSpec,
}

impl TargetExecutor {
    pub const fn new() -> Self {
        Self {
            next_activation_id: 1,
            next_trap_id: 1,
            next_hostcall_trace_id: 1,
            next_cleanup_id: 1,
            next_lease_id: 1,
            next_event_id: 1,
            activations: Vec::new(),
            traps: Vec::new(),
            dmw_leases: Vec::new(),
            hostcall_trace: Vec::new(),
            cleanup_transactions: Vec::new(),
            tombstones: Vec::new(),
            event_log: Vec::new(),
        }
    }

    pub fn start_activation(
        &mut self,
        store: &StoreRecord,
        code: &CodeObject,
        entry: ActivationEntry,
    ) -> Result<ActivationId, TargetExecutorError> {
        if store.state != StoreState::Running {
            return Err(TargetExecutorError::StoreNotRunning);
        }
        if code.state != CodeObjectState::BoundToStore
            || code.bound_store != Some(store.id)
            || code.bound_store_generation != Some(store.generation)
        {
            return Err(TargetExecutorError::CodeObjectNotBound);
        }
        let id = self.next_activation_id;
        self.next_activation_id += 1;
        let start_event = self.next_event("activation-started");
        self.activations.push(ActivationRecord {
            id,
            store: store.id,
            store_generation: store.generation,
            code_object: code.id,
            code_generation: code.generation,
            artifact: code.artifact_id,
            entry,
            generation: 1,
            state: ActivationState::Running,
            start_event,
            exit_event: None,
            active_dmw_leases: 0,
            blocked_wait: None,
            trap: None,
            return_tag: None,
        });
        Ok(id)
    }

    fn bad_abi_reason(frame: &ExecutorHostcallFrameV1) -> Option<&'static str> {
        if frame.magic != ExecutorHostcallFrameV1::MAGIC {
            Some("bad-hostcall-magic")
        } else if frame.abi_version != ExecutorHostcallFrameV1::ABI_VERSION {
            Some("bad-hostcall-abi")
        } else if frame.frame_size != ExecutorHostcallFrameV1::FRAME_SIZE {
            Some("bad-frame-size")
        } else if frame.cap_arg_count as usize > ExecutorHostcallFrameV1::CAP_ARG_CAPACITY {
            Some("bad-cap-arg-count")
        } else if RecordMode::from_u16(frame.record_mode).is_none() {
            Some("bad-record-mode")
        } else if HostcallReturnTag::from_u16(frame.ret_tag).is_none() {
            Some("bad-return-tag")
        } else {
            None
        }
    }

    fn semantic_frame_from_wire(
        wire: &ExecutorHostcallFrameV1,
        code: &CodeObject,
        spec: &HostcallSpec,
        capabilities: &CapabilityLedger,
    ) -> (HostcallFrame, Option<&'static str>) {
        let (cap_args, cap_arg_decode_error) = Self::decode_capability_handles(wire, capabilities);
        let authority_object = AuthorityObjectRef::from_label(
            CapabilityClass::from_object(&spec.object),
            &spec.object,
        );
        let generation = cap_args
            .iter()
            .find(|arg| arg.object_ref == Some(authority_object))
            .map(|arg| arg.generation)
            .or_else(|| capabilities.generation_of_authority(&code.package, authority_object))
            .unwrap_or(0);
        (
            HostcallFrame {
                abi_version: if wire.abi_version == ExecutorHostcallFrameV1::ABI_VERSION {
                    HostcallFrame::ABI_VERSION.to_string()
                } else {
                    format!("wire-v{}", wire.abi_version)
                },
                frame_size: wire.frame_size,
                flags: wire.flags,
                activation: wire.activation_id(),
                activation_generation: wire.activation_generation(),
                store: wire.store_id(),
                store_generation: wire.store_generation(),
                code_object: wire.code_object_id(),
                code_generation: wire.code_generation(),
                artifact: wire.artifact_id(),
                artifact_generation: wire.artifact_generation(),
                hostcall_number: wire.hostcall_number,
                hostcall_seq: wire.hostcall_seq,
                caller_offset: wire.caller_offset,
                subject: code.package.clone(),
                object: spec.object.clone(),
                operation: spec.operation.clone(),
                generation,
                args: wire.args,
                cap_args,
                record_mode: RecordMode::from_u16(wire.record_mode)
                    .unwrap_or(RecordMode::Deterministic),
                ret_tag: HostcallReturnTag::from_u16(wire.ret_tag).unwrap_or(HostcallReturnTag::Ok),
                ret0: wire.ret0,
                ret1: wire.ret1,
                trap_out: (wire.trap_out.0.id != 0).then_some(wire.trap_out.0.id),
                trap_generation_out: (wire.trap_out.0.id != 0)
                    .then_some(wire.trap_out.0.generation),
                wait_token_out: (wire.wait_token_out.0.id != 0).then_some(wire.wait_token_out.0.id),
                wait_token_generation_out: (wire.wait_token_out.0.id != 0)
                    .then_some(wire.wait_token_out.0.generation),
            },
            cap_arg_decode_error,
        )
    }

    fn decode_capability_handles(
        wire: &ExecutorHostcallFrameV1,
        capabilities: &CapabilityLedger,
    ) -> (Vec<CapabilityHandleArg>, Option<&'static str>) {
        let mut args = Vec::new();
        let mut decode_error = None;
        for handle in wire.cap_args.iter().take(wire.cap_arg_count as usize) {
            let owner_store = handle.owner_store.0.id;
            let owner_store_generation = handle.owner_store.0.generation;
            let Some(record) = capabilities.records().iter().find(|record| {
                record.owner_store == Some(owner_store)
                    && record.owner_store_generation == Some(owner_store_generation)
                    && record.handle_slot == handle.slot
                    && !record.revoked
            }) else {
                decode_error.get_or_insert("cap-arg-missing");
                args.push(CapabilityHandleArg {
                    id: 0,
                    object: "<missing-capability>".to_string(),
                    object_ref: None,
                    generation: 0,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    handle_slot: handle.slot,
                    handle_generation: handle.slot_generation,
                    handle_tag: handle.tag,
                    class_hint: CapabilityClass::from_u16(handle.object_class),
                    rights_mask: handle.rights_mask,
                    rights: Vec::new(),
                });
                continue;
            };
            if record.handle_generation != handle.slot_generation {
                decode_error.get_or_insert("cap-arg-generation");
            }
            if record.handle_tag != handle.tag {
                decode_error.get_or_insert("cap-arg-tag");
            }
            match CapabilityClass::from_u16(handle.object_class) {
                Some(class) if class == record.class => {}
                Some(_) => {
                    decode_error.get_or_insert("cap-arg-object-class");
                }
                None => {
                    decode_error.get_or_insert("cap-arg-object-class");
                }
            }
            let rights = match Self::capability_rights_from_mask(record, handle.rights_mask) {
                Some(rights) => rights,
                None => {
                    decode_error.get_or_insert("cap-arg-rights-mask");
                    Vec::new()
                }
            };
            args.push(CapabilityHandleArg {
                id: record.id,
                object: record.object.clone(),
                object_ref: record.object_ref,
                generation: record.generation,
                owner_store: record.owner_store,
                owner_store_generation: record.owner_store_generation,
                handle_slot: handle.slot,
                handle_generation: handle.slot_generation,
                handle_tag: handle.tag,
                class_hint: CapabilityClass::from_u16(handle.object_class),
                rights_mask: handle.rights_mask,
                rights,
            });
        }
        (args, decode_error)
    }

    pub fn preflight_hostcall(
        &mut self,
        code: &CodeObject,
        wire_frame: ExecutorHostcallFrameV1,
        capabilities: &CapabilityLedger,
    ) -> Result<PreparedHostcallDispatch, TargetExecutorError> {
        let bad_abi = Self::bad_abi_reason(&wire_frame);
        if let Some(reason) = bad_abi {
            self.event_log.push(format!(
                "HostcallAbiMismatch activation={} reason={} abi={} expected={} frame_size={} expected_frame_size={}",
                wire_frame.activation_id(),
                reason,
                wire_frame.abi_version,
                ExecutorHostcallFrameV1::ABI_VERSION,
                wire_frame.frame_size,
                ExecutorHostcallFrameV1::FRAME_SIZE
            ));
        }
        let activation_index = self.activation_index(wire_frame.activation_id())?;
        let activation = self.activations[activation_index].clone();
        if activation.state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        if activation.store != wire_frame.store_id()
            || activation.store_generation != wire_frame.store_generation()
            || activation.generation != wire_frame.activation_generation()
        {
            return Err(TargetExecutorError::ActivationStoreMismatch);
        }
        if activation.code_object != code.id
            || activation.code_generation != code.generation
            || activation.artifact != code.artifact_id
            || wire_frame.code_object_id() != code.id
            || wire_frame.code_generation() != code.generation
            || wire_frame.artifact_id() != code.artifact_id
            || wire_frame.artifact_generation() != TARGET_ARTIFACT_GENERATION_V1
            || code.bound_store != Some(wire_frame.store_id())
            || code.bound_store_generation != Some(wire_frame.store_generation())
        {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CodeObjectTrap,
                Some(code),
                Some(format!("hostcall#{}", wire_frame.hostcall_number)),
                "attribution-failure",
                FailureEffect::CompleteWithErrno(5),
                "hostcall wire frame did not match activation code object attribution",
            );
            return Err(TargetExecutorError::CodeObjectMismatch);
        }
        let derived_subject = code.package.as_str();
        if let Some(reason) = bad_abi {
            let spec = code
                .hostcalls
                .iter()
                .find(|spec| spec.number == wire_frame.hostcall_number)
                .cloned()
                .unwrap_or_else(|| {
                    HostcallSpec::new(
                        wire_frame.hostcall_number,
                        "hostcall.bad-abi",
                        HostcallCategory::Service,
                        "hostcall.bad-abi",
                        "decode",
                        false,
                    )
                });
            let (frame, _) = Self::semantic_frame_from_wire(&wire_frame, code, &spec, capabilities);
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(spec.name.clone()),
                reason,
                FailureEffect::CompleteWithErrno(22),
                "hostcall frame ABI version mismatch",
            );
            self.record_trace(
                &frame,
                &spec,
                false,
                reason,
                HostcallReturnTag::BadAbi,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallAbiMismatch);
        }
        let Some(spec) =
            code.hostcalls.iter().find(|spec| spec.number == wire_frame.hostcall_number)
        else {
            let placeholder = HostcallSpec::new(
                wire_frame.hostcall_number,
                "hostcall.unsupported",
                HostcallCategory::Service,
                "hostcall.unsupported",
                "decode",
                false,
            );
            let (frame, _) =
                Self::semantic_frame_from_wire(&wire_frame, code, &placeholder, capabilities);
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(format!("hostcall#{}", wire_frame.hostcall_number)),
                "unsupported-hostcall",
                FailureEffect::CompleteWithErrno(38),
                "hostcall unsupported by artifact import table",
            );
            self.record_trace(
                &frame,
                &placeholder,
                false,
                "unsupported-call",
                HostcallReturnTag::BadAbi,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallNotDeclared);
        };
        let (frame, cap_arg_decode_error) =
            Self::semantic_frame_from_wire(&wire_frame, code, spec, capabilities);
        self.event_log.push(format!(
            "HostcallEntered activation={} name={} category={} subject={} object={} op={}",
            frame.activation,
            spec.name,
            spec.category.as_str(),
            derived_subject,
            frame.object,
            frame.operation
        ));
        let initial_authority_object = AuthorityObjectRef::from_label(
            CapabilityClass::from_object(&frame.object),
            &frame.object,
        );
        let declared_capability = capabilities
            .generation_of_authority(derived_subject, initial_authority_object)
            .is_some();
        let authority =
            match AuthorityMatrix::check(&frame.object, &frame.operation, declared_capability) {
                Ok(authority) => authority,
                Err(reason) => {
                    self.event_log.push(format!(
                        "AuthorityDenied activation={} subject={} object={} op={} reason={}",
                        frame.activation,
                        derived_subject,
                        frame.object,
                        frame.operation,
                        reason.as_str()
                    ));
                    let trap = self.record_trap_for_activation(
                        activation_index,
                        TargetTrapClass::CapabilityTrap,
                        Some(code),
                        Some(spec.name.clone()),
                        "authority-matrix",
                        FailureEffect::CompleteWithErrno(1),
                        "hostcall authority matrix rejected object/operation",
                    );
                    self.record_trace(
                        &frame,
                        spec,
                        false,
                        reason.as_str(),
                        HostcallReturnTag::Trap,
                        Some(trap),
                        None,
                    );
                    return Err(TargetExecutorError::CapabilityDenied);
                }
            };
        let required_right = authority.required_right.as_deref().unwrap_or(&frame.operation);
        let authority_object = AuthorityObjectRef::from_label(authority.class, &frame.object);
        if authority.requires_capability {
            if let Some(reason) = cap_arg_decode_error.or_else(|| {
                Self::cap_arg_denial_reason(
                    &frame,
                    derived_subject,
                    authority_object,
                    required_right,
                    capabilities,
                )
            }) {
                self.event_log.push(format!(
                    "CapabilityDenied activation={} subject={} object={} op={} required_right={} reason={reason}",
                    frame.activation, derived_subject, frame.object, frame.operation, required_right
                ));
                let (class, ret_tag, policy, detail) =
                    if matches!(reason, "cap-arg-empty-rights" | "cap-arg-rights-mask") {
                        (
                            TargetTrapClass::HostcallTrap,
                            HostcallReturnTag::BadAbi,
                            "bad-capability-argument",
                            "hostcall capability handle argument was malformed",
                        )
                    } else {
                        (
                            TargetTrapClass::CapabilityTrap,
                            HostcallReturnTag::Trap,
                            "capability-handle",
                            "hostcall capability handle argument failed validation",
                        )
                    };
                let trap = self.record_trap_for_activation(
                    activation_index,
                    class,
                    Some(code),
                    Some(spec.name.clone()),
                    policy,
                    FailureEffect::CompleteWithErrno(1),
                    detail,
                );
                self.record_trace(&frame, spec, false, reason, ret_tag, Some(trap), None);
                return Err(TargetExecutorError::CapabilityDenied);
            }
            let handle = frame
                .cap_args
                .iter()
                .find(|arg| arg.object_ref == Some(authority_object))
                .and_then(CapabilityHandleArg::capability_handle);
            match capabilities.check_authority(
                derived_subject,
                authority_object,
                required_right,
                handle.as_ref(),
            ) {
                Ok(capability) => {
                    if capability.generation != frame.generation {
                        self.event_log.push(format!(
                            "CapabilityGenerationMismatch activation={} subject={} object={} op={} expected={} actual={}",
                            frame.activation,
                            derived_subject,
                            frame.object,
                            required_right,
                            frame.generation,
                            capability.generation
                        ));
                        let trap = self.record_trap_for_activation(
                            activation_index,
                            TargetTrapClass::CapabilityTrap,
                            Some(code),
                            Some(spec.name.clone()),
                            "rebind-or-fail",
                            FailureEffect::CompleteWithErrno(1),
                            "capability generation mismatch",
                        );
                        self.record_trace(
                            &frame,
                            spec,
                            false,
                            "capability-generation",
                            HostcallReturnTag::Trap,
                            Some(trap),
                            None,
                        );
                        return Err(TargetExecutorError::CapabilityDenied);
                    }
                }
                Err(reason) => {
                    self.event_log.push(format!(
                        "CapabilityDenied activation={} subject={} object={} op={} reason={}",
                        frame.activation,
                        derived_subject,
                        frame.object,
                        required_right,
                        reason.as_str()
                    ));
                    let trap = self.record_trap_for_activation(
                        activation_index,
                        TargetTrapClass::CapabilityTrap,
                        Some(code),
                        Some(spec.name.clone()),
                        "rebind-or-fail",
                        FailureEffect::CompleteWithErrno(1),
                        "hostcall capability gate denied access",
                    );
                    self.record_trace(
                        &frame,
                        spec,
                        false,
                        reason.as_str(),
                        HostcallReturnTag::Trap,
                        Some(trap),
                        None,
                    );
                    return Err(TargetExecutorError::CapabilityDenied);
                }
            }
        }
        if spec.may_pending && self.activations[activation_index].active_dmw_leases != 0 {
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                Some(code),
                Some(spec.name.clone()),
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "pending hostcall attempted with active DMW lease",
            );
            self.record_trace(
                &frame,
                spec,
                false,
                "dmw-lease-active",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        Ok(PreparedHostcallDispatch { activation_index, frame, spec: spec.clone() })
    }

    pub fn commit_hostcall_success(
        &mut self,
        prepared: PreparedHostcallDispatch,
    ) -> Result<(), TargetExecutorError> {
        let Some(current) = self.activations.get(prepared.activation_index) else {
            return Err(TargetExecutorError::ActivationMissing);
        };
        if current.id != prepared.frame.activation
            || current.generation != prepared.frame.activation_generation
            || current.state != ActivationState::Running
        {
            return Err(TargetExecutorError::ActivationStoreMismatch);
        }
        self.record_trace(
            &prepared.frame,
            &prepared.spec,
            true,
            "complete",
            HostcallReturnTag::Ok,
            None,
            None,
        );
        let transition_event = self.next_event("activation-hostcall-complete");
        let old_generation = self.activations[prepared.activation_index].generation;
        self.retire_activation_generation(
            prepared.frame.activation,
            old_generation,
            transition_event,
            "activation-hostcall-previous-generation",
        );
        let activation = &mut self.activations[prepared.activation_index];
        activation.return_tag = Some(HostcallReturnTag::Ok);
        activation.generation += 1;
        Ok(())
    }

    pub fn invoke_hostcall(
        &mut self,
        code: &CodeObject,
        wire_frame: ExecutorHostcallFrameV1,
        capabilities: &CapabilityLedger,
    ) -> Result<(), TargetExecutorError> {
        let prepared = self.preflight_hostcall(code, wire_frame, capabilities)?;
        self.commit_hostcall_success(prepared)
    }

    pub fn acquire_dmw_lease(
        &mut self,
        activation: ActivationId,
        handle: &str,
    ) -> Result<DmwLeaseId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        let id = self.next_lease_id;
        self.next_lease_id += 1;
        self.dmw_leases.push(DmwLeaseRecord {
            id,
            activation,
            handle: handle.to_string(),
            generation: 1,
            active: true,
        });
        self.activations[activation_index].active_dmw_leases += 1;
        self.event_log
            .push(format!("DmwLeaseAcquired activation={activation} lease={id} handle={handle}"));
        Ok(id)
    }

    pub fn release_dmw_lease(&mut self, lease: DmwLeaseId) -> Result<(), TargetExecutorError> {
        let Some(lease_index) = self.dmw_leases.iter().position(|record| record.id == lease) else {
            return Err(TargetExecutorError::DmwLeaseMissing);
        };
        if !self.dmw_leases[lease_index].active {
            return Ok(());
        }
        let activation = self.dmw_leases[lease_index].activation;
        let activation_index = self.activation_index(activation)?;
        self.dmw_leases[lease_index].active = false;
        self.dmw_leases[lease_index].generation += 1;
        self.activations[activation_index].active_dmw_leases =
            self.activations[activation_index].active_dmw_leases.saturating_sub(1);
        self.event_log.push(format!("DmwLeaseReleased activation={activation} lease={lease}"));
        Ok(())
    }

    pub fn release_all_leases_for_activation(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> Result<u32, TargetExecutorError> {
        self.activation_index(activation)?;
        Ok(self.release_all_leases_for_activation_id(activation, reason))
    }

    pub fn pending_exit(
        &mut self,
        activation: ActivationId,
        wait: WaitId,
    ) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to enter pending with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let exit_event = self.next_event("activation-pending");
        let activation_id = activation;
        let old_generation = self.activations[activation_index].generation;
        self.retire_activation_generation(
            activation_id,
            old_generation,
            exit_event,
            "activation-pending-previous-generation",
        );
        let record = &mut self.activations[activation_index];
        record.state = ActivationState::Pending;
        record.blocked_wait = Some(wait);
        record.return_tag = Some(HostcallReturnTag::Pending);
        record.exit_event = Some(exit_event);
        record.generation += 1;
        Ok(())
    }

    pub fn return_exit(&mut self, activation: ActivationId) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to return with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let activation_id = activation;
        let exit_event = self.next_event("activation-returned");
        let old_generation = self.activations[activation_index].generation;
        self.retire_activation_generation(
            activation_id,
            old_generation,
            exit_event,
            "activation-returned-previous-generation",
        );
        let record = &mut self.activations[activation_index];
        record.state = ActivationState::Returned;
        record.return_tag = Some(HostcallReturnTag::Ok);
        record.exit_event = Some(exit_event);
        record.generation += 1;
        Ok(())
    }

    pub fn trap_exit(
        &mut self,
        activation: ActivationId,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        detail: &str,
    ) -> Result<TargetTrapId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                code,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to trap with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        Ok(self.record_trap_for_activation(
            activation_index,
            class,
            code,
            None,
            "trap-policy",
            FailureEffect::CompleteWithErrno(5),
            detail,
        ))
    }

    pub fn trap_exit_by_pc(
        &mut self,
        activation: ActivationId,
        code: &CodeObject,
        pc: u64,
        trap_map: &[TrapMapEntryV1],
    ) -> Result<TargetTrapId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        let activation_record = &self.activations[activation_index];
        let code_store_mismatch = code.state != CodeObjectState::Retired
            && (code.bound_store != Some(activation_record.store)
                || code.bound_store_generation != Some(activation_record.store_generation));
        if activation_record.code_object != code.id
            || activation_record.code_generation != code.generation
            || activation_record.artifact != code.artifact_id
            || code_store_mismatch
        {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CodeObjectTrap,
                Some(code),
                None,
                "trap-attribution-failure",
                FailureEffect::CompleteWithErrno(5),
                "trap PC attribution did not match activation code object",
            );
            return Err(TargetExecutorError::CodeObjectMismatch);
        }
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                Some(code),
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to trap with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let code_ref = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation);
        let range = PcRangeEntryV1::new(code_ref, code.text.start, code.text.len, 0, 0);
        let runtime_range = if code.state == CodeObjectState::Retired {
            PcRangeRuntimeEntryV1::retired(range)
        } else {
            PcRangeRuntimeEntryV1::live(range)
        };
        let ranges = [runtime_range];
        let attribution = classify_trap_pc(pc, &ranges, trap_map);
        let class = trap_class_for_attribution(attribution.trap_kind);
        let detail = format!(
            "pc={pc:#x} code_offset={} trap_kind={}",
            attribution
                .code_offset
                .map(|offset| format!("{offset:#x}"))
                .unwrap_or_else(|| "none".to_string()),
            attribution.trap_kind.as_str()
        );
        Ok(self.record_trap_for_activation_attributed(
            activation_index,
            class,
            attribution.code_object.map(|_| code),
            None,
            attribution.trap_kind.as_str(),
            FailureEffect::CompleteWithErrno(5),
            &detail,
            attribution.code_offset,
            Some(attribution),
        ))
    }

    pub fn synthetic_trap(
        &mut self,
        class: TargetTrapClass,
        store: StoreId,
        activation: Option<ActivationId>,
        code: Option<&CodeObject>,
        hostcall: Option<&str>,
        detail: &str,
    ) -> TargetTrapId {
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let store_generation = code.and_then(|code| code.bound_store_generation).or_else(|| {
            activation.and_then(|activation| {
                self.activations
                    .iter()
                    .find(|record| record.id == activation)
                    .map(|record| record.store_generation)
            })
        });
        self.traps.push(TargetTrapRecord {
            id,
            generation: 1,
            class,
            store: Some(store),
            store_generation,
            activation,
            activation_generation,
            code_object: code.map(|code| code.id),
            code_generation: code.map(|code| code.generation),
            artifact: code.map(|code| code.artifact_id),
            artifact_generation: code.map(|_| TARGET_ARTIFACT_GENERATION_V1),
            offset: Some(0),
            target_pc: None,
            trap_kind: None,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
            classification_status: None,
            attribution_status: "synthetic".to_string(),
            simd_attribution: None,
            hostcall: hostcall.map(|hostcall| hostcall.to_string()),
            fault_policy: "harness-classification".to_string(),
            effect: FailureEffect::CompleteWithErrno(5),
            detail: detail.to_string(),
        });
        self.event_log.push(format!(
            "TrapClassified trap={id} class={} store={store} detail={detail}",
            class.as_str()
        ));
        id
    }

    pub fn snapshot_barrier(&self) -> Result<(), TargetExecutorError> {
        let report = SnapshotBarrierValidator::validate(&self.snapshot_barrier_validation_state());
        for violation in report.violations {
            match violation.kind {
                BoundaryValidationErrorKind::ActiveDmwLease => {
                    return Err(TargetExecutorError::DmwLeaseActive);
                }
                BoundaryValidationErrorKind::PendingCleanup => {
                    return Err(TargetExecutorError::PendingCleanupActive);
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn snapshot_barrier_validation_state(&self) -> SnapshotBarrierValidationState {
        SnapshotBarrierValidationState {
            active_dmw_lease_count: self.dmw_leases.iter().filter(|lease| lease.active).count()
                as u32,
            pending_cleanup_count: self
                .cleanup_transactions
                .iter()
                .filter(|cleanup| cleanup.state == CleanupTransactionState::Pending)
                .count() as u32,
            ..SnapshotBarrierValidationState::default()
        }
    }

    pub fn begin_fault_cleanup_transaction(
        &mut self,
        store: &StoreRecord,
        activation: Option<ActivationId>,
        code: Option<&CodeObject>,
        reason: &str,
    ) -> CleanupTransactionId {
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let code_object = code.map(|code| code.id);
        let code_generation = code.map(|code| code.generation);
        if let Some(existing) = self.cleanup_transactions.iter().find(|cleanup| {
            cleanup.store == store.id
                && cleanup.store_generation == store.generation
                && cleanup.result_store_generation.is_none()
                && cleanup.activation == activation
                && cleanup.activation_generation == activation_generation
                && cleanup.code_object == code_object
                && cleanup.code_generation == code_generation
                && cleanup.reason == reason
                && cleanup.state == CleanupTransactionState::Pending
        }) {
            return existing.id;
        }
        let started_at = self.next_event("fault-cleanup-started");
        let id = self.next_cleanup_id;
        self.next_cleanup_id += 1;
        self.cleanup_transactions.push(FaultCleanupTransaction {
            id,
            store: store.id,
            store_generation: store.generation,
            result_store_generation: None,
            activation,
            activation_generation,
            code_object,
            code_generation,
            generation: 1,
            started_at,
            finished_at: None,
            state: CleanupTransactionState::Pending,
            reason: reason.to_string(),
            steps: Self::cleanup_step_order()
                .iter()
                .map(|step| CleanupStepRecord::pending(*step))
                .collect(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: Vec::new(),
            revoked_capability_refs: Vec::new(),
            dropped_resources: 0,
            unbound_code_object: false,
            state_digest: String::new(),
            effect: FailureEffect::CompleteWithErrno(5),
        });
        self.event_log.push(format!(
            "FaultCleanupStarted cleanup={id} store={}@{} activation={} reason={reason}",
            store.id,
            store.generation,
            activation
                .zip(activation_generation)
                .map(|(activation, generation)| format!("{activation}@{generation}"))
                .unwrap_or_else(|| "none".to_string())
        ));
        id
    }

    pub fn run_fault_cleanup(
        &mut self,
        store: &mut StoreRecord,
        activation: Option<ActivationId>,
        code: Option<&mut CodeObject>,
        capabilities: &mut CapabilityLedger,
        reason: &str,
    ) -> Result<CleanupTransactionId, TargetExecutorError> {
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let code_object = code.as_deref().map(|code| code.id);
        let code_generation = code.as_deref().map(|code| code.generation);
        if let Some(existing) = self.cleanup_transactions.iter().find(|cleanup| {
            cleanup.store == store.id
                && cleanup.result_store_generation == Some(store.generation)
                && cleanup.activation == activation
                && cleanup.activation_generation == activation_generation
                && cleanup.code_object == code_object
                && cleanup.code_generation == code_generation
                && cleanup.reason == reason
                && store.state == StoreState::Dead
                && cleanup.state == CleanupTransactionState::Completed
        }) {
            return Ok(existing.id);
        }
        let id = self.begin_fault_cleanup_transaction(store, activation, code.as_deref(), reason);
        self.apply_fault_cleanup_transaction(id, store, code, capabilities)
    }

    pub fn apply_fault_cleanup_transaction(
        &mut self,
        cleanup_id: CleanupTransactionId,
        store: &mut StoreRecord,
        mut code: Option<&mut CodeObject>,
        capabilities: &mut CapabilityLedger,
    ) -> Result<CleanupTransactionId, TargetExecutorError> {
        let Some(cleanup_index) =
            self.cleanup_transactions.iter().position(|cleanup| cleanup.id == cleanup_id)
        else {
            return Err(TargetExecutorError::CleanupTransactionMissing);
        };
        if self.cleanup_transactions[cleanup_index].state != CleanupTransactionState::Pending {
            return Ok(cleanup_id);
        }
        if self.cleanup_transactions[cleanup_index].store != store.id {
            return Err(TargetExecutorError::CleanupStoreMismatch);
        }

        let activation = self.cleanup_transactions[cleanup_index].activation;
        let reason = self.cleanup_transactions[cleanup_index].reason.clone();
        let expected_store_generation = self.cleanup_transactions[cleanup_index].store_generation;
        if store.generation != expected_store_generation {
            let event = self.next_event("fault-cleanup-stale-generation");
            let state_digest = self.cleanup_state_digest(store, code.as_deref(), capabilities);
            let target = ContractObjectRef::new(
                ContractObjectKind::Store,
                store.id,
                expected_store_generation,
            );
            let cleanup = &mut self.cleanup_transactions[cleanup_index];
            cleanup.state = CleanupTransactionState::SkippedStaleGeneration;
            cleanup.generation += 1;
            cleanup.result_store_generation = Some(store.generation);
            cleanup.finished_at = Some(event);
            cleanup.state_digest = state_digest;
            cleanup.steps = Self::cleanup_step_order()
                .iter()
                .map(|step| {
                    CleanupStepRecord::skipped_stale_generation(
                        *step,
                        target,
                        store.generation,
                        event,
                    )
                })
                .collect();
            cleanup.effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::RecordFailureEffect,
                target,
                expected_store_generation,
                CleanupEffectStatus::SkippedStaleGeneration,
                event,
            ));
            self.event_log.push(format!(
                "FaultCleanupSkipped cleanup={cleanup_id} store={} expected_generation={} observed_generation={}",
                store.id, expected_store_generation, store.generation
            ));
            return Ok(cleanup_id);
        }

        let released = activation
            .map(|activation| self.release_all_leases_for_activation_id(activation, &reason))
            .unwrap_or(0);
        let mut cancelled_waits = 0;
        let mut final_activation_generation = None;
        if let Some(activation) = activation {
            if let Some(index) = self.activations.iter().position(|record| record.id == activation)
            {
                let exit_event = self.next_event("activation-cleanup-dropped");
                let old_generation = self.activations[index].generation;
                self.retire_activation_generation(
                    activation,
                    old_generation,
                    exit_event,
                    "fault-cleanup-activation-previous-generation",
                );
                let (activation_generation, cancelled) = {
                    let record = &mut self.activations[index];
                    record.state = ActivationState::Dropped;
                    record.return_tag = Some(HostcallReturnTag::KillStore);
                    record.exit_event = Some(exit_event);
                    let cancelled = if record.blocked_wait.take().is_some() { 1 } else { 0 };
                    record.active_dmw_leases = 0;
                    record.generation += 1;
                    (record.generation, cancelled)
                };
                cancelled_waits += cancelled;
                final_activation_generation = Some(activation_generation);
            }
        }
        let revoked = capabilities.revoke_owner_store(store.id, expected_store_generation);
        let revoked_refs = revoked
            .iter()
            .filter_map(|capability_id| {
                capabilities
                    .records()
                    .iter()
                    .find(|record| record.id == *capability_id)
                    .map(CapabilityRecord::object_ref)
            })
            .collect::<Vec<_>>();
        let mut unbound = false;
        let mut code_generation = None;
        let mut code_ref = None;
        if let Some(code) = code.as_deref_mut() {
            if code.bound_store == Some(store.id)
                && code.bound_store_generation == Some(expected_store_generation)
            {
                code.bound_store = None;
                code.bound_store_generation = None;
                code.hostcall_table = None;
                code.state = CodeObjectState::Retired;
                code.generation += 1;
                unbound = true;
            }
            code_generation = Some(code.generation);
            code_ref = Some(code.object_ref());
        }
        store.state = StoreState::Dead;
        store.generation += 1;
        let store_ref = store.object_ref();
        if let Some(activation) = activation {
            if let Some(record) = self.activations.iter_mut().find(|record| record.id == activation)
            {
                record.store_generation = store.generation;
                if let Some(code_generation) = code_generation {
                    record.code_generation = code_generation;
                }
            }
        }
        let finished_at = self.next_event("fault-cleanup-completed");
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Store,
            store.id,
            expected_store_generation,
            finished_at,
            "fault-cleanup-store-target-retired",
        ));
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Store,
            store.id,
            store.generation,
            finished_at,
            "fault-cleanup-store-dead",
        ));
        if let Some(activation) = activation {
            if let Some(generation) = final_activation_generation {
                self.tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Activation,
                    activation,
                    generation,
                    finished_at,
                    "fault-cleanup-activation-dropped",
                ));
            }
        }
        if let Some(code_ref) = code_ref {
            self.tombstones.push(TombstoneRecord::new(
                ContractObjectKind::CodeObject,
                code_ref.id,
                code_ref.generation,
                finished_at,
                "fault-cleanup-code-retired",
            ));
        }
        let state_digest = self.cleanup_state_digest(store, code.as_deref(), capabilities);
        let revoked_count = revoked.len();
        let effects = Self::cleanup_effects_for_completed_transaction(
            store_ref,
            activation.zip(final_activation_generation).map(|(id, generation)| {
                ContractObjectRef::new(ContractObjectKind::Activation, id, generation)
            }),
            code_ref,
            &revoked_refs,
            released,
            cancelled_waits,
            1,
            finished_at,
        );
        let cleanup = self
            .cleanup_transactions
            .iter_mut()
            .find(|cleanup| cleanup.id == cleanup_id)
            .expect("cleanup transaction must exist");
        cleanup.state = CleanupTransactionState::Completed;
        cleanup.generation += 1;
        cleanup.result_store_generation = Some(store.generation);
        cleanup.finished_at = Some(finished_at);
        cleanup.activation_generation =
            final_activation_generation.or(cleanup.activation_generation);
        cleanup.code_generation = code_generation.or(cleanup.code_generation);
        cleanup.released_dmw_leases = released;
        cleanup.cancelled_waits = cancelled_waits;
        cleanup.revoked_capabilities = revoked;
        cleanup.revoked_capability_refs = revoked_refs;
        cleanup.dropped_resources = 1;
        cleanup.unbound_code_object = unbound;
        cleanup.state_digest = state_digest;
        cleanup.effect = FailureEffect::CompleteWithErrno(5);
        let mut steps = Vec::new();
        steps.push(
            CleanupStepRecord::done(CleanupStep::StopNewActivation, "new activations stopped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::SealActivation, "activation sealed")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::PreventHostcalls, "activation dropped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::ReleaseDmwLeases, "leases released")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::CancelWaitTokens, "no wait tokens in harness")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(
                CleanupStep::RevokeCapabilities,
                "store-owned capabilities revoked",
            )
            .with_target(store_ref)
            .with_observed_generation(store.generation)
            .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::DropResourceArena, "resource arena dropped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::UnbindCodeObject, "code object unbound")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::MarkStoreState, "store marked dead")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::RecordTransition, "cleanup transition recorded")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::EmitTombstones, "cleanup tombstones emitted")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::RecordFailureEffect, "failure effect recorded")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::EmitReport, "cleanup report emitted")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        cleanup.steps = steps;
        cleanup.effects = effects;
        self.event_log.push(format!(
            "FaultCleanupCompleted cleanup={cleanup_id} store={} released_dmw={} revoked_caps={} unbound_code={}",
            store.id,
            released,
            revoked_count,
            unbound
        ));
        Ok(cleanup_id)
    }

    pub fn classify_migration_objects(
        &self,
        code_objects: &[CodeObject],
    ) -> Vec<MigrationObjectRecord> {
        let mut records = Vec::new();
        records.push(MigrationObjectRecord::new(
            "semantic-object-graph",
            MigrationObjectClass::Migrated,
            "semantic roots are serialized",
        ));
        records.push(MigrationObjectRecord::new(
            "store-records",
            MigrationObjectClass::Migrated,
            "StoreRecord lifecycle state is semantic",
        ));
        for code in code_objects {
            records.push(MigrationObjectRecord::new(
                &format!("code-object:{}", code.id),
                MigrationObjectClass::Rebuilt,
                "target republishes executable code from verified artifact",
            ));
        }
        records.push(MigrationObjectRecord::new(
            "native-stack",
            MigrationObjectClass::NeverMigrated,
            "native stacks are substrate state",
        ));
        records.push(MigrationObjectRecord::new(
            "dmw-pointer",
            MigrationObjectClass::NeverMigrated,
            "handle-mode leases cannot cross snapshot barrier",
        ));
        records
    }

    pub fn activations(&self) -> &[ActivationRecord] {
        &self.activations
    }

    pub fn traps(&self) -> &[TargetTrapRecord] {
        &self.traps
    }

    pub fn dmw_leases(&self) -> &[DmwLeaseRecord] {
        &self.dmw_leases
    }

    pub fn hostcall_trace(&self) -> &[HostcallTraceRecord] {
        &self.hostcall_trace
    }

    pub fn cleanup_transactions(&self) -> &[FaultCleanupTransaction] {
        &self.cleanup_transactions
    }

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    pub fn restore_records(
        &mut self,
        activations: &[ActivationRecord],
        traps: &[TargetTrapRecord],
        hostcall_trace: &[HostcallTraceRecord],
        cleanup_transactions: &[FaultCleanupTransaction],
        tombstones: &[TombstoneRecord],
    ) -> bool {
        let mut restored_activations = Vec::new();
        for activation in activations {
            if activation.id == 0
                || activation.generation == 0
                || restored_activations
                    .iter()
                    .any(|existing: &ActivationRecord| existing.id == activation.id)
            {
                return false;
            }
            restored_activations.push(activation.clone());
        }

        let mut restored_traps = Vec::new();
        for trap in traps {
            if trap.id == 0
                || trap.generation == 0
                || restored_traps.iter().any(|existing: &TargetTrapRecord| existing.id == trap.id)
            {
                return false;
            }
            restored_traps.push(trap.clone());
        }

        let mut restored_hostcalls = Vec::new();
        for hostcall in hostcall_trace {
            if hostcall.id == 0
                || hostcall.generation == 0
                || restored_hostcalls
                    .iter()
                    .any(|existing: &HostcallTraceRecord| existing.id == hostcall.id)
            {
                return false;
            }
            restored_hostcalls.push(hostcall.clone());
        }

        let mut restored_cleanups = Vec::new();
        for cleanup in cleanup_transactions {
            if cleanup.id == 0
                || cleanup.generation == 0
                || restored_cleanups
                    .iter()
                    .any(|existing: &FaultCleanupTransaction| existing.id == cleanup.id)
            {
                return false;
            }
            restored_cleanups.push(cleanup.clone());
        }

        let mut restored_tombstones = Vec::new();
        for tombstone in tombstones {
            if tombstone.kind != ContractObjectKind::Activation
                || tombstone.id == 0
                || tombstone.generation == 0
                || restored_tombstones.iter().any(|existing: &TombstoneRecord| {
                    existing.object_ref() == tombstone.object_ref()
                })
            {
                return false;
            }
            restored_tombstones.push(tombstone.clone());
        }

        let activation_event_max = restored_activations
            .iter()
            .flat_map(|activation| [Some(activation.start_event), activation.exit_event])
            .flatten()
            .max()
            .unwrap_or(0);
        let cleanup_event_max = restored_cleanups
            .iter()
            .flat_map(|cleanup| [Some(cleanup.started_at), cleanup.finished_at])
            .flatten()
            .max()
            .unwrap_or(0);
        let tombstone_event_max =
            restored_tombstones.iter().map(|tombstone| tombstone.died_at).max().unwrap_or(0);

        let activation_record_next =
            restored_activations.iter().map(|activation| activation.id + 1).max().unwrap_or(1);
        let activation_tombstone_next = restored_tombstones
            .iter()
            .filter(|tombstone| tombstone.kind == ContractObjectKind::Activation)
            .map(|tombstone| tombstone.id + 1)
            .max()
            .unwrap_or(1);
        self.next_activation_id = activation_record_next.max(activation_tombstone_next);
        self.next_trap_id = restored_traps.iter().map(|trap| trap.id + 1).max().unwrap_or(1);
        self.next_hostcall_trace_id =
            restored_hostcalls.iter().map(|hostcall| hostcall.id + 1).max().unwrap_or(1);
        self.next_cleanup_id =
            restored_cleanups.iter().map(|cleanup| cleanup.id + 1).max().unwrap_or(1);
        self.next_lease_id = 1;
        self.next_event_id =
            activation_event_max.max(cleanup_event_max).max(tombstone_event_max) + 1;
        self.activations = restored_activations;
        self.traps = restored_traps;
        self.dmw_leases.clear();
        self.hostcall_trace = restored_hostcalls;
        self.cleanup_transactions = restored_cleanups;
        self.tombstones = restored_tombstones;
        self.event_log.clear();
        true
    }

    pub fn cleanup_state_digest(
        &self,
        store: &StoreRecord,
        code: Option<&CodeObject>,
        capabilities: &CapabilityLedger,
    ) -> String {
        let code_state = code
            .map(|code| {
                format!(
                    "code:{}@{}:{}:bound={}@{}",
                    code.id,
                    code.generation,
                    code.state.as_str(),
                    code.bound_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    code.bound_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            })
            .unwrap_or_else(|| "code:none".to_string());
        let activation_state = self
            .activations
            .iter()
            .map(|activation| {
                format!(
                    "act:{}@{}:{}:store={}@{}:code={}@{}:leases={}:wait={}",
                    activation.id,
                    activation.generation,
                    activation.state.as_str(),
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.active_dmw_leases,
                    activation
                        .blocked_wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let lease_state = self
            .dmw_leases
            .iter()
            .map(|lease| {
                format!(
                    "lease:{}@{}:activation={}:active={}",
                    lease.id, lease.generation, lease.activation, lease.active
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let capability_state = capabilities
            .records()
            .iter()
            .map(|capability| {
                format!(
                    "cap:{}@{}:owner={}:revoked={}",
                    capability.id,
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "store:{}@{}:{}|{}|activations=[{}]|leases=[{}]|caps=[{}]",
            store.id,
            store.generation,
            store.state.as_str(),
            code_state,
            activation_state,
            lease_state,
            capability_state
        )
    }

    pub fn event_log(&self) -> &[String] {
        &self.event_log
    }

    fn cleanup_step_order() -> [CleanupStep; 13] {
        [
            CleanupStep::StopNewActivation,
            CleanupStep::SealActivation,
            CleanupStep::PreventHostcalls,
            CleanupStep::ReleaseDmwLeases,
            CleanupStep::CancelWaitTokens,
            CleanupStep::RevokeCapabilities,
            CleanupStep::DropResourceArena,
            CleanupStep::UnbindCodeObject,
            CleanupStep::MarkStoreState,
            CleanupStep::RecordTransition,
            CleanupStep::EmitTombstones,
            CleanupStep::RecordFailureEffect,
            CleanupStep::EmitReport,
        ]
    }

    fn cleanup_effects_for_completed_transaction(
        store_ref: ContractObjectRef,
        activation_ref: Option<ContractObjectRef>,
        code_ref: Option<ContractObjectRef>,
        capability_refs: &[ContractObjectRef],
        released_dmw_leases: u32,
        cancelled_waits: u32,
        dropped_resources: u32,
        event_seq: EventId,
    ) -> Vec<CleanupEffectRecord> {
        let mut effects = Vec::new();
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::StopNewActivation,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        if let Some(activation_ref) = activation_ref {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::SealActivation,
                activation_ref,
                activation_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if released_dmw_leases != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::ReleaseLeases,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if cancelled_waits != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::CancelWaits,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        for capability_ref in capability_refs {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::RevokeCapability,
                *capability_ref,
                capability_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if dropped_resources != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::DropResources,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if let Some(code_ref) = code_ref {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::UnbindCode,
                code_ref,
                code_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::MarkStoreDead,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::EmitTombstone,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::RecordFailureEffect,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects
    }

    fn cap_arg_denial_reason(
        frame: &HostcallFrame,
        subject: &str,
        object_ref: AuthorityObjectRef,
        required_right: &str,
        capabilities: &CapabilityLedger,
    ) -> Option<&'static str> {
        if frame.cap_args.is_empty() {
            return Some("cap-arg-required");
        }
        let mut matched_frame_object = false;
        for handle in &frame.cap_args {
            let Some(owner_store) = handle.owner_store else {
                return Some("cap-arg-missing");
            };
            let Some(owner_store_generation) = handle.owner_store_generation else {
                return Some("cap-arg-missing");
            };
            let Some(record) = capabilities.records().iter().find(|record| {
                record.owner_store == Some(owner_store)
                    && record.owner_store_generation == Some(owner_store_generation)
                    && record.handle_slot == handle.handle_slot
                    && !record.revoked
            }) else {
                return Some("cap-arg-missing");
            };
            if record.subject != subject {
                return Some("cap-arg-subject");
            }
            if record.object_ref != handle.object_ref || handle.object_ref != Some(object_ref) {
                return Some("cap-arg-object");
            }
            if handle.class_hint != Some(record.class) || record.class != object_ref.class() {
                return Some("cap-arg-object-class");
            }
            if record.handle_generation != handle.handle_generation
                || record.generation != handle.generation
            {
                return Some("cap-arg-generation");
            }
            if record.handle_tag != handle.handle_tag {
                return Some("cap-arg-tag");
            }
            if handle.rights.is_empty() {
                return Some("cap-arg-empty-rights");
            }
            if handle.rights_mask == 0 {
                return Some("cap-arg-rights-mask");
            }
            for right in &handle.rights {
                if !record.operations.contains(right) {
                    return Some("cap-arg-rights");
                }
            }
            let Some(rights_mask) = Self::capability_rights_mask(record, &handle.rights) else {
                return Some("cap-arg-rights-mask");
            };
            if rights_mask != handle.rights_mask {
                return Some("cap-arg-rights-mask");
            }
            if handle.object_ref == Some(object_ref)
                && handle.rights.iter().any(|right| right == required_right)
            {
                matched_frame_object = true;
            }
        }
        if !matched_frame_object {
            return Some("cap-arg-frame-right");
        }
        None
    }

    fn capability_rights_mask(record: &CapabilityRecord, rights: &[String]) -> Option<u64> {
        let mut mask = 0u64;
        for right in rights {
            let index =
                record.operations.as_slice().iter().position(|operation| operation == right)?;
            if index >= u64::BITS as usize {
                return None;
            }
            mask |= 1u64 << index;
        }
        Some(mask)
    }

    fn capability_rights_from_mask(
        record: &CapabilityRecord,
        rights_mask: u64,
    ) -> Option<Vec<String>> {
        if rights_mask == 0 {
            return None;
        }
        let mut rights = Vec::new();
        for (index, operation) in record.operations.as_slice().iter().enumerate() {
            if index >= u64::BITS as usize {
                return None;
            }
            if rights_mask & (1u64 << index) != 0 {
                rights.push(operation.clone());
            }
        }
        let known_mask = Self::capability_rights_mask(record, &rights)?;
        if known_mask == rights_mask { Some(rights) } else { None }
    }

    fn record_trace(
        &mut self,
        frame: &HostcallFrame,
        spec: &HostcallSpec,
        allowed: bool,
        result: &str,
        ret_tag: HostcallReturnTag,
        trap_out: Option<TargetTrapId>,
        wait_token_out: Option<WaitId>,
    ) {
        let id = self.next_hostcall_trace_id;
        self.next_hostcall_trace_id += 1;
        self.hostcall_trace.push(HostcallTraceRecord {
            id,
            generation: 1,
            abi_version: frame.abi_version.clone(),
            frame_size: frame.frame_size,
            flags: frame.flags,
            activation: frame.activation,
            activation_generation: frame.activation_generation,
            store: frame.store,
            store_generation: frame.store_generation,
            code_object: frame.code_object,
            code_generation: frame.code_generation,
            artifact: frame.artifact,
            artifact_generation: frame.artifact_generation,
            hostcall_number: spec.number,
            hostcall_seq: frame.hostcall_seq,
            caller_offset: frame.caller_offset,
            name: spec.name.clone(),
            category: spec.category,
            subject: frame.subject.clone(),
            subject_source: HostcallTraceRecord::SUBJECT_SOURCE_ACTIVE_STATE.to_string(),
            object: spec.object.clone(),
            operation: spec.operation.clone(),
            args: frame.args,
            cap_args: frame.cap_args.clone(),
            record_mode: frame.record_mode,
            allowed,
            gate_status: HostcallTraceRecord::gate_status_for(allowed, ret_tag, trap_out)
                .to_string(),
            result: result.to_string(),
            denial_reason: (!allowed).then(|| result.to_string()),
            ret_tag,
            ret0: frame.ret0,
            ret1: frame.ret1,
            trap_out,
            trap_generation_out: trap_out.map(|_| frame.trap_generation_out.unwrap_or(1)),
            wait_token_out,
            wait_token_generation_out: wait_token_out
                .map(|_| frame.wait_token_generation_out.unwrap_or(1)),
        });
    }

    fn record_trap_for_activation(
        &mut self,
        activation_index: usize,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        hostcall: Option<String>,
        fault_policy: &str,
        effect: FailureEffect,
        detail: &str,
    ) -> TargetTrapId {
        self.record_trap_for_activation_attributed(
            activation_index,
            class,
            code,
            hostcall,
            fault_policy,
            effect,
            detail,
            Some(0),
            None,
        )
    }

    fn record_trap_for_activation_attributed(
        &mut self,
        activation_index: usize,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        hostcall: Option<String>,
        fault_policy: &str,
        effect: FailureEffect,
        detail: &str,
        offset: Option<u64>,
        attribution: Option<TrapAttributionV1>,
    ) -> TargetTrapId {
        let activation_id = self.activations[activation_index].id;
        let store = self.activations[activation_index].store;
        let store_generation = self.activations[activation_index].store_generation;
        let old_activation_generation = self.activations[activation_index].generation;
        self.release_all_leases_for_activation_id(activation_id, "trap-quarantine");
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        let exit_event = self.next_event("activation-trapped");
        self.retire_activation_generation(
            activation_id,
            old_activation_generation,
            exit_event,
            "activation-trapped-previous-generation",
        );
        let activation = &mut self.activations[activation_index];
        activation.state = ActivationState::Trapped;
        activation.trap = Some(id);
        activation.return_tag = Some(HostcallReturnTag::Trap);
        activation.exit_event = Some(exit_event);
        activation.generation += 1;
        let activation_generation = activation.generation;
        self.traps.push(TargetTrapRecord {
            id,
            generation: 1,
            class,
            store: Some(store),
            store_generation: Some(store_generation),
            activation: Some(activation_id),
            activation_generation: Some(activation_generation),
            code_object: code.map(|code| code.id),
            code_generation: code.map(|code| code.generation),
            artifact: code.map(|code| code.artifact_id),
            artifact_generation: code.map(|_| TARGET_ARTIFACT_GENERATION_V1),
            offset,
            target_pc: attribution.map(|attribution| attribution.pc),
            trap_kind: attribution.map(|attribution| attribution.trap_kind.as_str().to_string()),
            function_index: attribution.and_then(|attribution| attribution.function_index),
            wasm_offset: attribution.and_then(|attribution| attribution.wasm_offset),
            debug_symbol: attribution.and_then(|attribution| attribution.debug_symbol),
            classification_status: attribution
                .map(|attribution| attribution.trap_kind.as_str().to_string()),
            attribution_status: trap_attribution_status(attribution).to_string(),
            simd_attribution: attribution.and_then(|attribution| {
                SimdTrapAttribution::from_code(attribution.trap_kind, code)
            }),
            hostcall,
            fault_policy: fault_policy.to_string(),
            effect,
            detail: detail.to_string(),
        });
        id
    }

    fn retire_activation_generation(
        &mut self,
        activation: ActivationId,
        generation: Generation,
        event: EventId,
        reason: &str,
    ) {
        if generation == 0
            || self.tombstones.iter().any(|tombstone| {
                tombstone.object_ref()
                    == ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        activation,
                        generation,
                    )
            })
        {
            return;
        }
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Activation,
            activation,
            generation,
            event,
            reason,
        ));
    }

    fn release_all_leases_for_activation_id(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> u32 {
        let mut released = 0;
        for lease in &mut self.dmw_leases {
            if lease.activation == activation && lease.active {
                lease.active = false;
                lease.generation += 1;
                released += 1;
                self.event_log.push(format!(
                    "DmwLeaseReleased activation={activation} lease={} reason={reason}",
                    lease.id
                ));
            }
        }
        if released != 0 {
            if let Some(index) = self.activations.iter().position(|record| record.id == activation)
            {
                self.activations[index].active_dmw_leases =
                    self.activations[index].active_dmw_leases.saturating_sub(released);
            }
            self.event_log.push(format!(
                "DmwLeaseQuarantined activation={activation} released={released} reason={reason}"
            ));
        }
        released
    }

    fn activation_index(&self, activation: ActivationId) -> Result<usize, TargetExecutorError> {
        self.activations
            .iter()
            .position(|record| record.id == activation)
            .ok_or(TargetExecutorError::ActivationMissing)
    }

    fn next_event(&mut self, label: &str) -> EventId {
        let id = self.next_event_id;
        self.next_event_id += 1;
        self.event_log.push(format!("TargetExecutorEvent id={id} label={label}"));
        id
    }
}

impl Default for TargetExecutor {
    fn default() -> Self {
        Self::new()
    }
}
