use super::*;

impl SemanticGraph {
    pub fn publish_boundary(
        &mut self,
        name: &str,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: &str,
        blocked_by: Option<&str>,
    ) -> BoundaryId {
        if let Some(index) = self
            .boundaries
            .iter()
            .position(|boundary| boundary.name == name)
        {
            self.boundaries[index].kind = kind;
            self.boundaries[index].status = status;
            self.boundaries[index].backend = backend.to_string();
            self.boundaries[index].blocked_by = blocked_by.map(|value| value.to_string());
            self.boundaries[index].generation += 1;
            let id = self.boundaries[index].id;
            let name = self.boundaries[index].name.clone();
            let backend = self.boundaries[index].backend.clone();
            let blocked_by = self.boundaries[index].blocked_by.clone();
            let generation = self.boundaries[index].generation;
            self.event_log.push(
                "boundary",
                EventKind::BoundaryPublished {
                    boundary: id,
                    name,
                    kind,
                    status,
                    backend,
                    blocked_by,
                    generation,
                },
            );
            return id;
        }

        let id = self.next_boundary_id;
        self.next_boundary_id += 1;
        let boundary = BoundaryRecord {
            id,
            name: name.to_string(),
            kind,
            status,
            backend: backend.to_string(),
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        };
        self.event_log.push(
            "boundary",
            EventKind::BoundaryPublished {
                boundary: id,
                name: boundary.name.clone(),
                kind,
                status,
                backend: boundary.backend.clone(),
                blocked_by: boundary.blocked_by.clone(),
                generation: boundary.generation,
            },
        );
        self.boundaries.push(boundary);
        id
    }
    #[allow(clippy::too_many_arguments)]
    pub fn record_artifact_verification(
        &mut self,
        package: &str,
        artifact_name: &str,
        manifest_binding_hash: &str,
        cwasm_sha256: &str,
        abi_fingerprint: &str,
        signature_profile: &str,
        signer: &str,
        state: ArtifactVerificationState,
        blocked_by: Option<&str>,
    ) -> ArtifactId {
        if let Some(index) = self
            .artifact_verifications
            .iter()
            .position(|record| record.package == package)
        {
            self.artifact_verifications[index].artifact_name = artifact_name.to_string();
            self.artifact_verifications[index].manifest_binding_hash =
                manifest_binding_hash.to_string();
            self.artifact_verifications[index].cwasm_sha256 = cwasm_sha256.to_string();
            self.artifact_verifications[index].abi_fingerprint = abi_fingerprint.to_string();
            self.artifact_verifications[index].signature_profile = signature_profile.to_string();
            self.artifact_verifications[index].signer = signer.to_string();
            self.artifact_verifications[index].state = state;
            self.artifact_verifications[index].blocked_by =
                blocked_by.map(|value| value.to_string());
            self.artifact_verifications[index].generation += 1;
            let record = &self.artifact_verifications[index];
            self.event_log.push(
                "artifact",
                EventKind::ArtifactVerificationRecorded {
                    artifact: record.id,
                    package: record.package.clone(),
                    artifact_name: record.artifact_name.clone(),
                    state,
                    manifest_binding_hash: record.manifest_binding_hash.clone(),
                    blocked_by: record.blocked_by.clone(),
                    generation: record.generation,
                },
            );
            return record.id;
        }

        let id = self.next_artifact_id;
        self.next_artifact_id += 1;
        let record = ArtifactVerificationRecord {
            id,
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            cwasm_sha256: cwasm_sha256.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            signature_profile: signature_profile.to_string(),
            signer: signer.to_string(),
            state,
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        };
        self.event_log.push(
            "artifact",
            EventKind::ArtifactVerificationRecorded {
                artifact: id,
                package: record.package.clone(),
                artifact_name: record.artifact_name.clone(),
                state,
                manifest_binding_hash: record.manifest_binding_hash.clone(),
                blocked_by: record.blocked_by.clone(),
                generation: record.generation,
            },
        );
        self.artifact_verifications.push(record);
        id
    }
    #[allow(clippy::too_many_arguments)]
    pub fn record_store_activation(
        &mut self,
        store: StoreId,
        package: &str,
        manifest_binding_hash: &str,
        cwasm_sha256: &str,
        code_publish_state: CodePublishState,
        memory_layout_state: MemoryLayoutState,
        hostcall_table_state: HostcallLinkState,
        trap_surface_state: TrapSurfaceState,
        entrypoint_state: EntrypointState,
        blocked_by: Option<&str>,
    ) -> StoreActivationId {
        if let Some(index) = self
            .store_activations
            .iter()
            .position(|record| record.store == store)
        {
            self.store_activations[index].package = package.to_string();
            self.store_activations[index].manifest_binding_hash = manifest_binding_hash.to_string();
            self.store_activations[index].cwasm_sha256 = cwasm_sha256.to_string();
            self.store_activations[index].code_publish_state = code_publish_state;
            self.store_activations[index].memory_layout_state = memory_layout_state;
            self.store_activations[index].hostcall_table_state = hostcall_table_state;
            self.store_activations[index].trap_surface_state = trap_surface_state;
            self.store_activations[index].entrypoint_state = entrypoint_state;
            self.store_activations[index].blocked_by = blocked_by.map(|value| value.to_string());
            self.store_activations[index].generation += 1;
            let record = &self.store_activations[index];
            self.event_log.push(
                "activation",
                EventKind::StoreActivationRecorded {
                    activation: record.id,
                    store,
                    package: record.package.clone(),
                    code_publish_state,
                    memory_layout_state,
                    hostcall_table_state,
                    trap_surface_state,
                    entrypoint_state,
                    blocked_by: record.blocked_by.clone(),
                    generation: record.generation,
                },
            );
            return record.id;
        }

        let id = self.next_activation_id;
        self.next_activation_id += 1;
        let record = StoreActivationRecord::new(
            id,
            store,
            package,
            manifest_binding_hash,
            cwasm_sha256,
            code_publish_state,
            memory_layout_state,
            hostcall_table_state,
            trap_surface_state,
            entrypoint_state,
            blocked_by,
        );
        self.event_log.push(
            "activation",
            EventKind::StoreActivationRecorded {
                activation: id,
                store,
                package: record.package.clone(),
                code_publish_state,
                memory_layout_state,
                hostcall_table_state,
                trap_surface_state,
                entrypoint_state,
                blocked_by: record.blocked_by.clone(),
                generation: record.generation,
            },
        );
        self.store_activations.push(record);
        id
    }
    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }
    pub fn artifact_verification_count(&self) -> usize {
        self.artifact_verifications.len()
    }
    pub fn store_activation_count(&self) -> usize {
        self.store_activations.len()
    }
    pub fn boundaries(&self) -> &[BoundaryRecord] {
        &self.boundaries
    }
    pub fn artifact_verifications(&self) -> &[ArtifactVerificationRecord] {
        &self.artifact_verifications
    }
    pub fn artifact_verification_for_package(
        &self,
        package: &str,
    ) -> Option<&ArtifactVerificationRecord> {
        self.artifact_verifications
            .iter()
            .find(|record| record.package == package)
    }
    pub fn store_activations(&self) -> &[StoreActivationRecord] {
        &self.store_activations
    }
    pub fn store_activation_handle(&self, store: StoreId) -> Option<StoreActivationHandle> {
        self.store_activations
            .iter()
            .find(|record| record.store == store)
            .map(|record| StoreActivationHandle::new(record.store, record.generation))
    }
    pub fn validate_store_activation_handle(
        &mut self,
        handle: StoreActivationHandle,
    ) -> Result<(), GenerationCheckError> {
        let activation = self
            .store_activations
            .iter()
            .find(|record| record.store == handle.store);
        let actual = activation.map(|record| record.generation);
        let result = match activation {
            None => Err(GenerationCheckError::Missing),
            Some(record) if record.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "activation",
                    EventKind::StoreActivationHandleValidated {
                        store: handle.store,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "activation",
                    EventKind::StoreActivationHandleRejected {
                        store: handle.store,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }
}
