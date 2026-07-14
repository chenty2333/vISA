wit_bindgen::generate!({
    path: "../../../wit/regular-file-continuity",
    world: "regular-file-continuity",
});

use std::cell::RefCell;

use exports::visa::file_continuity::workload::{ComponentState, Guest, Phase, WorkloadError};
use visa::file_continuity::regular_file::{
    Durability, FileBinding, FileError, FileObservation, ReadResult,
};

struct LiveState {
    portable: ComponentState,
    file: FileBinding,
}

thread_local! {
    static STATE: RefCell<Option<LiveState>> = const { RefCell::new(None) };
}

struct FileWorkload;

impl Guest for FileWorkload {
    fn activate(
        session_id: String,
        mut state: ComponentState,
        file: FileBinding,
    ) -> Result<(), WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            if slot.is_some() {
                return Err(WorkloadError::AlreadyActive);
            }
            if state.phase != Phase::Active || state.session_id != session_id {
                return Err(WorkloadError::InvalidState);
            }
            state.session_id = session_id;
            *slot = Some(LiveState { portable: state, file });
            Ok(())
        })
    }

    fn read(max_bytes: u32) -> Result<ReadResult, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let result = live.file.read(max_bytes).map_err(WorkloadError::File)?;
            apply_observation(&mut live.portable, &result.observation);
            Ok(result)
        })
    }

    fn write(
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: Durability,
    ) -> Result<FileObservation, WorkloadError> {
        mutate(|file| file.write(&idempotency_key, &bytes, durability))
    }

    fn append(
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: Durability,
    ) -> Result<FileObservation, WorkloadError> {
        mutate(|file| file.append(&idempotency_key, &bytes, durability))
    }

    fn truncate(
        idempotency_key: String,
        size: u64,
        durability: Durability,
    ) -> Result<FileObservation, WorkloadError> {
        mutate(|file| file.truncate(&idempotency_key, size, durability))
    }

    fn rename(
        idempotency_key: String,
        relative_path: String,
    ) -> Result<FileObservation, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let result =
                live.file.rename(&idempotency_key, &relative_path).map_err(WorkloadError::File)?;
            live.portable.relative_path = relative_path;
            apply_observation(&mut live.portable, &result);
            Ok(result)
        })
    }

    fn sync(
        idempotency_key: String,
        durability: Durability,
    ) -> Result<FileObservation, WorkloadError> {
        mutate(|file| file.sync(&idempotency_key, durability))
    }

    fn acquire_lock(idempotency_key: String) -> Result<FileObservation, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let result = live.file.acquire_lock(&idempotency_key).map_err(WorkloadError::File)?;
            live.portable.lock_held = true;
            apply_observation(&mut live.portable, &result);
            Ok(result)
        })
    }

    fn release_lock(idempotency_key: String) -> Result<FileObservation, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let live = active(slot)?;
            let result = live.file.release_lock(&idempotency_key).map_err(WorkloadError::File)?;
            live.portable.lock_held = false;
            apply_observation(&mut live.portable, &result);
            Ok(result)
        })
    }

    fn freeze() -> Result<ComponentState, WorkloadError> {
        STATE.with_borrow_mut(|slot| {
            let mut live = slot.take().ok_or(WorkloadError::InvalidState)?;
            if live.portable.session_id == "safe-point-unreachable:session" {
                *slot = Some(live);
                return Err(WorkloadError::SafePointUnavailable);
            }
            if live.portable.lock_held {
                *slot = Some(live);
                return Err(WorkloadError::SafePointUnavailable);
            }
            live.portable.phase = Phase::Frozen;
            Ok(live.portable)
        })
    }

    fn thaw(state: ComponentState, file: FileBinding) -> Result<(), WorkloadError> {
        restore_live(state, file)
    }

    fn restore(state: ComponentState, file: FileBinding) -> Result<(), WorkloadError> {
        restore_live(state, file)
    }

    fn status() -> Option<ComponentState> {
        STATE.with_borrow(|slot| slot.as_ref().map(|live| live.portable.clone()))
    }
}

fn active(slot: &mut Option<LiveState>) -> Result<&mut LiveState, WorkloadError> {
    let live = slot.as_mut().ok_or(WorkloadError::InvalidState)?;
    if live.portable.phase != Phase::Active {
        return Err(WorkloadError::InvalidState);
    }
    Ok(live)
}

fn mutate(
    call: impl FnOnce(&FileBinding) -> Result<FileObservation, FileError>,
) -> Result<FileObservation, WorkloadError> {
    STATE.with_borrow_mut(|slot| {
        let live = active(slot)?;
        let result = call(&live.file).map_err(WorkloadError::File)?;
        apply_observation(&mut live.portable, &result);
        Ok(result)
    })
}

fn restore_live(mut state: ComponentState, file: FileBinding) -> Result<(), WorkloadError> {
    STATE.with_borrow_mut(|slot| {
        if slot.is_some() || state.phase != Phase::Frozen {
            return Err(WorkloadError::InvalidState);
        }
        state.phase = Phase::Active;
        *slot = Some(LiveState { portable: state, file });
        Ok(())
    })
}

fn apply_observation(state: &mut ComponentState, observed: &FileObservation) {
    state.logical_offset = observed.logical_offset;
    state.version = observed.version;
    state.size = observed.size;
    state.content_digest.clone_from(&observed.content_digest);
    state.durable_through = observed.durable_through;
    state.last_operation_id = Some(observed.operation_id.clone());
}

export!(FileWorkload);
