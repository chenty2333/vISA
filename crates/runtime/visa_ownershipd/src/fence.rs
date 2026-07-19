use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateError {
    Closed,
    AlreadyInFlight,
    StaleEpoch,
    NotDrained,
    GenerationOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActivationError<E> {
    Gate(GateError),
    Callback(E),
}

#[derive(Clone, Debug)]
pub(crate) struct AdmissionGate {
    inner: Arc<GateInner>,
}

#[derive(Debug)]
struct GateInner {
    state: Mutex<GateState>,
}

#[derive(Debug)]
struct GateState {
    epoch: u64,
    open: bool,
    in_flight: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct PendingPermit {
    reservation: Arc<Reservation>,
}

#[derive(Debug)]
pub(crate) struct CompletionLease {
    _reservation: Arc<Reservation>,
}

#[derive(Debug)]
struct Reservation {
    gate: Arc<GateInner>,
    sender: String,
    epoch: u64,
}

impl AdmissionGate {
    pub(crate) fn new_closed() -> Self {
        Self {
            inner: Arc::new(GateInner {
                state: Mutex::new(GateState { epoch: 0, open: false, in_flight: BTreeSet::new() }),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn open_next_epoch(&self) -> Result<u64, GateError> {
        let epoch = self.begin_next_epoch()?;
        self.activate_epoch_with(epoch, || Ok::<_, ()>(())).map_err(|error| match error {
            ActivationError::Gate(error) => error,
            ActivationError::Callback(()) => GateError::Closed,
        })?;
        Ok(epoch)
    }

    pub(crate) fn begin_next_epoch(&self) -> Result<u64, GateError> {
        let mut state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.open || !state.in_flight.is_empty() {
            return Err(GateError::NotDrained);
        }
        state.epoch = state.epoch.checked_add(1).ok_or(GateError::GenerationOverflow)?;
        Ok(state.epoch)
    }

    /// Makes an already prepared epoch observable while holding the same
    /// mutex used by request reservation. The callback may deliver READY; no
    /// method can observe the open gate until the callback succeeds and this
    /// mutex is released. Failure rolls the epoch back to closed.
    pub(crate) fn activate_epoch_with<E>(
        &self,
        epoch: u64,
        activate: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), ActivationError<E>> {
        let mut state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.open || state.epoch != epoch || !state.in_flight.is_empty() {
            return Err(ActivationError::Gate(GateError::StaleEpoch));
        }
        state.open = true;
        if let Err(error) = activate() {
            state.open = false;
            return Err(ActivationError::Callback(error));
        }
        Ok(())
    }

    pub(crate) fn close_epoch(&self, epoch: u64) -> bool {
        let mut state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.epoch != epoch || !state.open {
            return false;
        }
        state.open = false;
        true
    }

    pub(crate) fn reserve(&self, sender: &str) -> Result<PendingPermit, GateError> {
        let mut state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.open {
            return Err(GateError::Closed);
        }
        if !state.in_flight.insert(sender.to_owned()) {
            return Err(GateError::AlreadyInFlight);
        }
        Ok(PendingPermit {
            reservation: Arc::new(Reservation {
                gate: Arc::clone(&self.inner),
                sender: sender.to_owned(),
                epoch: state.epoch,
            }),
        })
    }

    /// Runs the final queue insertion while holding the same mutex used by
    /// `close_epoch`. This is the application-level linearization barrier:
    /// either loss closes the epoch first and the closure is not called, or
    /// the closure admits a work item that is allowed to finish through O1.
    pub(crate) fn with_commit_barrier<T>(
        &self,
        permit: &PendingPermit,
        admit: impl FnOnce(CompletionLease) -> T,
    ) -> Result<T, GateError> {
        let state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.open {
            return Err(GateError::Closed);
        }
        if state.epoch != permit.reservation.epoch {
            return Err(GateError::StaleEpoch);
        }
        if !state.in_flight.contains(&permit.reservation.sender) {
            return Err(GateError::StaleEpoch);
        }
        let lease = CompletionLease { _reservation: Arc::clone(&permit.reservation) };
        Ok(admit(lease))
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.inner.state.lock().unwrap_or_else(|error| error.into_inner()).in_flight.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (u64, bool, Vec<String>) {
        let state = self.inner.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.epoch, state.open, state.in_flight.iter().cloned().collect())
    }
}

impl PendingPermit {
    pub(crate) fn epoch(&self) -> u64 {
        self.reservation.epoch
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|error| error.into_inner());
        state.in_flight.remove(&self.sender);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_and_queue_admission_share_one_barrier() {
        let gate = AdmissionGate::new_closed();
        let epoch = gate.open_next_epoch().expect("open first epoch");
        let permit = gate.reserve(":1.7").expect("reserve sender");
        let lease = gate.with_commit_barrier(&permit, |lease| lease).expect("admit before loss");
        assert!(gate.close_epoch(epoch));
        assert!(matches!(gate.reserve(":1.8"), Err(GateError::Closed)));
        drop(permit);
        assert!(!gate.is_drained(), "queued work keeps the reservation alive");
        drop(lease);
        assert!(gate.is_drained());
        assert_eq!(gate.open_next_epoch(), Ok(2));
    }

    #[test]
    fn loss_before_barrier_prevents_admission() {
        let gate = AdmissionGate::new_closed();
        let epoch = gate.open_next_epoch().expect("open first epoch");
        let permit = gate.reserve(":1.9").expect("reserve sender");
        assert!(gate.close_epoch(epoch));
        assert_eq!(
            gate.with_commit_barrier(&permit, |lease| lease).unwrap_err(),
            GateError::Closed
        );
        drop(permit);
        assert!(gate.is_drained());
    }

    #[test]
    fn one_sender_has_at_most_one_mutation_in_flight() {
        let gate = AdmissionGate::new_closed();
        gate.open_next_epoch().expect("open first epoch");
        let first = gate.reserve(":1.10").expect("first request");
        assert!(matches!(gate.reserve(":1.10"), Err(GateError::AlreadyInFlight)));
        assert!(gate.reserve(":1.11").is_ok());
        drop(first);
    }

    #[test]
    fn failed_activation_rolls_back_before_any_reservation_is_visible() {
        let gate = AdmissionGate::new_closed();
        let epoch = gate.begin_next_epoch().expect("prepare first epoch");
        assert_eq!(
            gate.activate_epoch_with(epoch, || Err::<(), _>("notify failed")),
            Err(ActivationError::Callback("notify failed"))
        );
        assert_eq!(gate.snapshot(), (epoch, false, Vec::new()));
        assert!(matches!(gate.reserve(":1.12"), Err(GateError::Closed)));
    }
}
