use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    task::{Context, Poll, Waker},
    thread,
};

use visa_local_rpc::common::AgentBinding;
use visa_ownership_service::{AuthorityStore, OwnershipServiceError};

use crate::fence::{AdmissionGate, CompletionLease, GateError, PendingPermit};

pub(crate) const MUTATION_QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmitError {
    Gate(GateError),
    QueueFull,
    WorkerStopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreCallError {
    Authority(OwnershipServiceError),
    WorkerStopped,
}

impl StoreCallError {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::WorkerStopped
                | Self::Authority(
                    OwnershipServiceError::StoreMismatch
                        | OwnershipServiceError::Integrity
                        | OwnershipServiceError::Storage
                )
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoreSequencer {
    sender: SyncSender<Command>,
    healthy: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<StoreCallError>>>,
}

enum Command {
    Execute(Box<Work>),
    Shutdown,
}

struct Work {
    caller: AgentBinding,
    request_bytes: Vec<u8>,
    reply: Arc<ReplyCell>,
    _completion_lease: CompletionLease,
}

#[derive(Debug)]
struct ReplyCell {
    state: Mutex<ReplyState>,
}

#[derive(Debug)]
struct ReplyState {
    result: Option<Result<Vec<u8>, StoreCallError>>,
    waker: Option<Waker>,
}

#[derive(Debug)]
pub(crate) struct StoreReply {
    cell: Arc<ReplyCell>,
}

impl StoreSequencer {
    pub(crate) fn start(mut store: AuthorityStore) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(MUTATION_QUEUE_CAPACITY);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = Arc::clone(&healthy);
        let terminal = Arc::new(Mutex::new(None));
        let worker_terminal = Arc::clone(&terminal);
        thread::Builder::new().name("visa-ownershipd-store".to_owned()).spawn(move || {
            while let Ok(command) = receiver.recv() {
                match command {
                    Command::Execute(work) => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            store.execute_exact(work.caller, &work.request_bytes)
                        }));
                        match result {
                            Ok(Ok(response)) => {
                                // Dropping the work releases the per-sender mutation lease.
                                // O1 has already committed or rolled back at this point.
                                work.reply.complete(Ok(response));
                            }
                            Ok(Err(error)) => {
                                let terminal = StoreCallError::Authority(error).is_terminal();
                                if terminal {
                                    publish_terminal(
                                        &worker_health,
                                        &worker_terminal,
                                        StoreCallError::Authority(error),
                                    );
                                }
                                work.reply.complete(Err(StoreCallError::Authority(error)));
                                if terminal {
                                    break;
                                }
                            }
                            Err(_) => {
                                publish_terminal(
                                    &worker_health,
                                    &worker_terminal,
                                    StoreCallError::WorkerStopped,
                                );
                                work.reply.complete(Err(StoreCallError::WorkerStopped));
                                break;
                            }
                        }
                    }
                    Command::Shutdown => break,
                }
            }
            worker_health.store(false, Ordering::Release);
        })?;
        Ok(Self { sender, healthy, terminal })
    }

    pub(crate) fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    pub(crate) fn terminal_error(&self) -> Option<StoreCallError> {
        *self.terminal.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn submit(
        &self,
        gate: &AdmissionGate,
        permit: PendingPermit,
        caller: AgentBinding,
        request_bytes: Vec<u8>,
    ) -> Result<StoreReply, SubmitError> {
        if !self.is_healthy() {
            return Err(SubmitError::WorkerStopped);
        }
        let cell = Arc::new(ReplyCell::new());
        let send = gate
            .with_commit_barrier(&permit, |lease| {
                self.sender.try_send(Command::Execute(Box::new(Work {
                    caller,
                    request_bytes,
                    reply: Arc::clone(&cell),
                    _completion_lease: lease,
                })))
            })
            .map_err(SubmitError::Gate)?;
        match send {
            Ok(()) => {
                drop(permit);
                Ok(StoreReply { cell })
            }
            Err(TrySendError::Full(command)) => {
                drop(command);
                Err(SubmitError::QueueFull)
            }
            Err(TrySendError::Disconnected(command)) => {
                drop(command);
                publish_terminal(&self.healthy, &self.terminal, StoreCallError::WorkerStopped);
                Err(SubmitError::WorkerStopped)
            }
        }
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.sender.try_send(Command::Shutdown);
    }
}

fn record_terminal(slot: &Mutex<Option<StoreCallError>>, error: StoreCallError) {
    let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn publish_terminal(
    healthy: &AtomicBool,
    slot: &Mutex<Option<StoreCallError>>,
    error: StoreCallError,
) {
    record_terminal(slot, error);
    healthy.store(false, Ordering::Release);
}

impl Drop for Work {
    fn drop(&mut self) {
        // If the worker terminates, dropping the receiver also drops queued
        // work. Complete every surviving reply future instead of leaving an
        // admitted D-Bus method pending forever.
        self.reply.complete(Err(StoreCallError::WorkerStopped));
    }
}

impl ReplyCell {
    fn new() -> Self {
        Self { state: Mutex::new(ReplyState { result: None, waker: None }) }
    }

    fn complete(&self, result: Result<Vec<u8>, StoreCallError>) {
        let waker = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.result.is_some() {
                return;
            }
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for StoreReply {
    type Output = Result<Vec<u8>, StoreCallError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.cell.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(result) = state.result.take() {
            Poll::Ready(result)
        } else {
            let replace =
                state.waker.as_ref().is_none_or(|waker| !waker.will_wake(context.waker()));
            if replace {
                state.waker = Some(context.waker().clone());
            }
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        task::{Wake, Waker},
    };

    use super::*;

    struct FlagWake(AtomicBool);

    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn reply_future_is_woken_without_an_async_channel_dependency() {
        let cell = Arc::new(ReplyCell::new());
        let wake = Arc::new(FlagWake(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut reply = StoreReply { cell: Arc::clone(&cell) };
        assert!(Pin::new(&mut reply).poll(&mut context).is_pending());
        cell.complete(Ok(vec![1, 2, 3]));
        assert!(wake.0.load(Ordering::Acquire));
        assert_eq!(Pin::new(&mut reply).poll(&mut context), Poll::Ready(Ok(vec![1, 2, 3])));
    }

    #[test]
    fn first_terminal_cause_is_retained_for_process_exit_classification() {
        let terminal = Mutex::new(None);
        record_terminal(&terminal, StoreCallError::Authority(OwnershipServiceError::StoreMismatch));
        record_terminal(&terminal, StoreCallError::WorkerStopped);
        assert_eq!(
            *terminal.lock().expect("terminal cause"),
            Some(StoreCallError::Authority(OwnershipServiceError::StoreMismatch))
        );
    }

    #[test]
    fn unhealthy_publication_always_exposes_the_typed_terminal_cause() {
        let healthy = AtomicBool::new(true);
        let terminal = Mutex::new(None);
        publish_terminal(
            &healthy,
            &terminal,
            StoreCallError::Authority(OwnershipServiceError::Storage),
        );
        assert!(!healthy.load(Ordering::Acquire));
        assert_eq!(
            *terminal.lock().expect("published terminal cause"),
            Some(StoreCallError::Authority(OwnershipServiceError::Storage))
        );
    }
}
