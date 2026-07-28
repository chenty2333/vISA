use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use substrate_api::{
    AuthorityPort, BindingPort, JournalPort, KvPort, LeasePort, ProfilePort, ProviderError,
    ProviderErrorKind, TimerPort,
};
use substrate_host::SqliteProvider;

use super::{
    PROVIDER_RPC_SCHEMA_VERSION, validate_database_id,
    wire::{
        MAX_FRAME_BYTES, Request, RequestEnvelope, ResponseEnvelope, Value,
        WireProfileDispatchAuthorization,
    },
};

#[derive(Debug)]
pub enum ProviderRpcServerError {
    Io { operation: &'static str, path: PathBuf, source: io::Error },
    InvalidDatabaseRoot(PathBuf),
    InvalidSocketPath(PathBuf),
    ExistingSocketPath(PathBuf),
    ThreadPanic,
}

impl std::fmt::Display for ProviderRpcServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { operation, path, source } => {
                write!(formatter, "{operation} {}: {source}", path.display())
            }
            Self::InvalidDatabaseRoot(path) => {
                write!(formatter, "invalid provider database root {}", path.display())
            }
            Self::InvalidSocketPath(path) => {
                write!(formatter, "invalid provider socket path {}", path.display())
            }
            Self::ExistingSocketPath(path) => {
                write!(formatter, "provider socket path already exists {}", path.display())
            }
            Self::ThreadPanic => formatter.write_str("provider RPC server thread panicked"),
        }
    }
}

impl std::error::Error for ProviderRpcServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

struct BoundProviderServer {
    listener: UnixListener,
    socket_path: PathBuf,
    database_root: PathBuf,
    _socket_guard: SocketGuard,
}

impl BoundProviderServer {
    fn bind(
        database_root: impl AsRef<Path>,
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, ProviderRpcServerError> {
        let database_root = prepare_database_root(database_root.as_ref())?;
        let socket_path = prepare_socket_path(socket_path.as_ref())?;
        let listener =
            UnixListener::bind(&socket_path).map_err(|source| ProviderRpcServerError::Io {
                operation: "bind provider RPC socket",
                path: socket_path.clone(),
                source,
            })?;
        let socket_guard = SocketGuard(socket_path.clone());
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ProviderRpcServerError::Io {
                operation: "set provider RPC socket permissions",
                path: socket_path.clone(),
                source,
            }
        })?;
        Ok(Self { listener, socket_path, database_root, _socket_guard: socket_guard })
    }

    fn spawn(self) -> Result<ProviderServer, ProviderRpcServerError> {
        self.listener.set_nonblocking(true).map_err(|source| ProviderRpcServerError::Io {
            operation: "configure provider RPC listener",
            path: self.socket_path.clone(),
            source,
        })?;
        let Self {
            listener,
            socket_path: server_socket_path,
            database_root,
            _socket_guard: socket_guard,
        } = self;
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let server_sessions = Arc::clone(&sessions);
        let socket_path = server_socket_path.clone();
        let handle = thread::Builder::new()
            .name("visa-provider-rpc-server".to_owned())
            .spawn(move || {
                let _socket_guard = socket_guard;
                let next_session = AtomicU64::new(0);
                let mut session_threads = Vec::new();
                let mut result = loop {
                    if server_shutdown.load(Ordering::Acquire) {
                        break Ok(());
                    }
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let root = database_root.clone();
                            let session_id = next_session.fetch_add(1, Ordering::Relaxed);
                            let control_stream = stream.try_clone().map_err(|source| {
                                ProviderRpcServerError::Io {
                                    operation: "clone provider RPC session",
                                    path: server_socket_path.clone(),
                                    source,
                                }
                            })?;
                            server_sessions
                                .lock()
                                .map_err(|_| ProviderRpcServerError::ThreadPanic)?
                                .push((session_id, control_stream));
                            if server_shutdown.load(Ordering::Acquire)
                                && let Ok(sessions) = server_sessions.lock()
                                && let Some((_, stream)) =
                                    sessions.iter().find(|(id, _)| *id == session_id)
                            {
                                let _ = stream.shutdown(Shutdown::Both);
                            }
                            let session_registry = Arc::clone(&server_sessions);
                            match thread::Builder::new()
                                .name("visa-provider-rpc-session".to_owned())
                                .spawn(move || {
                                    let _ = serve_connection(stream, &root);
                                    if let Ok(mut sessions) = session_registry.lock() {
                                        sessions.retain(|(id, _)| *id != session_id);
                                    }
                                }) {
                                Ok(handle) => session_threads.push(handle),
                                Err(source) => {
                                    if let Ok(mut sessions) = server_sessions.lock() {
                                        sessions.retain(|(id, _)| *id != session_id);
                                    }
                                    break Err(ProviderRpcServerError::Io {
                                        operation: "spawn provider RPC session",
                                        path: server_socket_path.clone(),
                                        source,
                                    });
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(source) => {
                            break Err(ProviderRpcServerError::Io {
                                operation: "accept provider RPC connection",
                                path: server_socket_path.clone(),
                                source,
                            });
                        }
                    }
                };
                for session in session_threads {
                    if session.join().is_err() && result.is_ok() {
                        result = Err(ProviderRpcServerError::ThreadPanic);
                    }
                }
                result
            })
            .map_err(|source| ProviderRpcServerError::Io {
                operation: "spawn provider RPC server",
                path: socket_path.clone(),
                source,
            })?;
        Ok(ProviderServer { shutdown, sessions, handle: Some(handle), socket_path })
    }
}

pub struct ProviderServer {
    shutdown: Arc<AtomicBool>,
    sessions: Arc<Mutex<Vec<(u64, UnixStream)>>>,
    handle: Option<thread::JoinHandle<Result<(), ProviderRpcServerError>>>,
    socket_path: PathBuf,
}

impl ProviderServer {
    pub fn start(
        database_root: impl AsRef<Path>,
        socket_path: impl AsRef<Path>,
    ) -> Result<Self, ProviderRpcServerError> {
        BoundProviderServer::bind(database_root, socket_path)?.spawn()
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn shutdown(mut self) -> Result<(), ProviderRpcServerError> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), ProviderRpcServerError> {
        self.shutdown.store(true, Ordering::Release);
        for (_, stream) in
            self.sessions.lock().map_err(|_| ProviderRpcServerError::ThreadPanic)?.iter()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle.join().map_err(|_| ProviderRpcServerError::ThreadPanic)?
    }
}

impl Drop for ProviderServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn serve_connection(stream: UnixStream, database_root: &Path) -> io::Result<()> {
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let Some(open) = read_request(&mut reader)? else {
        return Ok(());
    };
    if open.schema_version != PROVIDER_RPC_SCHEMA_VERSION {
        write_response(
            &mut writer,
            &ResponseEnvelope::protocol_error(open.request_id, "unsupported RPC schema"),
        )?;
        return Ok(());
    }
    if matches!(open.request, Request::Ping) {
        write_response(&mut writer, &ResponseEnvelope::ok(open.request_id, Value::Unit))?;
        return Ok(());
    }
    let Request::Open { database_id, scope } = open.request else {
        write_response(
            &mut writer,
            &ResponseEnvelope::protocol_error(open.request_id, "first request must open a session"),
        )?;
        return Ok(());
    };
    let mut provider = match open_provider(database_root, &database_id, scope.into()) {
        Ok(provider) => provider,
        Err(OpenProviderError::Protocol(detail)) => {
            write_response(
                &mut writer,
                &ResponseEnvelope::protocol_error(open.request_id, detail),
            )?;
            return Ok(());
        }
        Err(OpenProviderError::Provider(error)) => {
            write_response(&mut writer, &ResponseEnvelope::provider_error(open.request_id, error))?;
            return Ok(());
        }
    };
    write_response(&mut writer, &ResponseEnvelope::ok(open.request_id, Value::Unit))?;

    while let Some(envelope) = read_request(&mut reader)? {
        let response = if envelope.schema_version != PROVIDER_RPC_SCHEMA_VERSION {
            ResponseEnvelope::protocol_error(envelope.request_id, "unsupported RPC schema")
        } else if matches!(envelope.request, Request::Open { .. }) {
            ResponseEnvelope::protocol_error(envelope.request_id, "session is already open")
        } else {
            match dispatch(&mut provider, envelope.request) {
                Ok(value) => ResponseEnvelope::ok(envelope.request_id, value),
                Err(error) => ResponseEnvelope::provider_error(envelope.request_id, error),
            }
        };
        write_response(&mut writer, &response)?;
    }
    Ok(())
}

enum OpenProviderError {
    Protocol(&'static str),
    Provider(ProviderError),
}

fn open_provider(
    database_root: &Path,
    database_id: &str,
    scope: substrate_api::JournalScope,
) -> Result<SqliteProvider, OpenProviderError> {
    validate_database_id(database_id)
        .map_err(|_| OpenProviderError::Protocol("invalid database_id"))?;
    let path = database_root.join(format!("{database_id}.sqlite3"));
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(OpenProviderError::Protocol("unsafe provider database path"));
    }
    SqliteProvider::open(path, scope).map_err(OpenProviderError::Provider)
}

fn dispatch(provider: &mut SqliteProvider, request: Request) -> Result<Value, ProviderError> {
    match request {
        Request::Ping => Ok(Value::Unit),
        Request::Open { .. } => Err(protocol_provider_error()),
        Request::InjectFailure { point } => {
            provider.inject_failure_once(point.into());
            Ok(Value::Unit)
        }
        Request::FaultObservation => {
            Ok(Value::OptionalFaultObservation(provider.fault_observation().map(Into::into)))
        }
        Request::InspectKeyValue { resource, key } => {
            Ok(Value::VersionedValueOption(provider.inspect_key_value(resource, &key)?))
        }
        Request::ProvisionKeyValueNamespace { resource, namespace } => {
            provider.provision_key_value_namespace(resource, namespace)?;
            Ok(Value::Unit)
        }
        Request::ProvisionKeyValueNamespaceAvailability { node, namespace } => {
            provider.provision_key_value_namespace_availability(node, namespace)?;
            Ok(Value::Unit)
        }
        Request::AppendEntry { entry } => {
            provider.append_entry(&entry)?;
            Ok(Value::Unit)
        }
        Request::CommitActivation { bundle } => {
            provider.commit_activation(&bundle.into())?;
            Ok(Value::Unit)
        }
        Request::CommitBundle { bundle } => {
            provider.commit_bundle(&bundle.into())?;
            Ok(Value::Unit)
        }
        Request::Entry { position } => Ok(Value::OptionalJournalEntry(provider.entry(position)?)),
        Request::Operation { operation } => {
            Ok(Value::OptionalOperationObservation(provider.operation(operation)?.map(Into::into)))
        }
        Request::Idempotency { key } => {
            Ok(Value::OptionalOperationObservation(provider.idempotency(key)?.map(Into::into)))
        }
        Request::ReplayFrom { after } => Ok(Value::JournalEntries(provider.replay_from(after)?)),
        Request::KvRead { request } => Ok(Value::EffectOutcome(provider.read(&request)?)),
        Request::KvCompareAndSet { request } => {
            Ok(Value::EffectOutcome(provider.compare_and_set(&request)?))
        }
        Request::KvQueryOperation { operation, idempotency_key } => {
            Ok(Value::OptionalEffectOutcome(provider.query_operation(operation, idempotency_key)?))
        }
        Request::TimerArm { request } => Ok(Value::EffectOutcome(provider.arm(&request)?)),
        Request::TimerCancel { request } => Ok(Value::EffectOutcome(provider.cancel(&request)?)),
        Request::TimerRestoreBinding { request, recovery } => {
            provider.restore_timer_binding(&request, recovery.into())?;
            Ok(Value::Unit)
        }
        Request::TimerObserve { operation } => {
            Ok(Value::TimerObservation(provider.observe(operation)?.into()))
        }
        Request::TimerSuspend { operation } => {
            Ok(Value::TimerObservation(provider.suspend_timer(operation)?.into()))
        }
        Request::TimerResume { operation } => {
            provider.resume_suspended(operation)?;
            Ok(Value::Unit)
        }
        Request::TimerCleanup { operation } => {
            provider.cleanup_timer(operation)?;
            Ok(Value::Unit)
        }
        Request::InstallPolicy { policy } => {
            provider.install_policy(policy.into())?;
            Ok(Value::Unit)
        }
        Request::InstallGrant { grant } => {
            provider.install_grant(&grant)?;
            Ok(Value::Unit)
        }
        Request::Attenuate { handoff, snapshot, parent, derived } => {
            Ok(Value::AuthorityGrant(provider.attenuate(handoff, snapshot, parent, &derived)?))
        }
        Request::Revoke { authority } => {
            provider.revoke(authority)?;
            Ok(Value::Unit)
        }
        Request::Reauthorize { request } => {
            Ok(Value::AuthorityGrant(provider.reauthorize(request.into())?))
        }
        Request::AuthorizeEffect { request, required_rights } => {
            Ok(Value::Rights(provider.authorize_effect(&request, required_rights)?))
        }
        Request::RevokePrepared { snapshot } => {
            provider.revoke_prepared(snapshot)?;
            Ok(Value::Unit)
        }
        Request::InitializeLease { lease } => {
            provider.initialize_lease(lease.into())?;
            Ok(Value::Unit)
        }
        Request::PrepareTransitions { request, resources } => Ok(Value::PreparedLeaseTransitions(
            provider.prepare_transitions(&request, &resources)?.into(),
        )),
        Request::CurrentLease { resource } => {
            Ok(Value::OptionalLeaseRecord(provider.current_lease(resource)?.map(Into::into)))
        }
        Request::CheckLease { resource, owner, epoch } => {
            provider.check_lease(resource, owner, epoch)?;
            Ok(Value::Unit)
        }
        Request::PrepareBinding { request } => {
            Ok(Value::BindingReceipt(provider.prepare_binding(request.into())?))
        }
        Request::Binding { snapshot, claim } => {
            Ok(Value::OptionalBindingReceipt(provider.binding(snapshot, claim)?))
        }
        Request::CleanupBinding { snapshot, claim } => {
            provider.cleanup_binding(snapshot, claim)?;
            Ok(Value::Unit)
        }
        Request::RequireProfileDispatchAuthorization { profile } => {
            provider.require_profile_dispatch_authorization(profile)?;
            Ok(Value::Unit)
        }
        // The token is intentionally non-forgeable and has no public
        // constructor. Native Stage 4 fixes timer/KV, so profile dispatch is
        // outside this transport claim and remains fail closed.
        Request::ArmProfileDispatch { authorization: WireProfileDispatchAuthorization { .. } } => {
            Err(ProviderError::new(ProviderErrorKind::Unsupported, false))
        }
        Request::FinishProfileDispatch { binding } => {
            Ok(Value::Bool(provider.finish_profile_dispatch(binding.into())?))
        }
        Request::ExecuteProfile { request, extension } => {
            Ok(Value::EffectOutcome(provider.execute_profile(&request, &extension)?))
        }
        Request::QueryProfileOperation { operation, idempotency_key } => {
            Ok(Value::OptionalEffectOutcome(
                provider.query_profile_operation(operation, idempotency_key)?,
            ))
        }
        Request::ReconcileProfileOperation { request, extension } => {
            Ok(Value::OptionalEffectOutcome(
                provider.reconcile_profile_operation(&request, &extension)?,
            ))
        }
        Request::CleanupProfileOperation { request } => {
            provider.cleanup_profile_operation(&request)?;
            Ok(Value::Unit)
        }
    }
}

fn read_request(reader: &mut BufReader<UnixStream>) -> io::Result<Option<RequestEnvelope>> {
    let mut frame = Vec::new();
    let read = reader
        .take(u64::try_from(MAX_FRAME_BYTES + 1).unwrap_or(u64::MAX))
        .read_until(b'\n', &mut frame)?;
    if read == 0 {
        return Ok(None);
    }
    if frame.len() > MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider RPC request frame is invalid",
        ));
    }
    frame.pop();
    serde_json::from_slice(&frame)
        .map(Some)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))
}

fn write_response(writer: &mut UnixStream, response: &ResponseEnvelope) -> io::Result<()> {
    let bytes = serde_json::to_vec(response)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider RPC response frame is too large",
        ));
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn prepare_database_root(path: &Path) -> Result<PathBuf, ProviderRpcServerError> {
    fs::create_dir_all(path).map_err(|source| ProviderRpcServerError::Io {
        operation: "create provider database root",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ProviderRpcServerError::Io {
        operation: "inspect provider database root",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProviderRpcServerError::InvalidDatabaseRoot(path.to_path_buf()));
    }
    path.canonicalize().map_err(|source| ProviderRpcServerError::Io {
        operation: "canonicalize provider database root",
        path: path.to_path_buf(),
        source,
    })
}

fn prepare_socket_path(path: &Path) -> Result<PathBuf, ProviderRpcServerError> {
    super::ProviderLocator::new(path, "0".repeat(64))
        .map_err(|_| ProviderRpcServerError::InvalidSocketPath(path.to_path_buf()))?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(ProviderRpcServerError::ExistingSocketPath(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ProviderRpcServerError::InvalidSocketPath(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| ProviderRpcServerError::Io {
        operation: "inspect provider socket parent",
        path: parent.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProviderRpcServerError::InvalidSocketPath(path.to_path_buf()));
    }
    Ok(path.to_path_buf())
}

fn protocol_provider_error() -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidRequest, false)
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
