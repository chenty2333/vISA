use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    os::fd::AsRawFd,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    str, thread,
    time::{Duration, Instant},
};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
};
use serde::Serialize;
use serde_json::{Value, json};
use visa_component_adapter::AdapterError;

use crate::{
    carrier::PreparedComponentBytes,
    error::{protocol_error, startup_error, terminal_error},
    protocol::{
        CommandReply, CommandRequest, Envelope, FieldPresence, HostCall, HostResponse,
        MAX_JSONL_MESSAGE_BYTES, PROTOCOL_VERSION, RuntimeReport, WireError,
    },
};

const POISONED_PROCESS_ERROR: &str =
    "wacogo sidecar was terminated after a previous adapter failure";
const CLOSED_PROCESS_ERROR: &str = "wacogo sidecar already completed protocol shutdown";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// A running sidecar that has loaded and checked the Component but has not
/// executed Component.Instantiate.
pub(crate) struct PreparedProcess {
    inner: Option<RpcProcess>,
    runtime: RuntimeReport,
}

/// A sidecar containing exactly one live wacogo Component instance.
pub(crate) struct WacogoProcess {
    inner: RpcProcess,
}

struct RpcProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_command_id: u64,
    next_hostcall_id: u64,
    poisoned: bool,
    closed: bool,
}

impl PreparedProcess {
    pub(crate) fn spawn(
        executable: &File,
        component: &PreparedComponentBytes,
    ) -> Result<Self, AdapterError> {
        let fd_path = format!("/proc/self/fd/{}", executable.as_raw_fd());
        if !std::path::Path::new(&fd_path).exists() {
            return Err(AdapterError::UnsupportedRuntimeFeature(
                "wacogo requires procfs /proc/self/fd execution on Linux".into(),
            ));
        }
        let mut command = Command::new(fd_path);
        command.env_clear();
        Self::spawn_command(command, Some(component), &component.digest_hex())
    }

    fn spawn_command(
        mut command: Command,
        component: Option<&PreparedComponentBytes>,
        expected_component_sha256: &str,
    ) -> Result<Self, AdapterError> {
        let production_component = component.is_some();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| sidecar_spawn_error(error, production_component))?;
        let Some(mut stdin) = child.stdin.take() else {
            kill_and_wait(&mut child);
            return Err(AdapterError::Engine("wacogo sidecar stdin was unavailable".into()));
        };
        let Some(stdout) = child.stdout.take() else {
            drop(stdin);
            kill_and_wait(&mut child);
            return Err(AdapterError::Engine("wacogo sidecar stdout was unavailable".into()));
        };
        if let Some(component) = component
            && let Err(error) = component.write_frame(&mut stdin)
        {
            kill_and_wait(&mut child);
            return Err(AdapterError::Engine(format!(
                "writing the owned wacogo Component carrier: {error}"
            )));
        }
        let mut inner = RpcProcess {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            next_command_id: 1,
            next_hostcall_id: 1,
            poisoned: false,
            closed: false,
        };
        let prepared = inner.read_envelope().map_err(|error| {
            AdapterError::Engine(format!("waiting for wacogo prepared handshake: {error}"))
        })?;
        if prepared.protocol() != PROTOCOL_VERSION {
            return Err(AdapterError::UnsupportedRuntimeFeature(
                "wacogo sidecar reported an incompatible protocol".into(),
            ));
        }
        let runtime = match prepared {
            Envelope::Prepared {
                component_sha256,
                guest_instantiated: false,
                live_resources: 0,
                runtime,
                ..
            } => {
                if component_sha256 != expected_component_sha256 {
                    return Err(AdapterError::InvalidComponent(format!(
                        "wacogo prepared Component digest mismatch: expected {expected_component_sha256}, found {component_sha256}"
                    )));
                }
                runtime.validate()?;
                runtime
            }
            Envelope::Prepared { guest_instantiated: true, .. } => {
                return Err(AdapterError::Engine(
                    "wacogo preflight instantiated guest code before returning Prepared".into(),
                ));
            }
            Envelope::Prepared { live_resources, .. } => {
                return Err(AdapterError::Engine(format!(
                    "wacogo preflight reported {live_resources} live resources"
                )));
            }
            Envelope::StartupError { ok: false, error, live_resources: 0, .. } => {
                return Err(startup_error(error));
            }
            Envelope::StartupError { ok: false, live_resources, .. } => {
                return Err(AdapterError::Engine(format!(
                    "wacogo preflight failed with {live_resources} live resources"
                )));
            }
            Envelope::StartupError { ok: true, .. } => {
                return Err(AdapterError::Engine(
                    "wacogo startup-error message was marked successful".into(),
                ));
            }
            other => {
                return Err(AdapterError::Engine(format!(
                    "unexpected wacogo startup message: {}",
                    other.kind()
                )));
            }
        };
        inner.require_idle_stdout("after the prepared handshake")?;
        Ok(Self { inner: Some(inner), runtime })
    }

    pub(crate) fn runtime(&self) -> &RuntimeReport {
        &self.runtime
    }

    pub(crate) fn instantiate(mut self) -> Result<WacogoProcess, AdapterError> {
        let mut inner = self.inner.take().expect("prepared process owns its runtime process");
        let reply = inner.call("instantiate", json!({}), |_| {
            Err(protocol_error(
                "hostcall-during-instantiation",
                "wacogo emitted a hostcall while instantiating the fixed Component",
            ))
        })?;
        if reply.live_resources != 0 {
            inner.terminate_after_adapter_failure();
            return Err(AdapterError::Instantiation(format!(
                "wacogo instantiated with {} live resources",
                reply.live_resources
            )));
        }
        unit_result(reply.result?, "instantiate")?;
        Ok(WacogoProcess { inner })
    }

    pub(crate) fn shutdown(mut self) -> Result<(), AdapterError> {
        let mut inner = self.inner.take().expect("prepared process owns its runtime process");
        // The production protocol permits shutdown before Component
        // instantiation. No Rust HostState exists at this boundary, so a
        // hostcall is a fatal protocol violation and triggers process cleanup.
        let reply = inner.shutdown(|_| {
            Err(protocol_error(
                "hostcall-during-prepared-shutdown",
                "prepared wacogo shutdown emitted a hostcall before Rust host state existed",
            ))
        })?;
        if reply.live_resources != 0 {
            return Err(AdapterError::GuestTrap(format!(
                "prepared wacogo shutdown retained {} live resources",
                reply.live_resources
            )));
        }
        unit_result(reply.result?, "shutdown")
    }

    #[cfg(test)]
    fn spawn_test_driver(
        command: Command,
        expected_component_sha256: &str,
    ) -> Result<Self, AdapterError> {
        Self::spawn_command(command, None, expected_component_sha256)
    }
}

impl Drop for PreparedProcess {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.terminate_after_adapter_failure();
        }
    }
}

impl WacogoProcess {
    pub(crate) fn call<F>(
        &mut self,
        op: &str,
        args: Value,
        host: F,
    ) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        self.inner.call(op, args, host)
    }

    pub(crate) fn terminate_after_adapter_failure(&mut self) {
        self.inner.terminate_after_adapter_failure();
    }

    pub(crate) fn shutdown<F>(&mut self, host: F) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        self.inner.shutdown(host)
    }
}

impl RpcProcess {
    fn call<F>(&mut self, op: &str, args: Value, host: F) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        if self.poisoned {
            return Err(AdapterError::GuestTrap(POISONED_PROCESS_ERROR.into()));
        }
        if self.closed {
            return Err(AdapterError::GuestTrap(CLOSED_PROCESS_ERROR.into()));
        }
        let result = self.call_inner(op, args, host, false);
        if result.is_err() {
            self.terminate_after_adapter_failure();
        }
        result
    }

    fn shutdown<F>(&mut self, host: F) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        if self.poisoned {
            return Err(AdapterError::GuestTrap(POISONED_PROCESS_ERROR.into()));
        }
        if self.closed {
            return Err(AdapterError::GuestTrap(CLOSED_PROCESS_ERROR.into()));
        }
        let reply = match self.call_inner("shutdown", json!({}), host, true) {
            Ok(reply) => reply,
            Err(error) => {
                self.terminate_after_adapter_failure();
                return Err(error);
            }
        };
        if let Err(error) = &reply.result {
            let error = error.clone();
            self.terminate_after_adapter_failure();
            return Err(error);
        }
        self.stdin.take();
        if let Err(error) = self.wait_for_clean_exit() {
            self.terminate_after_adapter_failure();
            return Err(error);
        }
        self.closed = true;
        Ok(reply)
    }

    fn call_inner<F>(
        &mut self,
        op: &str,
        args: Value,
        mut host: F,
        expect_exit: bool,
    ) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        self.require_idle_stdout("before sending a new wacogo command")?;
        if op.is_empty() {
            return Err(AdapterError::GuestTrap("wacogo command operation was empty".into()));
        }
        let id = take_next_id(&mut self.next_command_id, "wacogo command")?;
        self.write_json(&CommandRequest {
            message_type: "command",
            protocol: PROTOCOL_VERSION,
            id,
            op,
            args,
        })?;

        loop {
            let message = self.read_envelope()?;
            if message.protocol() != PROTOCOL_VERSION {
                return Err(AdapterError::GuestTrap(
                    "wacogo sidecar used an incompatible protocol".into(),
                ));
            }
            match message {
                Envelope::Hostcall { id: hostcall_id, command_id, resource, operation, .. } => {
                    require_id(command_id, "wacogo hostcall parent command")?;
                    if command_id != id {
                        return Err(AdapterError::GuestTrap(format!(
                            "wacogo hostcall parent command {command_id} did not match active command {id}"
                        )));
                    }
                    require_id(resource, "wacogo hostcall resource")?;
                    require_id(hostcall_id, "wacogo hostcall")?;
                    let expected_hostcall_id =
                        take_next_id(&mut self.next_hostcall_id, "wacogo hostcall")?;
                    if hostcall_id != expected_hostcall_id {
                        return Err(AdapterError::GuestTrap(format!(
                            "wacogo hostcall id {hostcall_id} did not match expected {expected_hostcall_id}"
                        )));
                    }
                    let call = HostCall { id: hostcall_id, resource, operation };
                    let call_id = call.id;
                    let (ok, result, error) = match host(call) {
                        Ok(result) => (true, Some(result), None),
                        Err(error) if error.domain == "protocol" => {
                            return Err(fatal_host_protocol_error(error));
                        }
                        Err(error) => (false, None, Some(error)),
                    };
                    self.write_json(&HostResponse {
                        message_type: "hostcall-response",
                        protocol: PROTOCOL_VERSION,
                        id: call_id,
                        ok,
                        result,
                        error,
                    })?;
                }
                Envelope::Response {
                    id: response_id, ok, result, error, live_resources, ..
                } => {
                    require_id(response_id, "wacogo response")?;
                    if response_id != id {
                        return Err(AdapterError::GuestTrap(format!(
                            "wacogo response id {response_id} did not match command {id}"
                        )));
                    }
                    let reply = match (ok, result, error) {
                        (true, FieldPresence::Present(result), FieldPresence::Missing) => {
                            CommandReply { result: Ok(result), live_resources }
                        }
                        (false, FieldPresence::Missing, FieldPresence::Present(error)) => {
                            CommandReply { result: Err(terminal_error(error, op)?), live_resources }
                        }
                        (true, _, _) => Err(AdapterError::GuestTrap(
                            "successful wacogo response must contain result and omit error".into(),
                        ))?,
                        (false, _, _) => Err(AdapterError::GuestTrap(
                            "failed wacogo response must omit result and contain error".into(),
                        ))?,
                    };
                    self.require_settled(id)?;
                    if !expect_exit {
                        self.require_idle_stdout("after the terminal wacogo response settled")?;
                    }
                    return Ok(reply);
                }
                other => {
                    return Err(AdapterError::GuestTrap(format!(
                        "unexpected wacogo protocol message: {}",
                        other.kind()
                    )));
                }
            }
        }
    }

    fn require_settled(&mut self, command_id: u64) -> Result<(), AdapterError> {
        let message = self.read_envelope().map_err(|error| {
            AdapterError::GuestTrap(format!(
                "reading wacogo settled boundary after terminal response: {error}"
            ))
        })?;
        if message.protocol() != PROTOCOL_VERSION {
            return Err(AdapterError::GuestTrap(
                "wacogo sidecar used an incompatible protocol after terminal response".into(),
            ));
        }
        match message {
            Envelope::Settled { id, .. } => {
                require_id(id, "wacogo settled command")?;
                if id != command_id {
                    return Err(AdapterError::GuestTrap(format!(
                        "wacogo settled command {id} did not match terminal response {command_id}"
                    )));
                }
                Ok(())
            }
            other => Err(AdapterError::GuestTrap(format!(
                "expected wacogo settled boundary, received {}",
                other.kind()
            ))),
        }
    }

    fn terminate_after_adapter_failure(&mut self) {
        if self.closed {
            return;
        }
        self.poisoned = true;
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.closed = true;
    }

    fn wait_for_clean_exit(&mut self) -> Result<(), AdapterError> {
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(AdapterError::GuestTrap(format!(
                        "wacogo sidecar exited unsuccessfully after shutdown: {status}"
                    )));
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) => {
                    return Err(AdapterError::GuestTrap(
                        "wacogo sidecar did not exit after shutdown".into(),
                    ));
                }
                Err(error) => {
                    return Err(AdapterError::GuestTrap(format!(
                        "waiting for wacogo sidecar shutdown: {error}"
                    )));
                }
            }
        }
    }

    fn require_idle_stdout(&mut self, boundary: &str) -> Result<(), AdapterError> {
        if !self.stdout.buffer().is_empty() {
            return Err(AdapterError::GuestTrap(format!(
                "wacogo protocol stream contained an unsolicited buffered frame {boundary}"
            )));
        }
        if let Some(status) = self.child.try_wait().map_err(|error| {
            AdapterError::GuestTrap(format!("checking wacogo process status {boundary}: {error}"))
        })? {
            return Err(AdapterError::GuestTrap(format!(
                "wacogo protocol stream closed with {status} {boundary}"
            )));
        }
        let events = {
            let mut descriptors = [PollFd::new(self.stdout.get_ref(), PollFlags::IN)];
            loop {
                match poll(&mut descriptors, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })) {
                    Ok(_) => break descriptors[0].revents(),
                    Err(Errno::INTR) => continue,
                    Err(error) => {
                        return Err(AdapterError::GuestTrap(format!(
                            "polling wacogo protocol stream {boundary}: {error}"
                        )));
                    }
                }
            }
        };
        if !events.is_empty() {
            return Err(AdapterError::GuestTrap(format!(
                "wacogo protocol stream was readable or closed {boundary} ({events:?})"
            )));
        }
        Ok(())
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> Result<(), AdapterError> {
        let bytes = encode_jsonl(value)?;
        self.stdin
            .as_mut()
            .ok_or_else(|| AdapterError::GuestTrap("wacogo sidecar stdin was closed".into()))?
            .write_all(&bytes)
            .and_then(|()| self.stdin.as_mut().expect("checked").flush())
            .map_err(|error| AdapterError::GuestTrap(format!("writing wacogo request: {error}")))
    }

    fn read_envelope(&mut self) -> Result<Envelope, AdapterError> {
        let line = read_bounded_jsonl(&mut self.stdout).map_err(|error| {
            AdapterError::GuestTrap(format!("reading wacogo response: {error}"))
        })?;
        let Some(line) = line else {
            let status = self.child.try_wait().ok().flatten();
            return Err(AdapterError::GuestTrap(format!(
                "wacogo protocol stream closed{}",
                status.map_or_else(String::new, |status| format!(" with {status}"))
            )));
        };
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        let payload = str::from_utf8(payload).map_err(|error| {
            AdapterError::GuestTrap(format!("decoding wacogo response as UTF-8: {error}"))
        })?;
        serde_json::from_str(payload)
            .map_err(|error| AdapterError::GuestTrap(format!("decoding wacogo response: {error}")))
    }
}

impl Drop for RpcProcess {
    fn drop(&mut self) {
        self.terminate_after_adapter_failure();
    }
}

fn unit_result(value: Value, operation: &str) -> Result<(), AdapterError> {
    if value.is_null() {
        Ok(())
    } else {
        Err(AdapterError::GuestTrap(format!(
            "wacogo returned a non-null result for unit operation {operation}"
        )))
    }
}

fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn sidecar_spawn_error(error: io::Error, production_component: bool) -> AdapterError {
    let unsupported_host = production_component
        && (matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound)
            || error.raw_os_error() == Some(Errno::NOEXEC.raw_os_error()));
    if unsupported_host {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "executing the sealed wacogo sidecar through /proc/self/fd is unsupported: {error}"
        ))
    } else {
        AdapterError::Engine(format!("starting wacogo sidecar: {error}"))
    }
}

fn encode_jsonl<T: Serialize>(value: &T) -> Result<Vec<u8>, AdapterError> {
    let mut output = BoundedJsonBuffer::new(MAX_JSONL_MESSAGE_BYTES - 1);
    serde_json::to_writer(&mut output, value)
        .map_err(|error| AdapterError::GuestTrap(format!("encoding wacogo request: {error}")))?;
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedJsonBuffer {
    fn new(limit: usize) -> Self {
        Self { bytes: Vec::with_capacity(4096), limit }
    }
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "wacogo JSONL length overflow")
        })?;
        if next > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("wacogo JSONL message exceeds {MAX_JSONL_MESSAGE_BYTES} bytes"),
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_bounded_jsonl(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(4096);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "wacogo JSONL message ended without a newline",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        let next = line.len().checked_add(take).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "wacogo JSONL length overflow")
        })?;
        if next > MAX_JSONL_MESSAGE_BYTES || (newline.is_none() && next >= MAX_JSONL_MESSAGE_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("wacogo JSONL message exceeds {MAX_JSONL_MESSAGE_BYTES} bytes"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn require_id(id: u64, label: &str) -> Result<(), AdapterError> {
    if id == 0 {
        return Err(AdapterError::GuestTrap(format!("{label} id must be positive")));
    }
    Ok(())
}

fn take_next_id(next: &mut u64, label: &str) -> Result<u64, AdapterError> {
    let id = *next;
    require_id(id, label)?;
    *next = id
        .checked_add(1)
        .ok_or_else(|| AdapterError::GuestTrap(format!("{label} id exhausted")))?;
    Ok(id)
}

fn fatal_host_protocol_error(error: WireError) -> AdapterError {
    let detail = error.detail.map_or_else(String::new, |detail| format!(": {detail}"));
    AdapterError::GuestTrap(format!("wacogo hostcall protocol violation: {}{detail}", error.kind))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;

    use super::*;
    use crate::{
        identity::WacogoProvenance,
        protocol::{HostCallOperation, ResourceKind},
    };

    const COMPONENT_SHA: &str = "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b";
    static NEXT_PID_FILE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn prepared_process_instantiates_and_shutdowns_on_exact_boundaries() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
case "$instantiate" in
  *'"type":"command"'*'"id":1'*'"op":"instantiate"'*) ;;
  *) exit 90 ;;
esac
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r shutdown
case "$shutdown" in
  *'"type":"command"'*'"id":2'*'"op":"shutdown"'*) ;;
  *) exit 91 ;;
esac
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":2}'
"#,
        );
        prepared.runtime().validate().unwrap();
        let mut live = prepared.instantiate().unwrap();
        let reply = live.shutdown(|_| panic!("shutdown emitted no hostcalls")).unwrap();
        assert!(reply.result.unwrap().is_null());
        assert_eq!(reply.live_resources, 0);
        assert!(live.inner.closed);
        assert!(!live.inner.poisoned);
        assert!(live.inner.child.try_wait().unwrap().is_some_and(|status| status.success()));
        let after_shutdown = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert!(
            matches!(after_shutdown, AdapterError::GuestTrap(detail) if detail == CLOSED_PROCESS_ERROR)
        );
    }

    #[test]
    fn startup_protocol_or_runtime_identity_mismatch_fails_closed_without_fallback() {
        let mut wrong_protocol = prepared_handshake();
        wrong_protocol["protocol"] = json!(PROTOCOL_VERSION + 1);
        let protocol_error = fake_process_error(wrong_protocol, "IFS= read -r unexpected");
        assert_eq!(
            protocol_error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );

        let mut wrong_identity = prepared_handshake();
        wrong_identity["runtime"]["engine"] = json!("wasmtime");
        let identity_error = fake_process_error(wrong_identity, "IFS= read -r unexpected");
        assert_eq!(
            identity_error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
    }

    #[test]
    fn startup_eof_is_an_engine_failure_and_the_child_is_reaped() {
        let pid_file = test_pid_file("startup-eof");
        let script = format!(
            "printf '%s' \"$$\" > '{}'\nexit 41",
            pid_file.to_string_lossy().replace('\'', "'\\''")
        );
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        let error = match PreparedProcess::spawn_test_driver(command, COMPONENT_SHA) {
            Ok(_) => panic!("startup EOF unexpectedly reached Prepared"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Engine);
        let pid = read_test_pid(&pid_file);
        let _ = fs::remove_file(&pid_file);
        assert_pid_reaped(pid);
    }

    #[test]
    fn explicit_prepared_shutdown_uses_the_pre_instantiation_protocol_boundary() {
        let marker = test_pid_file("prepared-clean-shutdown");
        let body = format!(
            r#"
IFS= read -r shutdown
case "$shutdown" in
  *'"type":"command"'*'"id":1'*'"op":"shutdown"'*) ;;
  *) exit 95 ;;
esac
printf '%s' clean > '{}'
printf '%s\n' '{{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}}'
printf '%s\n' '{{"type":"settled","protocol":1,"id":1}}'
"#,
            marker.to_string_lossy().replace('\'', "'\\''")
        );
        let prepared = fake_process(&body);
        let pid = prepared.inner.as_ref().unwrap().child.id();
        prepared.shutdown().unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap(), "clean");
        let _ = fs::remove_file(marker);
        assert_pid_reaped(pid);
    }

    #[test]
    fn malformed_explicit_prepared_shutdown_falls_back_to_kill_and_wait() {
        let marker = test_pid_file("prepared-failed-shutdown");
        let body = format!(
            r#"
IFS= read -r shutdown
printf '%s' attempted > '{}'
printf '%s\n' '{{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}}'
printf '%s\n' '{{"type":"settled","protocol":1,"id":99}}'
IFS= read -r never
"#,
            marker.to_string_lossy().replace('\'', "'\\''")
        );
        let prepared = fake_process(&body);
        let pid = prepared.inner.as_ref().unwrap().child.id();
        let error = prepared.shutdown().unwrap_err();
        assert!(matches!(error, AdapterError::GuestTrap(_)));
        assert_eq!(fs::read_to_string(&marker).unwrap(), "attempted");
        let _ = fs::remove_file(marker);
        assert_pid_reaped(pid);
    }

    #[test]
    fn ordinary_prepared_drop_is_only_the_kill_and_wait_failure_fallback() {
        let prepared = fake_process("IFS= read -r unexpected");
        let pid = prepared.inner.as_ref().unwrap().child.id();
        drop(prepared);
        assert_pid_reaped(pid);
    }

    #[test]
    fn instantiate_eof_returns_a_failure_and_reaps_the_consumed_prepared_process() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
exit 42
"#,
        );
        let pid = prepared.inner.as_ref().unwrap().child.id();
        let error = match prepared.instantiate() {
            Ok(_) => panic!("instantiate EOF unexpectedly produced a live process"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert_pid_reaped(pid);
    }

    #[test]
    fn sidecar_crash_during_a_command_poisoned_and_reaped_the_process() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r status
exit 37
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let error = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert_poisoned_and_reaped(&mut live);
        let second = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert!(
            matches!(second, AdapterError::GuestTrap(detail) if detail == POISONED_PROCESS_ERROR)
        );
    }

    #[test]
    fn wrong_settled_boundary_poisoned_and_reaped_the_process() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r status
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":99}'
IFS= read -r never
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let error = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert!(
            matches!(error, AdapterError::GuestTrap(detail) if detail.contains("settled command 99"))
        );
        assert_poisoned_and_reaped(&mut live);
    }

    #[test]
    fn fatal_hostcall_protocol_error_sends_no_response_and_reaps_the_sidecar() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r status
printf '%s\n' '{"type":"hostcall","protocol":1,"id":1,"commandId":2,"resource":7,"op":"kv.read","args":{"key":"work"}}'
if IFS= read -r forbidden_response; then
  exit 92
fi
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let error = live
            .call("status", json!({}), |_| {
                Err(protocol_error("unknown-resource", "injected host table failure"))
            })
            .unwrap_err();
        assert!(matches!(
            error,
            AdapterError::GuestTrap(detail)
                if detail.contains("wacogo hostcall protocol violation: unknown-resource")
        ));
        assert_poisoned_and_reaped(&mut live);
    }

    #[test]
    fn shutdown_routes_resource_disposal_hostcalls_then_observes_a_clean_exit() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r shutdown
printf '%s\n' '{"type":"hostcall","protocol":1,"id":1,"commandId":2,"resource":7,"op":"resource.dispose","args":{"kind":"kv"}}'
IFS= read -r kv_response
case "$kv_response" in
  *'"type":"hostcall-response"'*'"id":1'*'"ok":true'*'"result":null'*) ;;
  *) exit 93 ;;
esac
printf '%s\n' '{"type":"hostcall","protocol":1,"id":2,"commandId":2,"resource":8,"op":"resource.dispose","args":{"kind":"timer"}}'
IFS= read -r timer_response
case "$timer_response" in
  *'"type":"hostcall-response"'*'"id":2'*'"ok":true'*'"result":null'*) ;;
  *) exit 94 ;;
esac
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":2}'
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let mut disposed = Vec::new();
        let reply = live
            .shutdown(|call| {
                let HostCallOperation::ResourceDispose(args) = call.operation else {
                    panic!("shutdown emitted a non-disposal hostcall")
                };
                disposed.push((call.resource, args.kind));
                Ok(Value::Null)
            })
            .unwrap();
        assert_eq!(disposed, [(7, ResourceKind::Kv), (8, ResourceKind::Timer)]);
        assert_eq!(reply.live_resources, 0);
        assert!(reply.result.unwrap().is_null());
        assert!(live.inner.closed);
        assert!(!live.inner.poisoned);
        assert!(live.inner.child.try_wait().unwrap().is_some_and(|status| status.success()));
    }

    #[test]
    fn shutdown_failure_poisoned_and_reaped_instead_of_masquerading_as_clean_exit() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r shutdown
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":false,"error":{"domain":"trap","kind":"shutdown-cleanup","detail":"injected cleanup failure"},"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":2}'
IFS= read -r never
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let error = live.shutdown(|_| unreachable!()).unwrap_err();
        assert!(
            matches!(error, AdapterError::GuestTrap(detail) if detail.contains("shutdown-cleanup"))
        );
        assert_poisoned_and_reaped(&mut live);
    }

    #[test]
    fn hostcalls_must_match_the_active_command_and_are_replied_to_strictly() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r status
printf '%s\n' '{"type":"hostcall","protocol":1,"id":1,"commandId":2,"resource":7,"op":"kv.read","args":{"key":"work"}}'
IFS= read -r host_response
case "$host_response" in
  *'"type":"hostcall-response"'*'"id":1'*'"ok":true'*) ;;
  *) exit 91 ;;
esac
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":2}'
IFS= read -r shutdown
printf '%s\n' '{"type":"response","protocol":1,"id":3,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":3}'
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let reply = live
            .call("status", json!({}), |call| {
                assert_eq!(call.id, 1);
                assert_eq!(call.resource, 7);
                Ok(Value::Null)
            })
            .unwrap();
        assert!(reply.result.unwrap().is_null());
        live.shutdown(|_| unreachable!()).unwrap();
    }

    #[test]
    fn malformed_terminal_response_poisoned_the_process() {
        let prepared = fake_process(
            r#"
IFS= read -r instantiate
printf '%s\n' '{"type":"response","protocol":1,"id":1,"ok":true,"result":null,"liveResources":0}'
printf '%s\n' '{"type":"settled","protocol":1,"id":1}'
IFS= read -r status
printf '%s\n' '{"type":"response","protocol":1,"id":2,"ok":true,"liveResources":0}'
IFS= read -r never
"#,
        );
        let mut live = prepared.instantiate().unwrap();
        let error = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        let second = live.call("status", json!({}), |_| unreachable!()).unwrap_err();
        assert!(
            matches!(second, AdapterError::GuestTrap(detail) if detail == POISONED_PROCESS_ERROR)
        );
    }

    #[test]
    fn production_spawn_classifies_host_execution_rejections_without_changing_test_drivers() {
        for error in [
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::from(io::ErrorKind::NotFound),
            io::Error::from_raw_os_error(Errno::NOEXEC.raw_os_error()),
        ] {
            assert_eq!(
                sidecar_spawn_error(error, true).kind(),
                visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
            );
        }
        assert_eq!(
            sidecar_spawn_error(io::Error::from(io::ErrorKind::PermissionDenied), false).kind(),
            visa_component_adapter::AdapterFailureKind::Engine
        );
        assert_eq!(
            sidecar_spawn_error(io::Error::from(io::ErrorKind::WouldBlock), true).kind(),
            visa_component_adapter::AdapterFailureKind::Engine
        );
    }

    fn prepared_handshake() -> Value {
        serde_json::json!({
            "type": "prepared",
            "protocol": PROTOCOL_VERSION,
            "componentSha256": COMPONENT_SHA,
            "guestInstantiated": false,
            "liveResources": 0,
            "runtime": RuntimeReport::expected(),
        })
    }

    fn fake_process(body: &str) -> PreparedProcess {
        fake_process_result(prepared_handshake(), body).unwrap()
    }

    fn fake_process_result(prepared: Value, body: &str) -> Result<PreparedProcess, AdapterError> {
        let script =
            format!("printf '%s\\n' '{}'\n{body}", prepared.to_string().replace('\'', "'\\''"));
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        PreparedProcess::spawn_test_driver(command, COMPONENT_SHA)
    }

    fn fake_process_error(prepared: Value, body: &str) -> AdapterError {
        match fake_process_result(prepared, body) {
            Ok(_) => panic!("an incompatible test sidecar unexpectedly reached Prepared"),
            Err(error) => error,
        }
    }

    fn assert_poisoned_and_reaped(live: &mut WacogoProcess) {
        assert!(live.inner.poisoned);
        assert!(live.inner.closed);
        assert!(live.inner.stdin.is_none());
        assert!(live.inner.child.try_wait().unwrap().is_some());
    }

    fn test_pid_file(label: &str) -> std::path::PathBuf {
        let sequence = NEXT_PID_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("visa-wacogo-{label}-{}-{sequence}.pid", std::process::id()))
    }

    fn read_test_pid(path: &std::path::Path) -> u32 {
        fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("reading test sidecar pid {}: {error}", path.display()))
            .parse()
            .unwrap_or_else(|error| panic!("decoding test sidecar pid {}: {error}", path.display()))
    }

    fn assert_pid_reaped(pid: u32) {
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "sidecar process {pid} still exists after the failure returned"
        );
    }

    #[allow(dead_code)]
    fn provenance_type_is_runtime_local(_: WacogoProvenance) {}
}
