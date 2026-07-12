use std::{
    io::{self, BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Stdio},
    str,
};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
};
use serde::Serialize;
use serde_json::Value;
use visa_component_adapter::AdapterError;

use crate::{
    carrier::PreparedExecutionGraph,
    error::guest_error,
    node::locked_node_command,
    protocol::{
        CommandReply, CommandRequest, Envelope, FieldPresence, HostCall, HostResponse,
        MAX_JS_SAFE_INTEGER, MAX_JSONL_MESSAGE_BYTES, PROTOCOL_VERSION, WireError,
    },
};

pub(crate) struct NodeProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_command_id: u64,
    next_hostcall_id: u64,
    poisoned: bool,
}

const POISONED_PROCESS_ERROR: &str = "Node process was terminated after a previous adapter failure";

impl NodeProcess {
    pub(crate) fn spawn(node: &Path, graph: &PreparedExecutionGraph) -> Result<Self, AdapterError> {
        Self::spawn_with_expected_digest(node, graph, graph.generated_digest_hex())
    }

    fn spawn_with_expected_digest(
        node: &Path,
        graph: &PreparedExecutionGraph,
        expected_digest: String,
    ) -> Result<Self, AdapterError> {
        let mut command = locked_node_command(node);
        command
            .args(["--input-type=module", "--eval", include_str!("driver.mjs"), "--"])
            .arg(expected_digest);
        Self::spawn_command(command, Some(graph))
    }

    #[cfg(test)]
    fn spawn_test_driver(
        node: &Path,
        driver: &Path,
        entrypoint: &Path,
        artifact_directory: &Path,
    ) -> Result<Self, AdapterError> {
        let mut command = locked_node_command(node);
        command.arg(driver).arg(entrypoint).current_dir(artifact_directory);
        Self::spawn_command(command, None)
    }

    fn spawn_command(
        mut command: std::process::Command,
        graph: Option<&PreparedExecutionGraph>,
    ) -> Result<Self, AdapterError> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| AdapterError::Instantiation(format!("starting Node: {error}")))?;
        let Some(mut stdin) = child.stdin.take() else {
            kill_and_wait(&mut child);
            return Err(AdapterError::Instantiation("Node stdin was not available".into()));
        };
        let Some(stdout) = child.stdout.take() else {
            drop(stdin);
            kill_and_wait(&mut child);
            return Err(AdapterError::Instantiation("Node stdout was not available".into()));
        };
        if let Some(graph) = graph
            && let Err(error) = graph.write_frame(&mut stdin)
        {
            kill_and_wait(&mut child);
            return Err(AdapterError::Instantiation(format!(
                "writing the path-free Node startup carrier: {error}"
            )));
        }
        let mut process = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_command_id: 1,
            next_hostcall_id: 1,
            poisoned: false,
        };
        let ready = process.read_envelope().map_err(|error| {
            AdapterError::Instantiation(format!("waiting for Node driver: {error}"))
        })?;
        if ready.protocol() != PROTOCOL_VERSION {
            return Err(AdapterError::Instantiation(
                "Node driver reported an incompatible protocol".into(),
            ));
        }
        match ready {
            Envelope::Ready { node_version, v8_version, live_resources: 0, .. } => {
                require_live_runtime_identity(
                    Some(&node_version),
                    Some(&v8_version),
                    crate::preflight::NODE_VERSION,
                    crate::preflight::V8_VERSION,
                )?;
            }
            Envelope::Ready { live_resources, .. } => {
                return Err(AdapterError::Instantiation(format!(
                    "Node driver reported {live_resources} live resources before startup"
                )));
            }
            Envelope::StartupError { ok: false, error, live_resources, .. } => {
                let error = guest_error(error).map_err(|error| {
                    AdapterError::Instantiation(format!(
                        "Node startup-error message had an invalid error shape: {error}"
                    ))
                })?;
                return Err(AdapterError::Instantiation(format!(
                    "{error} (live resources: {live_resources})"
                )));
            }
            Envelope::StartupError { ok: true, .. } => {
                return Err(AdapterError::Instantiation(
                    "Node startup-error message was marked successful".into(),
                ));
            }
            other => {
                return Err(AdapterError::Instantiation(format!(
                    "unexpected Node startup message: {}",
                    other.kind()
                )));
            }
        }
        Ok(process)
    }

    pub(crate) fn call<F>(
        &mut self,
        op: &str,
        args: Value,
        host: F,
    ) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        if self.poisoned {
            return Err(AdapterError::GuestTrap(POISONED_PROCESS_ERROR.into()));
        }

        let result = self.call_inner(op, args, host);
        if result.is_err() {
            self.terminate_after_adapter_failure();
        }
        result
    }

    fn call_inner<F>(
        &mut self,
        op: &str,
        args: Value,
        mut host: F,
    ) -> Result<CommandReply, AdapterError>
    where
        F: FnMut(HostCall) -> Result<Value, WireError>,
    {
        self.require_idle_stdout("before sending a new Node command")?;
        if op.is_empty() {
            return Err(AdapterError::GuestTrap("Node command operation was empty".into()));
        }
        let id = take_next_safe_id(&mut self.next_command_id, "Node command")?;
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
                    "Node driver used an incompatible protocol".into(),
                ));
            }
            match message {
                Envelope::Hostcall { id: hostcall_id, command_id, resource, operation, .. } => {
                    require_safe_id(command_id, "Node hostcall parent command")?;
                    if command_id != id {
                        return Err(AdapterError::GuestTrap(format!(
                            "Node hostcall parent command {command_id} did not match active command {id}"
                        )));
                    }
                    require_safe_id(resource, "Node hostcall resource")?;
                    require_safe_id(hostcall_id, "Node hostcall")?;
                    let expected_hostcall_id =
                        take_next_safe_id(&mut self.next_hostcall_id, "Node hostcall")?;
                    if hostcall_id != expected_hostcall_id {
                        return Err(AdapterError::GuestTrap(format!(
                            "Node hostcall id {hostcall_id} did not match expected {expected_hostcall_id}"
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
                    require_safe_id(response_id, "Node response")?;
                    if response_id != id {
                        return Err(AdapterError::GuestTrap(format!(
                            "Node response id did not match command {id}"
                        )));
                    }
                    let reply = match (ok, result, error) {
                        (true, FieldPresence::Present(result), FieldPresence::Missing) => {
                            CommandReply { result: Ok(result), live_resources }
                        }
                        (false, FieldPresence::Missing, FieldPresence::Present(error)) => {
                            CommandReply { result: Err(guest_error(error)?), live_resources }
                        }
                        (true, _, _) => Err(AdapterError::GuestTrap(
                            "successful Node response must contain result and omit error".into(),
                        ))?,
                        (false, _, _) => Err(AdapterError::GuestTrap(
                            "failed Node response must omit result and contain error".into(),
                        ))?,
                    };
                    self.require_settled(id)?;
                    self.require_idle_stdout("after the terminal Node response settled")?;
                    return Ok(reply);
                }
                other => {
                    return Err(AdapterError::GuestTrap(format!(
                        "unexpected Node protocol message: {}",
                        other.kind()
                    )));
                }
            }
        }
    }

    fn require_settled(&mut self, command_id: u64) -> Result<(), AdapterError> {
        let message = self.read_envelope().map_err(|error| {
            AdapterError::GuestTrap(format!(
                "reading Node settled boundary after the terminal Node response: {error}"
            ))
        })?;
        if message.protocol() != PROTOCOL_VERSION {
            return Err(AdapterError::GuestTrap(
                "Node driver used an incompatible protocol after the terminal Node response".into(),
            ));
        }
        match message {
            Envelope::Settled { id, .. } => {
                require_safe_id(id, "Node settled command")?;
                if id != command_id {
                    return Err(AdapterError::GuestTrap(format!(
                        "Node settled command {id} did not match terminal response {command_id}"
                    )));
                }
                Ok(())
            }
            other => Err(AdapterError::GuestTrap(format!(
                "expected Node settled boundary after the terminal Node response, received {}",
                other.kind()
            ))),
        }
    }

    pub(crate) fn terminate_after_adapter_failure(&mut self) {
        if self.poisoned {
            return;
        }
        self.poisoned = true;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn require_idle_stdout(&mut self, boundary: &str) -> Result<(), AdapterError> {
        if !self.stdout.buffer().is_empty() {
            return Err(AdapterError::GuestTrap(format!(
                "Node protocol stream contained an unsolicited buffered frame {boundary}"
            )));
        }

        if let Some(status) = self.child.try_wait().map_err(|error| {
            AdapterError::GuestTrap(format!("checking Node process status {boundary}: {error}"))
        })? {
            return Err(AdapterError::GuestTrap(format!(
                "Node protocol stream closed with {status} {boundary}"
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
                            "polling Node protocol stream {boundary}: {error}"
                        )));
                    }
                }
            }
        };
        if !events.is_empty() {
            return Err(AdapterError::GuestTrap(format!(
                "Node protocol stream was readable or closed {boundary} ({events:?})"
            )));
        }

        Ok(())
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> Result<(), AdapterError> {
        let bytes = encode_jsonl(value)?;
        self.stdin
            .write_all(&bytes)
            .and_then(|()| self.stdin.flush())
            .map_err(|error| AdapterError::GuestTrap(format!("writing Node request: {error}")))
    }

    fn read_envelope(&mut self) -> Result<Envelope, AdapterError> {
        let line = read_bounded_jsonl(&mut self.stdout)
            .map_err(|error| AdapterError::GuestTrap(format!("reading Node response: {error}")))?;
        let Some(line) = line else {
            let status = self.child.try_wait().ok().flatten();
            return Err(AdapterError::GuestTrap(format!(
                "Node protocol stream closed{}",
                status.map_or_else(String::new, |status| format!(" with {status}"))
            )));
        };
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        let payload = str::from_utf8(payload).map_err(|error| {
            AdapterError::GuestTrap(format!("decoding Node response as UTF-8: {error}"))
        })?;
        serde_json::from_str(payload)
            .map_err(|error| AdapterError::GuestTrap(format!("decoding Node response: {error}")))
    }
}

fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn encode_jsonl<T: Serialize>(value: &T) -> Result<Vec<u8>, AdapterError> {
    let mut output = BoundedJsonBuffer::new(MAX_JSONL_MESSAGE_BYTES - 1);
    serde_json::to_writer(&mut output, value)
        .map_err(|error| AdapterError::GuestTrap(format!("encoding Node request: {error}")))?;
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
            io::Error::new(io::ErrorKind::InvalidData, "Node JSONL message length overflow")
        })?;
        if next > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Node JSONL message exceeds {MAX_JSONL_MESSAGE_BYTES} bytes"),
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
                "Node JSONL message ended without a newline",
            ));
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        let next = line.len().checked_add(take).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Node JSONL message length overflow")
        })?;
        if next > MAX_JSONL_MESSAGE_BYTES || (newline.is_none() && next >= MAX_JSONL_MESSAGE_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Node JSONL message exceeds {MAX_JSONL_MESSAGE_BYTES} bytes"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn require_live_runtime_identity(
    observed_node: Option<&str>,
    observed_v8: Option<&str>,
    expected_node: &str,
    expected_v8: &str,
) -> Result<(), AdapterError> {
    if observed_node == Some(expected_node) && observed_v8 == Some(expected_v8) {
        return Ok(());
    }
    Err(AdapterError::Instantiation(format!(
        "live Node driver identity mismatch: expected Node {expected_node} / V8 {expected_v8}, found Node {} / V8 {}",
        observed_node.unwrap_or("<missing>"),
        observed_v8.unwrap_or("<missing>"),
    )))
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        self.terminate_after_adapter_failure();
    }
}

fn require_safe_id(id: u64, label: &str) -> Result<(), AdapterError> {
    if id == 0 || id > MAX_JS_SAFE_INTEGER {
        return Err(AdapterError::GuestTrap(format!(
            "{label} id {id} was not a positive JavaScript-safe integer"
        )));
    }
    Ok(())
}

fn take_next_safe_id(next: &mut u64, label: &str) -> Result<u64, AdapterError> {
    let id = *next;
    require_safe_id(id, label)?;
    *next = id
        .checked_add(1)
        .ok_or_else(|| AdapterError::GuestTrap(format!("{label} id exhausted")))?;
    Ok(id)
}

fn fatal_host_protocol_error(error: WireError) -> AdapterError {
    let detail = error.detail.map_or_else(String::new, |detail| format!(": {detail}"));
    AdapterError::GuestTrap(format!("Node hostcall protocol violation: {}{detail}", error.kind))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use serde_json::json;

    use super::*;
    use crate::carrier::PreparedExecutionGraph;

    const READY_AND_WAIT: &str = r#"
import { closeSync, readSync, writeSync } from 'node:fs';
function send(message) {
  const bytes = Buffer.from(`${JSON.stringify(message)}\n`, 'utf8');
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(1, bytes, offset, bytes.length - offset);
}
function sendRaw(message) {
  const bytes = Buffer.from(`${message}\n`, 'utf8');
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(1, bytes, offset, bytes.length - offset);
}
function settle(id) {
  send({ type: 'settled', protocol: 3, id });
}
send({
  type: 'ready', protocol: 3,
  nodeVersion: process.versions.node,
  v8Version: process.versions.v8,
  liveResources: 0,
});
const command = Buffer.alloc(4096);
readSync(0, command, 0, command.length, null);
"#;

    #[test]
    fn live_driver_identity_requires_both_exact_versions() {
        require_live_runtime_identity(
            Some(crate::preflight::NODE_VERSION),
            Some(crate::preflight::V8_VERSION),
            crate::preflight::NODE_VERSION,
            crate::preflight::V8_VERSION,
        )
        .expect("the pinned live identity is accepted");

        for (node, v8) in [
            (None, Some(crate::preflight::V8_VERSION)),
            (Some(crate::preflight::NODE_VERSION), None),
            (Some("0.0.0"), Some(crate::preflight::V8_VERSION)),
            (Some(crate::preflight::NODE_VERSION), Some("wrong-v8")),
        ] {
            let error = require_live_runtime_identity(
                node,
                v8,
                crate::preflight::NODE_VERSION,
                crate::preflight::V8_VERSION,
            )
            .expect_err("missing or mismatched live identity must be rejected");
            assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Instantiation);
        }
    }

    #[test]
    fn real_node_process_rejects_incomplete_wrong_and_unknown_ready_messages() {
        for (name, message) in [
            (
                "missing-protocol",
                "{\"type\":\"ready\",\"nodeVersion\":\"24.15.0\",\"v8Version\":\"13.6.233.17-node.48\",\"liveResources\":0}\n",
            ),
            (
                "missing-node-version",
                "{\"type\":\"ready\",\"protocol\":3,\"v8Version\":\"13.6.233.17-node.48\",\"liveResources\":0}\n",
            ),
            (
                "wrong-protocol",
                "{\"type\":\"ready\",\"protocol\":999,\"nodeVersion\":\"24.15.0\",\"v8Version\":\"13.6.233.17-node.48\",\"liveResources\":0}\n",
            ),
            (
                "wrong-runtime-version",
                "{\"type\":\"ready\",\"protocol\":3,\"nodeVersion\":\"0.0.0\",\"v8Version\":\"wrong\",\"liveResources\":0}\n",
            ),
            (
                "unknown-ready-field",
                "{\"type\":\"ready\",\"protocol\":3,\"nodeVersion\":\"24.15.0\",\"v8Version\":\"13.6.233.17-node.48\",\"liveResources\":0,\"fallback\":true}\n",
            ),
            ("wrong-startup-type", "{\"type\":\"not-ready\",\"protocol\":3}\n"),
            (
                "invalid-startup-error-shape",
                "{\"type\":\"startup-error\",\"protocol\":3,\"ok\":false,\"error\":{\"domain\":\"unknown\",\"kind\":\"failure\"},\"liveResources\":0}\n",
            ),
        ] {
            let source = raw_stdout_driver(message.as_bytes());
            let driver = FakeNodeDriver::new(name, &source);
            let error = driver.spawn_error();
            assert_eq!(
                error.kind(),
                visa_component_adapter::AdapterFailureKind::Instantiation,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn real_node_process_rejects_invalid_utf8_and_invalid_json() {
        for (name, source) in [
            (
                "invalid-utf8",
                "import { writeSync } from 'node:fs';\nwriteSync(1, Buffer.from([0xff, 0x0a]));\n"
                    .to_owned(),
            ),
            ("invalid-json", raw_stdout_driver(b"{\n")),
        ] {
            let driver = FakeNodeDriver::new(name, &source);
            let error = driver.spawn_error();
            assert_eq!(
                error.kind(),
                visa_component_adapter::AdapterFailureKind::Instantiation,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn real_node_process_rejects_an_oversized_unterminated_line() {
        let source = format!(
            r#"
import {{ writeSync }} from 'node:fs';
const bytes = Buffer.alloc({} + 1, 0x61);
let offset = 0;
try {{
  while (offset < bytes.length) {{
    offset += writeSync(1, bytes, offset, bytes.length - offset);
  }}
}} catch {{}}
"#,
            MAX_JSONL_MESSAGE_BYTES
        );
        let driver = FakeNodeDriver::new("oversized-line", &source);
        let error = driver.spawn_error();
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Instantiation);
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn real_node_process_rejects_wrong_protocol_response_id_and_missing_fields() {
        for (name, response) in [
            (
                "wrong-response-protocol",
                "{ type: 'response', protocol: 999, id: 1, ok: true, result: null, liveResources: 0 }",
            ),
            (
                "wrong-response-id",
                "{ type: 'response', protocol: 3, id: 9, ok: true, result: null, liveResources: 0 }",
            ),
            (
                "missing-response-id",
                "{ type: 'response', protocol: 3, ok: true, result: null, liveResources: 0 }",
            ),
            (
                "success-missing-result",
                "{ type: 'response', protocol: 3, id: 1, ok: true, liveResources: 0 }",
            ),
            (
                "success-with-error",
                "{ type: 'response', protocol: 3, id: 1, ok: true, result: null, error: { domain: 'workload', kind: 'invalid-state' }, liveResources: 0 }",
            ),
            (
                "success-with-null-error",
                "{ type: 'response', protocol: 3, id: 1, ok: true, result: null, error: null, liveResources: 0 }",
            ),
            (
                "failure-missing-error",
                "{ type: 'response', protocol: 3, id: 1, ok: false, liveResources: 0 }",
            ),
            (
                "failure-with-result",
                "{ type: 'response', protocol: 3, id: 1, ok: false, result: null, error: { domain: 'workload', kind: 'invalid-state' }, liveResources: 0 }",
            ),
            (
                "failure-with-null-error",
                "{ type: 'response', protocol: 3, id: 1, ok: false, error: null, liveResources: 0 }",
            ),
            (
                "failure-with-null-error-detail",
                "{ type: 'response', protocol: 3, id: 1, ok: false, error: { domain: 'workload', kind: 'invalid-state', detail: null }, liveResources: 0 }",
            ),
            (
                "failure-with-unknown-domain",
                "{ type: 'response', protocol: 3, id: 1, ok: false, error: { domain: 'unknown', kind: 'invalid-state' }, liveResources: 0 }",
            ),
            (
                "failure-with-unknown-workload-kind",
                "{ type: 'response', protocol: 3, id: 1, ok: false, error: { domain: 'workload', kind: 'unknown' }, liveResources: 0 }",
            ),
            (
                "guest-trap-without-detail",
                "{ type: 'response', protocol: 3, id: 1, ok: false, error: { domain: 'trap', kind: 'guest-trap' }, liveResources: 0 }",
            ),
        ] {
            let source = format!("{READY_AND_WAIT}\nsend({response});\n");
            let driver = FakeNodeDriver::new(name, &source);
            let mut process = driver.spawn().expect("valid ready handshake");
            let error = process
                .call("test", Value::Null, |_| Ok(Value::Null))
                .expect_err("malformed response must fail");
            assert_eq!(
                error.kind(),
                visa_component_adapter::AdapterFailureKind::GuestTrap,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn real_node_process_maps_a_well_formed_failure_response() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 1, ok: false, error: {{ domain: 'workload', kind: 'already-active' }}, liveResources: 0 }});
settle(1);
readSync(0, command, 0, command.length, null);
send({{ type: 'response', protocol: 3, id: 2, ok: true, result: {{ reusable: true }}, liveResources: 0 }});
settle(2);
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("well-formed-failure", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let reply = process
            .call("test", Value::Null, |_| Ok(Value::Null))
            .expect("a well-formed terminal response is trusted");
        let error = reply.result.expect_err("guest failure must be mapped");
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Workload);

        let reply = process
            .call("after-failure", Value::Null, |_| Ok(Value::Null))
            .expect("a well-formed guest failure must not poison the process");
        assert_eq!(reply.result.expect("the next command succeeds"), json!({ "reusable": true }));
    }

    #[test]
    fn a_well_formed_guest_trap_does_not_poison_the_process() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 1, ok: false, error: {{ domain: 'trap', kind: 'guest-trap', detail: 'guest trapped' }}, liveResources: 0 }});
settle(1);
readSync(0, command, 0, command.length, null);
send({{ type: 'response', protocol: 3, id: 2, ok: true, result: null, liveResources: 0 }});
settle(2);
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("well-formed-guest-trap", &source);
        let mut process = driver.spawn().expect("valid ready handshake");

        let reply = process
            .call("first", json!({}), |_| Ok(Value::Null))
            .expect("a well-formed guest trap is a terminal guest result");
        assert_eq!(
            reply.result.expect_err("the guest trap must propagate").kind(),
            visa_component_adapter::AdapterFailureKind::GuestTrap
        );

        let reply = process
            .call("second", json!({}), |_| Ok(Value::Null))
            .expect("a well-formed guest trap must not poison the process");
        assert_eq!(reply.result.expect("the next command succeeds"), Value::Null);
    }

    #[test]
    fn terminal_failure_retains_the_observed_live_resource_count() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 2 }});
settle(1);
readSync(0, command, 0, command.length, null);
send({{ type: 'response', protocol: 3, id: 2, ok: false, error: {{ domain: 'workload', kind: 'invalid-state' }}, liveResources: 0 }});
settle(2);
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("failure-live-resources", &source);
        let mut process = driver.spawn().expect("valid ready handshake");

        let first = process
            .call("first", Value::Null, |_| Ok(Value::Null))
            .expect("first terminal response");
        assert_eq!(first.live_resources, 2);
        assert!(first.result.is_ok());

        let second = process
            .call("second", Value::Null, |_| Ok(Value::Null))
            .expect("failure is still a well-formed terminal response");
        assert_eq!(second.live_resources, 0);
        assert!(second.result.is_err());
    }

    #[test]
    fn real_node_process_reports_eof_after_a_valid_ready_handshake() {
        let driver = FakeNodeDriver::new("eof", READY_AND_WAIT);
        let mut process = driver.spawn().expect("valid ready handshake");
        let error = process
            .call("test", Value::Null, |_| Ok(Value::Null))
            .expect_err("EOF before a response must fail");
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert!(error.to_string().contains("stream closed"), "{error}");

        let mut host_calls = 0;
        let error = process
            .call("retry", Value::Null, |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a process poisoned by EOF must reject later calls");
        assert!(
            matches!(&error, AdapterError::GuestTrap(detail) if detail == POISONED_PROCESS_ERROR),
            "{error}"
        );
        assert_eq!(host_calls, 0, "a poisoned process must not dispatch host calls");
        assert!(process.child.try_wait().expect("query terminated child").is_some());
    }

    #[test]
    fn malformed_response_terminates_the_process_before_a_second_call() {
        let source = format!(
            r#"import {{ writeFileSync }} from 'node:fs';
{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 99, ok: true, result: null, liveResources: 0 }});
const secondCommand = Buffer.alloc(4096);
const secondCount = readSync(0, secondCommand, 0, secondCommand.length, null);
if (secondCount > 0) writeFileSync('second-call-executed', 'yes');
"#
        );
        let driver = FakeNodeDriver::new("poison-after-malformed-response", &source);
        let marker = driver.directory.path().join("second-call-executed");
        let mut process = driver.spawn().expect("valid ready handshake");

        let first_error = process
            .call("first", Value::Null, |_| Ok(Value::Null))
            .expect_err("the malformed response must fail");
        assert!(first_error.to_string().contains("did not match command 1"));
        assert!(process.child.try_wait().expect("query terminated child").is_some());

        let mut host_calls = 0;
        let second_error = process
            .call("second", Value::Null, |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("the poisoned process must reject a second call");
        assert!(
            matches!(&second_error, AdapterError::GuestTrap(detail) if detail == POISONED_PROCESS_ERROR),
            "{second_error}"
        );
        assert_eq!(host_calls, 0, "the second call must not reach the host");
        assert!(!marker.exists(), "the second call must not reach the child");
    }

    #[test]
    fn real_node_process_rejects_an_oversized_outgoing_command_before_sending() {
        let driver = FakeNodeDriver::new("oversized-command", READY_AND_WAIT);
        let mut process = driver.spawn().expect("valid ready handshake");
        let error = process
            .call("test", json!({ "payload": "x".repeat(MAX_JSONL_MESSAGE_BYTES) }), |_| {
                Ok(Value::Null)
            })
            .expect_err("oversized command must fail before transmission");
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn real_node_process_round_trips_a_hostcall_before_the_command_response() {
        let source = format!(
            r#"{READY_AND_WAIT}
		send({{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
	const hostResponse = Buffer.alloc(4096);
	const count = readSync(0, hostResponse, 0, hostResponse.length, null);
	const decoded = JSON.parse(hostResponse.subarray(0, count).toString('utf8'));
		if (decoded.type !== 'hostcall-response' || decoded.id !== 1 || decoded.ok !== true) process.exit(23);
		send({{ type: 'response', protocol: 3, id: 1, ok: true, result: {{ done: true }}, liveResources: 0 }});
		settle(1);
		readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("hostcall", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let reply = process
            .call("test", Value::Null, |call| {
                assert_eq!(call.id, 1);
                assert_eq!(call.resource, 3);
                match call.operation {
                    crate::protocol::HostCallOperation::KvRead(args) => {
                        assert_eq!(args.key, "k");
                    }
                    other => panic!("unexpected hostcall operation: {other:?}"),
                }
                Ok(json!({ "value": null }))
            })
            .expect("hostcall and command response complete in order");
        assert_eq!(reply.result.expect("guest command succeeded"), json!({ "done": true }));
    }

    #[test]
    fn real_node_process_rejects_a_skipped_hostcall_id() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'hostcall', protocol: 3, id: 2, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
"#
        );
        let driver = FakeNodeDriver::new("skipped-hostcall-id", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let error = process
            .call("test", Value::Null, |_| Ok(Value::Null))
            .expect_err("a skipped hostcall id must fail");
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert!(error.to_string().contains("expected 1"), "{error}");
    }

    #[test]
    fn real_node_process_rejects_a_repeated_hostcall_id() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
const hostResponse = Buffer.alloc(4096);
readSync(0, hostResponse, 0, hostResponse.length, null);
send({{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
"#
        );
        let driver = FakeNodeDriver::new("repeated-hostcall-id", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let mut calls = 0;
        let error = process
            .call("test", Value::Null, |_| {
                calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a repeated hostcall id must fail");
        assert_eq!(calls, 1, "the repeated hostcall must not reach the host");
        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert!(error.to_string().contains("expected 2"), "{error}");
    }

    #[test]
    fn ready_followed_by_a_premature_response_is_rejected_before_the_first_command() {
        let source = r#"
import { readSync, writeSync } from 'node:fs';
const frames = [
  {
    type: 'ready', protocol: 3,
    nodeVersion: process.versions.node,
    v8Version: process.versions.v8,
    liveResources: 0,
  },
  { type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 0 },
];
const bytes = Buffer.from(`${frames.map(JSON.stringify).join('\n')}\n`, 'utf8');
let offset = 0;
while (offset < bytes.length) offset += writeSync(1, bytes, offset, bytes.length - offset);
const command = Buffer.alloc(4096);
readSync(0, command, 0, command.length, null);
"#;
        let driver = FakeNodeDriver::new("premature-response", source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let mut host_calls = 0;

        let error = process
            .call("first", json!({}), |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a response queued before its command must be rejected");

        assert!(error.to_string().contains("before sending a new Node command"), "{error}");
        assert_eq!(host_calls, 0);
        assert_poisoned(&mut process);
    }

    #[test]
    fn terminal_response_with_a_trailing_hostcall_is_rejected_without_dispatch() {
        let source = format!(
            r#"{READY_AND_WAIT}
const frames = [
  {{ type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 0 }},
  {{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'late' }} }},
];
const bytes = Buffer.from(`${{frames.map(JSON.stringify).join('\n')}}\n`, 'utf8');
let offset = 0;
while (offset < bytes.length) offset += writeSync(1, bytes, offset, bytes.length - offset);
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("trailing-hostcall", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let mut host_calls = 0;

        let error = process
            .call("first", json!({}), |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a terminal response followed by another frame must fail");

        assert!(error.to_string().contains("after the terminal Node response"), "{error}");
        assert_eq!(host_calls, 0, "the trailing hostcall must not reach the host");
        assert_poisoned(&mut process);
    }

    #[test]
    fn terminal_settled_boundary_rejects_a_trailing_frame_without_dispatch() {
        let source = format!(
            r#"{READY_AND_WAIT}
const frames = [
  {{ type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 0 }},
  {{ type: 'settled', protocol: 3, id: 1 }},
  {{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'late' }} }},
];
const bytes = Buffer.from(`${{frames.map(JSON.stringify).join('\n')}}\n`, 'utf8');
let offset = 0;
while (offset < bytes.length) offset += writeSync(1, bytes, offset, bytes.length - offset);
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("trailing-after-settled", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let mut host_calls = 0;

        let error = process
            .call("first", json!({}), |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a frame queued after settled must fail");

        assert!(error.to_string().contains("after the terminal Node response settled"), "{error}");
        assert_eq!(host_calls, 0, "the trailing hostcall must not reach the host");
        assert_poisoned(&mut process);
    }

    #[test]
    fn terminal_response_requires_a_matching_settled_command_id() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 0 }});
settle(2);
"#
        );
        let driver = FakeNodeDriver::new("wrong-settled-command", &source);
        let mut process = driver.spawn().expect("valid ready handshake");

        let error = process
            .call("first", json!({}), |_| Ok(Value::Null))
            .expect_err("settled must bind the terminal response command");

        assert!(error.to_string().contains("did not match terminal response 1"), "{error}");
        assert_poisoned(&mut process);
    }

    #[test]
    fn hostcall_parent_must_match_the_active_command_before_dispatch() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'hostcall', protocol: 3, id: 1, commandId: 2, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
"#
        );
        let driver = FakeNodeDriver::new("wrong-hostcall-parent", &source);
        let mut process = driver.spawn().expect("valid ready handshake");
        let mut host_calls = 0;

        let error = process
            .call("first", json!({}), |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a mismatched hostcall parent must fail");

        assert!(error.to_string().contains("did not match active command 1"), "{error}");
        assert_eq!(host_calls, 0);
        assert_poisoned(&mut process);
    }

    #[test]
    fn typed_hostcall_arguments_reject_extra_missing_duplicate_and_unknown_operations() {
        for (name, frame) in [
            (
                "extra-hostcall-argument",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":1,"op":"kv.read","resource":3,"args":{"key":"k","extra":true}}"#,
            ),
            (
                "missing-hostcall-argument",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":1,"op":"kv.read","resource":3,"args":{}}"#,
            ),
            (
                "duplicate-hostcall-argument",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":1,"op":"kv.read","resource":3,"args":{"key":"k","key":"other"}}"#,
            ),
            (
                "unknown-hostcall-operation",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":1,"op":"kv.erase","resource":3,"args":{"key":"k"}}"#,
            ),
        ] {
            let frame = serde_json::to_string(frame).expect("encode raw frame for JavaScript");
            let source = format!("{READY_AND_WAIT}\nsendRaw({frame});\n");
            let driver = FakeNodeDriver::new(name, &source);
            let mut process = driver.spawn().expect("valid ready handshake");
            let mut host_calls = 0;

            let error = process
                .call("first", json!({}), |_| {
                    host_calls += 1;
                    Ok(Value::Null)
                })
                .expect_err("malformed typed hostcall arguments must fail");

            assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
            assert_eq!(host_calls, 0, "{name}: malformed args reached the host");
            assert_poisoned(&mut process);
        }
    }

    #[test]
    fn incoming_protocol_ids_must_be_javascript_safe_integers() {
        for (name, frame) in [
            (
                "unsafe-hostcall-id",
                r#"{"type":"hostcall","protocol":3,"id":9007199254740992,"commandId":1,"op":"kv.read","resource":3,"args":{"key":"k"}}"#,
            ),
            (
                "unsafe-hostcall-parent",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":9007199254740992,"op":"kv.read","resource":3,"args":{"key":"k"}}"#,
            ),
            (
                "unsafe-resource-id",
                r#"{"type":"hostcall","protocol":3,"id":1,"commandId":1,"op":"kv.read","resource":9007199254740992,"args":{"key":"k"}}"#,
            ),
            (
                "unsafe-response-id",
                r#"{"type":"response","protocol":3,"id":9007199254740992,"ok":true,"result":null,"liveResources":0}"#,
            ),
        ] {
            let frame = serde_json::to_string(frame).expect("encode raw frame for JavaScript");
            let source = format!("{READY_AND_WAIT}\nsendRaw({frame});\n");
            let driver = FakeNodeDriver::new(name, &source);
            let mut process = driver.spawn().expect("valid ready handshake");
            let mut host_calls = 0;

            let error = process
                .call("first", json!({}), |_| {
                    host_calls += 1;
                    Ok(Value::Null)
                })
                .expect_err("unsafe protocol IDs must fail closed");

            assert!(error.to_string().contains("JavaScript-safe"), "{name}: {error}");
            assert_eq!(host_calls, 0, "{name}: unsafe ID reached the host");
            assert_poisoned(&mut process);
        }
    }

    #[test]
    fn a_protocol_domain_host_error_poisoned_the_process_without_a_wire_response() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'hostcall', protocol: 3, id: 1, commandId: 1, op: 'kv.read', resource: 3, args: {{ key: 'k' }} }});
readSync(0, command, 0, command.length, null);
"#
        );
        let driver = FakeNodeDriver::new("fatal-host-protocol-error", &source);
        let mut process = driver.spawn().expect("valid ready handshake");

        let error = process
            .call("first", json!({}), |_| {
                Err(WireError {
                    domain: "protocol".into(),
                    kind: "wrong-resource-kind".into(),
                    detail: Some("timer handle used for kv.read".into()),
                })
            })
            .expect_err("a host protocol error must be connection-fatal");

        assert!(error.to_string().contains("wrong-resource-kind"), "{error}");
        assert_poisoned(&mut process);
    }

    #[test]
    fn terminal_response_followed_by_eof_is_not_accepted() {
        let source = format!(
            r#"{READY_AND_WAIT}
send({{ type: 'response', protocol: 3, id: 1, ok: true, result: null, liveResources: 0 }});
closeSync(1);
"#
        );
        let driver = FakeNodeDriver::new("terminal-eof", &source);
        let mut process = driver.spawn().expect("valid ready handshake");

        let error = process
            .call("first", json!({}), |_| Ok(Value::Null))
            .expect_err("EOF at the terminal boundary must invalidate the response");

        assert!(error.to_string().contains("after the terminal Node response"), "{error}");
        assert_poisoned(&mut process);
    }

    #[test]
    fn actual_driver_rejects_a_non_contiguous_command_id() {
        let driver = ActualNodeDriver::new();
        let mut process = driver.spawn().expect("actual driver ready handshake");
        process.next_command_id = 2;

        let error = process
            .call("status", json!({}), |_| Ok(Value::Null))
            .expect_err("the actual driver must reject a skipped command id");

        assert!(error.to_string().contains("unexpected Node protocol message"), "{error}");
        assert_poisoned(&mut process);
    }

    #[test]
    fn actual_driver_rejects_non_canonical_semantic_u64_text() {
        let driver = ActualNodeDriver::new();
        let mut process = driver.spawn().expect("actual driver ready handshake");

        let error = process
            .call(
                "restore",
                json!({
                    "state": {
                        "sessionId": "session",
                        "key": "key",
                        "expectedVersion": "01",
                        "completionValue": [],
                        "timerOperationId": "timer-operation",
                        "timerIdempotencyKey": "timer-idempotency",
                        "completionIdempotencyKey": "completion-idempotency",
                        "phase": "frozen",
                    },
                    "remainingDurationNs": "1",
                    "kvResource": 1,
                    "timerResource": 2,
                }),
                |_| Ok(Value::Null),
            )
            .expect_err("the actual driver must reject non-canonical u64 text");

        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::GuestTrap);
        assert_poisoned(&mut process);
    }

    #[test]
    fn actual_driver_rejects_substituted_bytes_before_import() {
        let original = ActualNodeDriver::new();
        let expected = original.graph.generated_digest_hex();
        let directory = tempfile::tempdir().expect("substituted carrier marker directory");
        let marker = directory.path().join("substituted-entrypoint-executed");
        let marker_json = serde_json::to_string(&marker.to_string_lossy()).unwrap();
        let substituted_source = format!(
            "import {{ writeFileSync }} from 'node:fs';\nwriteFileSync({marker_json}, 'bad');\n{ACTUAL_ENTRYPOINT}"
        );
        let substituted = PreparedExecutionGraph::new(
            "handoff-component.component.js".into(),
            substituted_source.into_bytes(),
            vec![("handoff-component.component.core.wasm".into(), b"\0asm\x01\0\0\0".to_vec())],
        )
        .expect("well-formed substituted graph");

        let error =
            match NodeProcess::spawn_with_expected_digest(&node_path(), &substituted, expected) {
                Ok(_) => panic!("a graph with a different captured digest did not fail closed"),
                Err(error) => error,
            };

        assert_eq!(error.kind(), visa_component_adapter::AdapterFailureKind::Instantiation);
        assert!(!marker.exists(), "substituted entrypoint executed before digest validation");
    }

    #[cfg(unix)]
    #[test]
    fn actual_driver_ignores_replaced_publisher_files_directories_symlinks_and_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("hostile publisher fixture");
        let published = directory.path().join("published");
        let moved = directory.path().join("published-original");
        let external_core = directory.path().join("external.core.wasm");
        let marker = directory.path().join("replacement-entrypoint-executed");
        fs::create_dir(&published).unwrap();
        fs::write(published.join("handoff-component.component.js"), ACTUAL_ENTRYPOINT).unwrap();
        fs::write(published.join("handoff-component.component.core.wasm"), b"\0asm\x01\0\0\0")
            .unwrap();
        let graph = PreparedExecutionGraph::new(
            "handoff-component.component.js".into(),
            fs::read(published.join("handoff-component.component.js")).unwrap(),
            vec![(
                "handoff-component.component.core.wasm".into(),
                fs::read(published.join("handoff-component.component.core.wasm")).unwrap(),
            )],
        )
        .expect("capture publisher bytes before replacement");

        fs::rename(&published, &moved).unwrap();
        fs::create_dir(&published).unwrap();
        let marker_json = serde_json::to_string(&marker.to_string_lossy()).unwrap();
        fs::write(
            published.join("handoff-component.component.js"),
            format!(
                "import {{ writeFileSync }} from 'node:fs'; writeFileSync({marker_json}, 'bad');"
            ),
        )
        .unwrap();
        fs::write(&external_core, b"attacker core").unwrap();
        symlink(&external_core, published.join("handoff-component.component.core.wasm")).unwrap();

        let process = NodeProcess::spawn(&node_path(), &graph)
            .expect("owned bytes remain executable after every publisher pathname is replaced");
        drop(process);
        assert!(!marker.exists(), "replacement publisher entrypoint unexpectedly executed");
    }

    #[test]
    fn locally_generated_ids_stop_at_the_javascript_safe_integer_limit() {
        let mut next = MAX_JS_SAFE_INTEGER;
        assert_eq!(
            take_next_safe_id(&mut next, "test").expect("the maximum safe id is valid"),
            MAX_JS_SAFE_INTEGER
        );
        assert_eq!(next, MAX_JS_SAFE_INTEGER + 1);
        let error = take_next_safe_id(&mut next, "test")
            .expect_err("an id above the JavaScript safe-integer limit must fail");
        assert!(error.to_string().contains("JavaScript-safe"), "{error}");
    }

    fn assert_poisoned(process: &mut NodeProcess) {
        let mut host_calls = 0;
        let error = process
            .call("after-failure", json!({}), |_| {
                host_calls += 1;
                Ok(Value::Null)
            })
            .expect_err("a poisoned process must reject the next call");
        assert!(
            matches!(&error, AdapterError::GuestTrap(detail) if detail == POISONED_PROCESS_ERROR),
            "{error}"
        );
        assert_eq!(host_calls, 0);
        assert!(process.child.try_wait().expect("query terminated child").is_some());
    }

    fn raw_stdout_driver(bytes: &[u8]) -> String {
        let bytes = bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        format!("import {{ writeSync }} from 'node:fs';\nwriteSync(1, Buffer.from([{bytes}]));\n")
    }

    struct FakeNodeDriver {
        directory: tempfile::TempDir,
        driver: PathBuf,
        entrypoint: PathBuf,
    }

    impl FakeNodeDriver {
        fn new(name: &str, source: &str) -> Self {
            let directory = tempfile::tempdir().expect("fake Node driver directory");
            let driver = directory.path().join(format!("{name}.mjs"));
            let entrypoint = directory.path().join("unused-entrypoint.mjs");
            fs::write(&driver, source).expect("write fake Node driver");
            fs::write(&entrypoint, "export {};\n").expect("write unused entrypoint");
            Self { directory, driver, entrypoint }
        }

        fn spawn(&self) -> Result<NodeProcess, AdapterError> {
            let node = std::env::var_os("VISA_NODE_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("node"));
            NodeProcess::spawn_test_driver(
                &node,
                &self.driver,
                &self.entrypoint,
                self.directory.path(),
            )
        }

        fn spawn_error(&self) -> AdapterError {
            match self.spawn() {
                Ok(_) => panic!("malformed fake Node driver unexpectedly started"),
                Err(error) => error,
            }
        }
    }

    const ACTUAL_ENTRYPOINT: &str = r#"
export function instantiate(getCoreModule) {
  getCoreModule('handoff-component.component.core.wasm');
  return {
    workload: {
      activate() {},
      freeze() { return undefined; },
      thaw() {},
      restore() {},
      timerFired() {},
      cancelPending() {},
      status() { return undefined; },
    },
  };
}
"#;

    struct ActualNodeDriver {
        graph: PreparedExecutionGraph,
    }

    impl ActualNodeDriver {
        fn new() -> Self {
            let graph = PreparedExecutionGraph::new(
                "handoff-component.component.js".into(),
                ACTUAL_ENTRYPOINT.as_bytes().to_vec(),
                vec![("handoff-component.component.core.wasm".into(), b"\0asm\x01\0\0\0".to_vec())],
            )
            .expect("actual-driver path-free graph");
            Self { graph }
        }

        fn spawn(&self) -> Result<NodeProcess, AdapterError> {
            NodeProcess::spawn(&node_path(), &self.graph)
        }
    }

    fn node_path() -> PathBuf {
        std::env::var_os("VISA_NODE_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("node"))
    }
}
