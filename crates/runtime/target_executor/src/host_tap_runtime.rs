use std::{env, error::Error, thread, time::Duration};

use net_stack_adapter::{
    SmoltcpAdapterConfig, SmoltcpPacketStack, StackDriverBackendPumpEvidence,
    pump_stack_driver_backend,
};
use service_core::driver::DriverVirtioNetState;
use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};
use substrate_virtio::net::HostTapPacketDeviceBackend;

use crate::HOST_TAP_ENV;

const HOST_TAP_REMOTE_IPV4_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REMOTE_IPV4";
const HOST_TAP_REMOTE_PORT_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REMOTE_PORT";
const HOST_TAP_PUMP_STEPS_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_PUMP_STEPS";
const HOST_TAP_PUMP_SLEEP_MS_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_PUMP_SLEEP_MS";
const HOST_TAP_REQUIRE_ESTABLISHED_ENV: &str = "VMOS_TARGET_EXECUTOR_HOST_TAP_REQUIRE_ESTABLISHED";
const HOST_TAP_DEFAULT_REMOTE_IPV4: [u8; 4] = [10, 0, 2, 2];
const HOST_TAP_DEFAULT_REMOTE_PORT: u16 = 80;
const HOST_TAP_DEFAULT_PUMP_STEPS: u32 = 16;
const HOST_TAP_MAX_PUMP_STEPS: u32 = 1024;
const HOST_TAP_DEFAULT_PUMP_SLEEP_MS: u64 = 10;
const HOST_TAP_MAX_PUMP_SLEEP_MS: u64 = 1000;

pub(crate) struct HostTapRuntimeConfig {
    pub(crate) tap_name: String,
    remote_ipv4: [u8; 4],
    remote_port: u16,
    pump_steps: u32,
    pump_sleep_ms: u64,
    require_established: bool,
}

impl HostTapRuntimeConfig {
    pub(crate) fn new(
        tap_name: String,
        remote_ipv4: [u8; 4],
        remote_port: u16,
        pump_steps: u32,
        pump_sleep_ms: u64,
        require_established: bool,
    ) -> Result<Self, Box<dyn Error>> {
        if remote_port == 0 {
            return Err("host TAP remote port must be nonzero".into());
        }
        if pump_steps == 0 || pump_steps > HOST_TAP_MAX_PUMP_STEPS {
            return Err(
                format!("host TAP pump steps must be in 1..={HOST_TAP_MAX_PUMP_STEPS}").into()
            );
        }
        if pump_sleep_ms > HOST_TAP_MAX_PUMP_SLEEP_MS {
            return Err(format!(
                "host TAP pump sleep ms must be in 0..={HOST_TAP_MAX_PUMP_SLEEP_MS}"
            )
            .into());
        }
        Ok(Self {
            tap_name,
            remote_ipv4,
            remote_port,
            pump_steps,
            pump_sleep_ms,
            require_established,
        })
    }

    pub(crate) fn from_env() -> Result<Option<Self>, Box<dyn Error>> {
        let Some(tap_name) = env::var_os(HOST_TAP_ENV) else {
            return Ok(None);
        };
        let tap_name =
            tap_name.into_string().map_err(|_| format!("{HOST_TAP_ENV} must be valid UTF-8"))?;
        Ok(Some(Self::new(
            tap_name,
            host_tap_remote_ipv4()?,
            host_tap_remote_port()?,
            host_tap_pump_steps()?,
            host_tap_pump_sleep_ms()?,
            host_tap_require_established()?,
        )?))
    }
}

pub(crate) struct HostTapRuntimeReport {
    pub(crate) tap_name: String,
    pub(crate) pump_steps: u32,
    pub(crate) completed_steps: u32,
    pub(crate) pump_sleep_ms: u64,
    pub(crate) require_established: bool,
    pub(crate) final_state: &'static str,
    pub(crate) final_can_send: bool,
    pub(crate) tx_frames: usize,
    pub(crate) tx_bytes: usize,
    pub(crate) tx_lengths: Vec<usize>,
    pub(crate) rx_frames: usize,
    pub(crate) rx_bytes: usize,
    pub(crate) rx_lengths: Vec<usize>,
    pub(crate) totals: HostTapPumpTotals,
}

pub(crate) fn run_host_tap_runtime_probe(
    config: HostTapRuntimeConfig,
) -> Result<HostTapRuntimeReport, Box<dyn Error>> {
    let mut stack = SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos())
        .map_err(|error| format!("host TAP smoltcp stack init failed: {error}"))?;
    let mut driver = DriverVirtioNetState::new();
    let mut backend = CountingHostTapBackend::open(&config.tap_name)?;
    stack
        .init_backend(&mut backend)
        .map_err(|error| format!("host TAP backend init failed: {error:?}"))?;

    let socket_id = stack
        .create_tcp_socket()
        .map_err(|error| format!("host TAP probe tcp socket creation failed: {error}"))?;
    stack
        .connect_tcp_ipv4(socket_id, config.remote_ipv4, config.remote_port)
        .map_err(|error| format!("host TAP probe tcp connect setup failed: {error}"))?;

    let mut totals = HostTapPumpTotals::default();
    let mut final_state = "unknown";
    let mut final_can_send = false;
    let mut completed_steps = 0u32;
    for step in 0..config.pump_steps {
        completed_steps = step.saturating_add(1);
        let tick = u64::from(step).saturating_add(1);
        let pump =
            pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, tick as i64, tick)
                .map_err(|error| format!("host TAP stack/driver/backend pump failed: {error:?}"))?;
        totals.add(&pump);
        let snapshot = stack
            .tcp_snapshot(socket_id)
            .map_err(|error| format!("host TAP tcp snapshot failed: {error}"))?;
        final_state = snapshot.state;
        final_can_send = snapshot.can_send;
        if config.require_established && final_state == "established" {
            break;
        }
        if config.pump_sleep_ms != 0 && completed_steps < config.pump_steps {
            thread::sleep(Duration::from_millis(config.pump_sleep_ms));
        }
    }
    if backend.tx_frames == 0 {
        return Err("host TAP probe produced no backend TX frame".into());
    }
    if config.require_established && final_state != "established" {
        return Err(
            format!("host TAP probe did not establish TCP socket: state={final_state}").into()
        );
    }

    Ok(HostTapRuntimeReport {
        tap_name: config.tap_name,
        pump_steps: config.pump_steps,
        completed_steps,
        pump_sleep_ms: config.pump_sleep_ms,
        require_established: config.require_established,
        final_state,
        final_can_send,
        tx_frames: backend.tx_frames,
        tx_bytes: backend.tx_bytes,
        tx_lengths: backend.tx_lengths,
        rx_frames: backend.rx_frames,
        rx_bytes: backend.rx_bytes,
        rx_lengths: backend.rx_lengths,
        totals,
    })
}

struct CountingHostTapBackend {
    inner: HostTapPacketDeviceBackend,
    tx_frames: usize,
    tx_bytes: usize,
    tx_lengths: Vec<usize>,
    rx_frames: usize,
    rx_bytes: usize,
    rx_lengths: Vec<usize>,
}

impl CountingHostTapBackend {
    fn open(name: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            inner: HostTapPacketDeviceBackend::open(name)
                .map_err(|error| format!("host TAP open failed: {error:?}"))?,
            tx_frames: 0,
            tx_bytes: 0,
            tx_lengths: Vec::new(),
            rx_frames: 0,
            rx_bytes: 0,
            rx_lengths: Vec::new(),
        })
    }
}

impl PacketDeviceBackend for CountingHostTapBackend {
    fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
        self.inner.init(mac)
    }

    fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
        self.inner.submit_tx(frame)?;
        self.tx_frames += 1;
        self.tx_bytes = self.tx_bytes.saturating_add(frame.len());
        self.tx_lengths.push(frame.len());
        Ok(())
    }

    fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
        let count = self.inner.poll_rx(out)?;
        if count > out.len() {
            return Err(SubstrateError::ContractViolation {
                detail: "host TAP backend overreported rx frame count",
            });
        }
        for slot in out.iter().take(count) {
            let len = usize::from(slot.len);
            self.rx_bytes = self.rx_bytes.saturating_add(len);
            self.rx_lengths.push(len);
        }
        self.rx_frames = self.rx_frames.saturating_add(count);
        Ok(count)
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
}

#[derive(Default)]
pub(crate) struct HostTapPumpTotals {
    pub(crate) backend_rx_frames_delivered_to_driver: usize,
    pub(crate) driver_rx_frames_delivered_to_stack: usize,
    pub(crate) stack_tx_frames_submitted_to_driver: usize,
    pub(crate) driver_tx_frames_submitted_to_backend: usize,
}

impl HostTapPumpTotals {
    fn add(&mut self, pump: &StackDriverBackendPumpEvidence) {
        self.backend_rx_frames_delivered_to_driver = self
            .backend_rx_frames_delivered_to_driver
            .saturating_add(pump.backend_rx_frames_delivered_to_driver);
        self.driver_rx_frames_delivered_to_stack = self
            .driver_rx_frames_delivered_to_stack
            .saturating_add(pump.driver_rx_frames_delivered_to_stack);
        self.stack_tx_frames_submitted_to_driver = self
            .stack_tx_frames_submitted_to_driver
            .saturating_add(pump.stack_tx_frames_submitted_to_driver);
        self.driver_tx_frames_submitted_to_backend = self
            .driver_tx_frames_submitted_to_backend
            .saturating_add(pump.driver_tx_frames_submitted_to_backend);
    }
}

fn host_tap_remote_ipv4() -> Result<[u8; 4], Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REMOTE_IPV4_ENV) else {
        return Ok(HOST_TAP_DEFAULT_REMOTE_IPV4);
    };
    parse_ipv4(HOST_TAP_REMOTE_IPV4_ENV, &raw)
}

fn host_tap_remote_port() -> Result<u16, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REMOTE_PORT_ENV) else {
        return Ok(HOST_TAP_DEFAULT_REMOTE_PORT);
    };
    parse_nonzero_u16(HOST_TAP_REMOTE_PORT_ENV, &raw)
}

fn host_tap_pump_steps() -> Result<u32, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_PUMP_STEPS_ENV) else {
        return Ok(HOST_TAP_DEFAULT_PUMP_STEPS);
    };
    parse_bounded_u32(HOST_TAP_PUMP_STEPS_ENV, &raw, 1, HOST_TAP_MAX_PUMP_STEPS)
}

fn host_tap_pump_sleep_ms() -> Result<u64, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_PUMP_SLEEP_MS_ENV) else {
        return Ok(HOST_TAP_DEFAULT_PUMP_SLEEP_MS);
    };
    parse_bounded_u64(HOST_TAP_PUMP_SLEEP_MS_ENV, &raw, 0, HOST_TAP_MAX_PUMP_SLEEP_MS)
}

fn host_tap_require_established() -> Result<bool, Box<dyn Error>> {
    let Ok(raw) = env::var(HOST_TAP_REQUIRE_ESTABLISHED_ENV) else {
        return Ok(false);
    };
    parse_bool(HOST_TAP_REQUIRE_ESTABLISHED_ENV, &raw)
}

fn parse_ipv4(name: &'static str, raw: &str) -> Result<[u8; 4], Box<dyn Error>> {
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for (index, part) in raw.split('.').enumerate() {
        if index >= out.len() {
            return Err(format!("{name} has too many octets").into());
        }
        out[index] = part.parse::<u8>().map_err(|_| format!("{name} contains invalid octet"))?;
        count += 1;
    }
    if count != out.len() {
        return Err(format!("{name} must contain four octets").into());
    }
    Ok(out)
}

fn parse_nonzero_u16(name: &'static str, raw: &str) -> Result<u16, Box<dyn Error>> {
    let value = raw.parse::<u16>().map_err(|_| format!("{name} must be a u16 TCP port"))?;
    if value == 0 {
        return Err(format!("{name} must be nonzero").into());
    }
    Ok(value)
}

fn parse_bounded_u32(
    name: &'static str,
    raw: &str,
    min: u32,
    max: u32,
) -> Result<u32, Box<dyn Error>> {
    let value = raw.parse::<u32>().map_err(|_| format!("{name} must be a u32"))?;
    if value < min || value > max {
        return Err(format!("{name} must be in {min}..={max}").into());
    }
    Ok(value)
}

fn parse_bounded_u64(
    name: &'static str,
    raw: &str,
    min: u64,
    max: u64,
) -> Result<u64, Box<dyn Error>> {
    let value = raw.parse::<u64>().map_err(|_| format!("{name} must be a u64"))?;
    if value < min || value > max {
        return Err(format!("{name} must be in {min}..={max}").into());
    }
    Ok(value)
}

fn parse_bool(name: &'static str, raw: &str) -> Result<bool, Box<dyn Error>> {
    match raw {
        "0" | "false" | "FALSE" | "False" => Ok(false),
        "1" | "true" | "TRUE" | "True" => Ok(true),
        _ => Err(format!("{name} must be boolean").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_tap_parsers_accept_valid_values() {
        assert_eq!(parse_ipv4("IP", "192.0.2.7").unwrap(), [192, 0, 2, 7]);
        assert_eq!(parse_nonzero_u16("PORT", "8080").unwrap(), 8080);
        assert_eq!(parse_bounded_u32("STEPS", "16", 1, 1024).unwrap(), 16);
        assert_eq!(parse_bounded_u64("SLEEP", "0", 0, 1000).unwrap(), 0);
        assert!(parse_bool("BOOL", "true").unwrap());
        assert!(!parse_bool("BOOL", "0").unwrap());
        let config =
            HostTapRuntimeConfig::new("tap0".to_owned(), [10, 0, 2, 2], 80, 16, 0, false).unwrap();
        assert_eq!(config.tap_name, "tap0");
    }

    #[test]
    fn host_tap_parsers_reject_invalid_values() {
        assert!(parse_ipv4("IP", "192.0.2").is_err());
        assert!(parse_ipv4("IP", "192.0.2.1.9").is_err());
        assert!(parse_ipv4("IP", "192.0.2.999").is_err());
        assert!(parse_nonzero_u16("PORT", "0").is_err());
        assert!(parse_bounded_u32("STEPS", "0", 1, 1024).is_err());
        assert!(parse_bounded_u64("SLEEP", "1001", 0, 1000).is_err());
        assert!(parse_bool("BOOL", "yes").is_err());
        assert!(
            HostTapRuntimeConfig::new("tap0".to_owned(), [10, 0, 2, 2], 0, 16, 0, false).is_err()
        );
        assert!(
            HostTapRuntimeConfig::new("tap0".to_owned(), [10, 0, 2, 2], 80, 0, 0, false).is_err()
        );
    }
}
