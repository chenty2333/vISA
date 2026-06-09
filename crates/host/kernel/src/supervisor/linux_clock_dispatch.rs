use visa_abi::{ERR_EFAULT, ERR_EINVAL, ERR_EPERM};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{CAP_SYS_TIME, RuntimeClockAdjustmentState},
};

const CLOCK_REALTIME: u64 = 0;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_REALTIME_ALARM: u64 = 8;
const CLOCK_TAI: u64 = 11;
const MAX_CLOCK_ID: u64 = 11;
const TIMEX_SIZE: u32 = 208;
const TIMESPEC_SIZE: usize = 16;
const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_ESTERROR: u32 = 0x0008;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_TIMECONST: u32 = 0x0020;
const ADJ_TAI: u32 = 0x0080;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
const ADJ_TICK_MIN_US: i64 = 9_000;
const ADJ_TICK_MAX_US: i64 = 11_000;
const SUPPORTED_MODES: u32 = ADJ_OFFSET
    | ADJ_FREQUENCY
    | ADJ_MAXERROR
    | ADJ_ESTERROR
    | ADJ_STATUS
    | ADJ_TIMECONST
    | ADJ_TAI
    | ADJ_SETOFFSET
    | ADJ_MICRO
    | ADJ_NANO
    | ADJ_TICK;
const STA_UNSYNC: i32 = 0x0040;
const STA_RONLY: i32 = 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x4000 | 0x8000;
const TIME_OK: i64 = 0;
const TIME_ERROR: i64 = 5;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_clock_gettime(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_clock_gettime(plan) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_clock_getres(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_clock_getres(plan) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_clock_adjtime(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_clock_adjtime(plan) {
            Ok(ret) => Ok(LinuxCallResult::Ret(ret)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    fn apply_clock_gettime(&mut self, plan: LinuxPlan) -> Result<(), i32> {
        let clock_id = plan.args[0];
        let ts_ptr = checked_user_ptr(plan.args[1])?;
        let now_ns = self.current_runtime_clock_ns(clock_id)?;
        self.write_timespec(ts_ptr, now_ns)
    }

    fn apply_clock_getres(&mut self, plan: LinuxPlan) -> Result<(), i32> {
        let clock_id = plan.args[0];
        if clock_id > MAX_CLOCK_ID {
            return Err(ERR_EINVAL);
        }
        if plan.args[1] == 0 {
            return Ok(());
        }
        let ts_ptr = checked_user_ptr(plan.args[1])?;
        let resolution_ns = 1_000_000_000u64 / (crate::interrupts::TIMER_HZ as u64).max(1);
        self.write_timespec(ts_ptr, resolution_ns)
    }

    fn apply_clock_adjtime(&mut self, plan: LinuxPlan) -> Result<i64, i32> {
        let clock_id = plan.args[0];
        let tx_ptr = checked_user_ptr(plan.args[1])?;
        if clock_id != CLOCK_REALTIME && clock_id != CLOCK_TAI {
            return Err(ERR_EINVAL);
        }

        let mut tx = match self.linux.read_bytes(tx_ptr, TIMEX_SIZE) {
            Ok(bytes) if bytes.len() == TIMEX_SIZE as usize => bytes,
            _ => return Err(ERR_EFAULT),
        };
        let modes = read_u32_from(&tx, 0)?;
        if modes & !SUPPORTED_MODES != 0 || modes & ADJ_MICRO != 0 && modes & ADJ_NANO != 0 {
            return Err(ERR_EINVAL);
        }
        if clock_id == CLOCK_TAI && modes != 0 {
            return Err(ERR_EINVAL);
        }
        if modes != 0 && self.current_access_state().cap_effective & CAP_SYS_TIME == 0 {
            return Err(ERR_EPERM);
        }
        validate_clock_adjtime_timex(modes, &tx)?;

        let tick = crate::interrupts::tick_count();
        let timer_hz = crate::interrupts::TIMER_HZ as u64;
        if clock_id == CLOCK_TAI {
            let state = self.clock_adj;
            write_timex_snapshot(&mut tx, modes, state, self.runtime_tai_now_ns(tick, timer_hz))?;
            if self.linux.write_bytes(tx_ptr, &tx).is_err() {
                return Err(ERR_EFAULT);
            }
            return if state.status & STA_UNSYNC != 0 { Ok(TIME_ERROR) } else { Ok(TIME_OK) };
        }

        let current_ns = self.runtime_realtime_now_ns(tick, timer_hz);
        self.set_runtime_realtime_ns(current_ns, tick);

        let mut state = self.clock_adj;
        if modes & ADJ_MICRO != 0 {
            state.nano = false;
        }
        if modes & ADJ_NANO != 0 {
            state.nano = true;
        }
        let unit_ns = if state.nano { 1i128 } else { 1_000i128 };

        let mut delta_ns = 0i128;
        if modes & ADJ_OFFSET != 0 {
            delta_ns =
                delta_ns.saturating_add((read_i64_from(&tx, 8)? as i128).saturating_mul(unit_ns));
        }
        if modes & ADJ_SETOFFSET != 0 {
            let sec = read_i64_from(&tx, 72)? as i128;
            let frac = read_i64_from(&tx, 80)? as i128;
            delta_ns = delta_ns
                .saturating_add(sec.saturating_mul(1_000_000_000))
                .saturating_add(frac.saturating_mul(setoffset_unit_ns(modes)));
        }
        if delta_ns != 0 {
            self.adjust_runtime_realtime_ns(delta_ns, tick, timer_hz);
            self.cancel_realtime_timerfds_on_clock_set();
        }

        let current_ns = self.runtime_realtime_now_ns(tick, timer_hz);
        self.set_runtime_realtime_ns(current_ns, tick);
        if modes & ADJ_FREQUENCY != 0 {
            state.freq_scaled_ppm = read_i64_from(&tx, 16)?;
        }
        if modes & ADJ_MAXERROR != 0 {
            state.maxerror_us = read_i64_from(&tx, 24)?;
        }
        if modes & ADJ_ESTERROR != 0 {
            state.esterror_us = read_i64_from(&tx, 32)?;
        }
        if modes & ADJ_STATUS != 0 {
            state.status = read_i32_from(&tx, 40)? & !STA_RONLY;
        }
        if modes & ADJ_TIMECONST != 0 {
            state.constant = read_i64_from(&tx, 48)?;
        }
        if modes & ADJ_TICK != 0 {
            state.tick_us = read_i64_from(&tx, 88)?;
        }
        if modes & ADJ_TAI != 0 {
            state.tai = read_i32_from(&tx, 160)?;
        }
        self.clock_adj = state;

        write_timex_snapshot(&mut tx, modes, state, self.runtime_realtime_now_ns(tick, timer_hz))?;
        if self.linux.write_bytes(tx_ptr, &tx).is_err() {
            return Err(ERR_EFAULT);
        }

        if state.status & STA_UNSYNC != 0 { Ok(TIME_ERROR) } else { Ok(TIME_OK) }
    }

    fn current_runtime_clock_ns(&self, clock_id: u64) -> Result<u64, i32> {
        if clock_id > MAX_CLOCK_ID {
            return Err(ERR_EINVAL);
        }
        let tick = crate::interrupts::tick_count();
        let timer_hz = crate::interrupts::TIMER_HZ as u64;
        let monotonic_ns =
            1_000_000_000u64.saturating_add(tick.saturating_mul(1_000_000_000) / timer_hz.max(1));
        match clock_id {
            CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM => {
                Ok(self.runtime_realtime_now_ns(tick, timer_hz))
            }
            CLOCK_TAI => Ok(self.runtime_tai_now_ns(tick, timer_hz)),
            _ => Ok(monotonic_ns),
        }
    }

    fn runtime_tai_now_ns(&self, tick: u64, timer_hz: u64) -> u64 {
        let realtime_ns = self.runtime_realtime_now_ns(tick, timer_hz);
        let offset_ns = self.clock_adj.tai as i128 * 1_000_000_000i128;
        if offset_ns >= 0 {
            realtime_ns.saturating_add(offset_ns as u64)
        } else {
            realtime_ns.saturating_sub((-offset_ns) as u64)
        }
    }

    fn write_timespec(&mut self, ptr: u32, ns: u64) -> Result<(), i32> {
        let mut encoded = [0u8; TIMESPEC_SIZE];
        encoded[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_le_bytes());
        encoded[8..].copy_from_slice(&((ns % 1_000_000_000) as i64).to_le_bytes());
        if self.linux.write_bytes(ptr, &encoded).is_err() {
            return Err(ERR_EFAULT);
        }
        Ok(())
    }
}

fn validate_clock_adjtime_timex(modes: u32, tx: &[u8]) -> Result<(), i32> {
    if modes & ADJ_TICK != 0 {
        let tick = read_i64_from(tx, 88)?;
        if !(ADJ_TICK_MIN_US..=ADJ_TICK_MAX_US).contains(&tick) {
            return Err(ERR_EINVAL);
        }
    }
    if modes & ADJ_SETOFFSET != 0 {
        let frac = read_i64_from(tx, 80)?;
        if frac < 0 {
            return Err(ERR_EINVAL);
        }
        let limit = if modes & ADJ_NANO != 0 { 1_000_000_000 } else { 1_000_000 };
        if frac >= limit {
            return Err(ERR_EINVAL);
        }
    }
    Ok(())
}

fn setoffset_unit_ns(modes: u32) -> i128 {
    if modes & ADJ_NANO != 0 { 1 } else { 1_000 }
}

fn checked_user_ptr(value: u64) -> Result<u32, i32> {
    match u32::try_from(value) {
        Ok(ptr) if ptr != 0 => Ok(ptr),
        _ => Err(ERR_EFAULT),
    }
}

fn write_timex_snapshot(
    tx: &mut [u8],
    modes: u32,
    state: RuntimeClockAdjustmentState,
    now_ns: u64,
) -> Result<(), i32> {
    const STA_NANO: i32 = 0x2000;
    write_u32(tx, 0, modes)?;
    write_i64(tx, 8, 0)?;
    write_i64(tx, 16, state.freq_scaled_ppm)?;
    write_i64(tx, 24, state.maxerror_us)?;
    write_i64(tx, 32, state.esterror_us)?;
    let status = if state.nano { state.status | STA_NANO } else { state.status & !STA_NANO };
    write_i32(tx, 40, status)?;
    write_i64(tx, 48, state.constant)?;
    write_i64(tx, 56, 1_000_000 / crate::interrupts::TIMER_HZ as i64)?;
    write_i64(tx, 64, 500)?;
    write_i64(tx, 72, (now_ns / 1_000_000_000) as i64)?;
    let subsec = now_ns % 1_000_000_000;
    write_i64(tx, 80, if state.nano { subsec as i64 } else { (subsec / 1_000) as i64 })?;
    write_i64(tx, 88, state.tick_us)?;
    write_i64(tx, 96, 0)?;
    write_i64(tx, 104, 0)?;
    write_i32(tx, 112, 0)?;
    write_i64(tx, 120, 0)?;
    write_i64(tx, 128, 0)?;
    write_i64(tx, 136, 0)?;
    write_i64(tx, 144, 0)?;
    write_i64(tx, 152, 0)?;
    write_i32(tx, 160, state.tai)?;
    Ok(())
}

fn read_u32_from(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    let end = offset.checked_add(4).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i32_from(bytes: &[u8], offset: usize) -> Result<i32, i32> {
    let end = offset.checked_add(4).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(i32::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i64_from(bytes: &[u8], offset: usize) -> Result<i64, i32> {
    let end = offset.checked_add(8).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(i64::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), i32> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) -> Result<(), i32> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_i64(bytes: &mut [u8], offset: usize, value: i64) -> Result<(), i32> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), i32> {
    let end = offset.checked_add(value.len()).ok_or(ERR_EINVAL)?;
    bytes.get_mut(offset..end).ok_or(ERR_EINVAL)?.copy_from_slice(value);
    Ok(())
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec::Vec};

    use visa_abi::{ERR_EINVAL, ERR_EPERM, SYS_CLOCK_ADJTIME, SyscallContext};

    use super::{
        super::{
            engine::RuntimeOnlyExecutor,
            types::{CAP_SYS_TIME, ProcessAccessState},
        },
        *,
    };

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected Ret, got {other:?}"),
        }
    }

    fn timex_with_i64(mode: u32, offset: usize, value: i64) -> Vec<u8> {
        let mut bytes = vec![0u8; TIMEX_SIZE as usize];
        bytes[0..4].copy_from_slice(&mode.to_le_bytes());
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn timex_setoffset(mode: u32, sec: i64, frac: i64) -> Vec<u8> {
        let mut bytes = vec![0u8; TIMEX_SIZE as usize];
        bytes[0..4].copy_from_slice(&mode.to_le_bytes());
        bytes[72..80].copy_from_slice(&sec.to_le_bytes());
        bytes[80..88].copy_from_slice(&frac.to_le_bytes());
        bytes
    }

    fn grant_cap_sys_time(runtime: &mut PrototypeRuntime<'_>) {
        let pid = runtime.current_pid();
        runtime.processes.iter_mut().find(|process| process.pid == pid).unwrap().access =
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                CAP_SYS_TIME,
                CAP_SYS_TIME,
            );
    }

    #[test]
    fn generic_clock_adjtime_requires_cap_sys_time_for_mutation() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        runtime.processes.iter_mut().find(|process| process.pid == pid).unwrap().access =
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                0,
                0,
            );

        let read_only = vec![0u8; TIMEX_SIZE as usize];
        let (read_ptr, _) = runtime.linux.write_arg_bytes(&read_only).expect("read timex");
        let read_result = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_read",
                SyscallContext::new(
                    SYS_CLOCK_ADJTIME,
                    [CLOCK_REALTIME, read_ptr as u64, 0, 0, 0, 0],
                ),
            )
            .expect("read-only clock_adjtime dispatch");
        assert_eq!(expect_ret(read_result), TIME_OK);

        let input = timex_with_i64(ADJ_FREQUENCY, 16, 123);
        let (tx_ptr, _) = runtime.linux.write_arg_bytes(&input).expect("mutating timex");
        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_denied",
                SyscallContext::new(SYS_CLOCK_ADJTIME, [CLOCK_REALTIME, tx_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("denied clock_adjtime dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));
        assert_eq!(runtime.clock_adj, RuntimeClockAdjustmentState::default());

        runtime.processes.iter_mut().find(|process| process.pid == pid).unwrap().access =
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                CAP_SYS_TIME,
                CAP_SYS_TIME,
            );
        let allowed = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_allowed",
                SyscallContext::new(SYS_CLOCK_ADJTIME, [CLOCK_REALTIME, tx_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("allowed clock_adjtime dispatch");
        assert_eq!(expect_ret(allowed), TIME_OK);
        assert_eq!(runtime.clock_adj.freq_scaled_ppm, 123);
    }

    #[test]
    fn generic_clock_adjtime_setoffset_uses_explicit_resolution_and_bounds_fraction() {
        let mut runtime = test_runtime();
        grant_cap_sys_time(&mut runtime);
        let tick = crate::interrupts::tick_count();
        let timer_hz = crate::interrupts::TIMER_HZ as u64;
        runtime.set_runtime_realtime_ns(2_000_000_000, tick);

        let input = timex_setoffset(ADJ_SETOFFSET, 1, 500_000);
        let (tx_ptr, _) = runtime.linux.write_arg_bytes(&input).expect("setoffset timex");
        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_setoffset_default_micro",
                SyscallContext::new(SYS_CLOCK_ADJTIME, [CLOCK_REALTIME, tx_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("clock_adjtime setoffset dispatch");
        assert_eq!(expect_ret(result), TIME_OK);
        let now = runtime.runtime_realtime_now_ns(crate::interrupts::tick_count(), timer_hz);
        assert!((3_500_000_000..3_600_000_000).contains(&now));

        for (mode, frac) in [
            (ADJ_SETOFFSET, -1),
            (ADJ_SETOFFSET, 1_000_000),
            (ADJ_SETOFFSET | ADJ_NANO, 1_000_000_000),
        ] {
            let invalid = timex_setoffset(mode, 0, frac);
            let (invalid_ptr, _) =
                runtime.linux.write_arg_bytes(&invalid).expect("invalid setoffset timex");
            let denied = runtime
                .dispatch_linux_syscall_raw(
                    "test_clock_adjtime_setoffset_invalid_fraction",
                    SyscallContext::new(
                        SYS_CLOCK_ADJTIME,
                        [CLOCK_REALTIME, invalid_ptr as u64, 0, 0, 0, 0],
                    ),
                )
                .expect("invalid clock_adjtime setoffset dispatch");
            assert_eq!(expect_ret(denied), -(ERR_EINVAL as i64));
        }
    }

    #[test]
    fn generic_clock_adjtime_tick_is_bounded_like_linux_user_hz() {
        let mut runtime = test_runtime();
        grant_cap_sys_time(&mut runtime);

        for tick in [ADJ_TICK_MIN_US - 1, ADJ_TICK_MAX_US + 1] {
            let input = timex_with_i64(ADJ_TICK, 88, tick);
            let (tx_ptr, _) = runtime.linux.write_arg_bytes(&input).expect("invalid tick timex");
            let denied = runtime
                .dispatch_linux_syscall_raw(
                    "test_clock_adjtime_bad_tick",
                    SyscallContext::new(
                        SYS_CLOCK_ADJTIME,
                        [CLOCK_REALTIME, tx_ptr as u64, 0, 0, 0, 0],
                    ),
                )
                .expect("invalid tick dispatch");
            assert_eq!(expect_ret(denied), -(ERR_EINVAL as i64));
            assert_eq!(runtime.clock_adj.tick_us, RuntimeClockAdjustmentState::default().tick_us);
        }

        let input = timex_with_i64(ADJ_TICK, 88, 10_500);
        let (tx_ptr, _) = runtime.linux.write_arg_bytes(&input).expect("valid tick timex");
        let allowed = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_good_tick",
                SyscallContext::new(SYS_CLOCK_ADJTIME, [CLOCK_REALTIME, tx_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("valid tick dispatch");
        assert_eq!(expect_ret(allowed), TIME_OK);
        assert_eq!(runtime.clock_adj.tick_us, 10_500);
    }

    #[test]
    fn generic_clock_adjtime_clock_tai_returns_read_only_snapshot() {
        let mut runtime = test_runtime();
        let tick = crate::interrupts::tick_count();
        runtime.set_runtime_realtime_ns(2_000_000_000, tick);
        runtime.clock_adj.tai = 37;

        let read_only = vec![0u8; TIMEX_SIZE as usize];
        let (read_ptr, _) = runtime.linux.write_arg_bytes(&read_only).expect("tai timex");
        let read_result = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_tai_read",
                SyscallContext::new(SYS_CLOCK_ADJTIME, [CLOCK_TAI, read_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("read-only tai clock_adjtime dispatch");
        assert_eq!(expect_ret(read_result), TIME_OK);

        let snapshot = runtime.linux.read_bytes(read_ptr, TIMEX_SIZE).expect("tai snapshot");
        assert_eq!(read_i32_from(&snapshot, 160).expect("tai field"), 37);
        assert!(read_i64_from(&snapshot, 72).expect("tai seconds") >= 39);

        let mut mutating = vec![0u8; TIMEX_SIZE as usize];
        mutating[0..4].copy_from_slice(&ADJ_TAI.to_le_bytes());
        mutating[160..164].copy_from_slice(&40i32.to_le_bytes());
        let (mutating_ptr, _) =
            runtime.linux.write_arg_bytes(&mutating).expect("mutating tai timex");
        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_clock_adjtime_tai_mutation_denied",
                SyscallContext::new(
                    SYS_CLOCK_ADJTIME,
                    [CLOCK_TAI, mutating_ptr as u64, 0, 0, 0, 0],
                ),
            )
            .expect("mutating tai clock_adjtime dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EINVAL as i64));
        assert_eq!(runtime.clock_adj.tai, 37);
    }
}
