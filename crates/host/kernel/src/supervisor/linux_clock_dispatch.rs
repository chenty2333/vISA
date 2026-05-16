use vmos_abi::{ERR_EFAULT, ERR_EINVAL};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::RuntimeClockAdjustmentState,
};

const CLOCK_REALTIME: u64 = 0;
const TIMEX_SIZE: u32 = 208;
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
    pub(super) fn plan_clock_adjtime(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_clock_adjtime(plan) {
            Ok(ret) => Ok(LinuxCallResult::Ret(ret)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    fn apply_clock_adjtime(&mut self, plan: LinuxPlan) -> Result<i64, i32> {
        let clock_id = plan.args[0];
        let tx_ptr = match u32::try_from(plan.args[1]) {
            Ok(ptr) if ptr != 0 => ptr,
            _ => return Err(ERR_EFAULT),
        };
        if clock_id != CLOCK_REALTIME {
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

        let tick = crate::interrupts::tick_count();
        let timer_hz = crate::interrupts::TIMER_HZ as u64;
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
                .saturating_add(frac.saturating_mul(unit_ns));
        }
        if delta_ns != 0 {
            self.adjust_runtime_realtime_ns(delta_ns, tick, timer_hz);
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
