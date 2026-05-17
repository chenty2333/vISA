use vmos_abi::{ERR_EBADF, ERR_ECANCELED, ERR_EFAULT, ERR_EINVAL};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

const ITIMERSPEC_SIZE: usize = 32;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_timerfd_create(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let clock_id = plan.args[0];
        let flags = match u32::try_from(plan.args[1]) {
            Ok(flags) => flags,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        match self.create_timerfd(clock_id, flags) {
            Ok(fd) => Ok(LinuxCallResult::Ret(fd as i64)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_timerfd_settime(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(errno_ret(ERR_EBADF)),
        };
        let flags = match u32::try_from(plan.args[1]) {
            Ok(flags) => flags,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let new_ptr = match checked_user_ptr(plan.args[2]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let bytes = match self.linux.read_bytes(new_ptr, ITIMERSPEC_SIZE as u32) {
            Ok(bytes) if bytes.len() == ITIMERSPEC_SIZE => bytes,
            _ => return Ok(errno_ret(ERR_EFAULT)),
        };
        let (value_ns, interval_ns) = match decode_itimerspec_ns(&bytes) {
            Ok(decoded) => decoded,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        match self.timerfd_settime(fd, flags, value_ns, interval_ns) {
            Ok((old_value_ns, old_interval_ns, was_canceled)) => {
                if plan.args[3] != 0 {
                    let old_ptr = match checked_user_ptr(plan.args[3]) {
                        Ok(ptr) => ptr,
                        Err(errno) => return Ok(errno_ret(errno)),
                    };
                    let old = encode_itimerspec_ns(old_value_ns, old_interval_ns);
                    if self.linux.write_bytes(old_ptr, &old).is_err() {
                        return Ok(errno_ret(ERR_EFAULT));
                    }
                }
                if was_canceled {
                    return Ok(errno_ret(ERR_ECANCELED));
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_timerfd_gettime(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(errno_ret(ERR_EBADF)),
        };
        let curr_ptr = match checked_user_ptr(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        match self.timerfd_gettime(fd) {
            Ok((value_ns, interval_ns)) => {
                let current = encode_itimerspec_ns(value_ns, interval_ns);
                if self.linux.write_bytes(curr_ptr, &current).is_err() {
                    return Ok(errno_ret(ERR_EFAULT));
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(errno) => Ok(errno_ret(errno)),
        }
    }
}

fn checked_user_ptr(value: u64) -> Result<u32, i32> {
    match u32::try_from(value) {
        Ok(ptr) if ptr != 0 => Ok(ptr),
        _ => Err(ERR_EFAULT),
    }
}

fn decode_itimerspec_ns(bytes: &[u8]) -> Result<(u64, u64), i32> {
    let interval_ns = decode_timespec_ns(bytes, 0)?;
    let value_ns = decode_timespec_ns(bytes, 16)?;
    Ok((value_ns, interval_ns))
}

fn decode_timespec_ns(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    let sec = read_i64_from(bytes, offset)?;
    let nsec = read_i64_from(bytes, offset + 8)?;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(ERR_EINVAL);
    }
    Ok((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
}

fn encode_itimerspec_ns(value_ns: u64, interval_ns: u64) -> [u8; ITIMERSPEC_SIZE] {
    let mut out = [0u8; ITIMERSPEC_SIZE];
    write_timespec_ns(&mut out, 0, interval_ns);
    write_timespec_ns(&mut out, 16, value_ns);
    out
}

fn write_timespec_ns(out: &mut [u8], offset: usize, ns: u64) {
    let sec = (ns / 1_000_000_000) as i64;
    let nsec = (ns % 1_000_000_000) as i64;
    out[offset..offset + 8].copy_from_slice(&sec.to_le_bytes());
    out[offset + 8..offset + 16].copy_from_slice(&nsec.to_le_bytes());
}

fn read_i64_from(bytes: &[u8], offset: usize) -> Result<i64, i32> {
    let end = offset.checked_add(8).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(i64::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
