use alloc::vec::Vec;

use vmos_abi::{ERR_EBADF, ERR_EINVAL, ERR_ENOSYS};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

const POLLFD_SIZE: usize = 8;
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLNVAL: u16 = 0x020;
const POLLRDNORM: u16 = 0x040;
const POLLWRNORM: u16 = 0x100;
const POLLRDHUP: u16 = 0x2000;
const POLL_READ_EVENTS: u16 = POLLIN | POLLRDNORM;
const POLL_WRITE_EVENTS: u16 = POLLOUT | POLLWRNORM;
const FDSET_WORDS: usize = 16;
const MAX_FDSET_FDS: usize = FDSET_WORDS * 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PollFdEntry {
    fd: i32,
    events: u16,
    revents: u16,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_mmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let addr = plan.args[0];
        let len = plan.args[1];
        let prot = plan.args[2];
        let (readable, writable, executable) = prot_user_region_permissions(prot);
        self.record_guest_memory_region(addr, len, readable, writable, executable);
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_munmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        self.record_guest_memory_unmap(plan.args[0], plan.args[1]);
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_poll(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let nfds = match usize::try_from(plan.args[1]) {
            Ok(nfds) => nfds,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let timeout_ms = poll_timeout_ms(plan.args[2]);
        if nfds == 0 {
            if timeout_ms != Some(0) {
                if let Err(errno) = self.block_on_fdset_wait(
                    [0; FDSET_WORDS],
                    [0; FDSET_WORDS],
                    [0; FDSET_WORDS],
                    0,
                    timeout_ms,
                ) {
                    return Ok(errno_ret(errno));
                }
            }
            return Ok(LinuxCallResult::Ret(0));
        }

        let ptr = match u32::try_from(plan.args[0]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let mut entries = match self.read_pollfds(ptr, nfds) {
            Ok(entries) => entries,
            Err(errno) => return Ok(errno_ret(errno)),
        };

        let ready = match self.collect_poll_revents(&mut entries) {
            Ok(ready) => ready,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if ready != 0 || timeout_ms == Some(0) {
            return self.write_pollfds(ptr, &entries, ready);
        }

        let (read_bits, write_bits, error_bits, wait_nfds) = match poll_wait_bits(&entries) {
            Ok(bits) => bits,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if let Err(errno) =
            self.block_on_fdset_wait(read_bits, write_bits, error_bits, wait_nfds, timeout_ms)
        {
            return Ok(errno_ret(errno));
        }

        let ready = match self.collect_poll_revents(&mut entries) {
            Ok(ready) => ready,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        self.write_pollfds(ptr, &entries, ready)
    }

    fn read_pollfds(&mut self, ptr: u32, nfds: usize) -> Result<Vec<PollFdEntry>, i32> {
        let len = nfds.checked_mul(POLLFD_SIZE).ok_or(ERR_EINVAL)?;
        let len_u32 = u32::try_from(len).map_err(|_| ERR_EINVAL)?;
        let bytes = self.linux.read_bytes(ptr, len_u32).map_err(|_| ERR_EINVAL)?;
        let mut entries = Vec::new();
        for index in 0..nfds {
            let offset = index * POLLFD_SIZE;
            let fd =
                i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?);
            let events = u16::from_le_bytes(
                bytes[offset + 4..offset + 6].try_into().map_err(|_| ERR_EINVAL)?,
            );
            entries.push(PollFdEntry { fd, events, revents: 0 });
        }
        Ok(entries)
    }

    fn collect_poll_revents(&mut self, entries: &mut [PollFdEntry]) -> Result<i64, i32> {
        let mut ready = 0i64;
        for entry in entries {
            entry.revents = if entry.fd < 0 {
                0
            } else {
                match self.fd_poll_revents(entry.fd as u32, entry.events) {
                    Ok(revents) => revents,
                    Err(ERR_EBADF) => POLLNVAL,
                    Err(errno) => return Err(errno),
                }
            };
            if entry.revents != 0 {
                ready += 1;
            }
        }
        Ok(ready)
    }

    fn write_pollfds(
        &mut self,
        ptr: u32,
        entries: &[PollFdEntry],
        ready: i64,
    ) -> Result<LinuxCallResult, &'static str> {
        let bytes = encode_pollfds(entries).map_err(|_| "pollfd output overflowed")?;
        if !bytes.is_empty() && self.linux.write_bytes(ptr, &bytes).is_err() {
            return Ok(errno_ret(ERR_EINVAL));
        }
        Ok(LinuxCallResult::Ret(ready))
    }
}

fn prot_user_region_permissions(prot: u64) -> (bool, bool, bool) {
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;

    let writable = prot & PROT_WRITE != 0;
    let readable = writable || prot & PROT_READ != 0;
    let executable = prot & PROT_EXEC != 0;
    (readable, writable, executable)
}

fn poll_timeout_ms(timeout_arg: u64) -> Option<u32> {
    let timeout = timeout_arg as i32;
    if timeout < 0 { None } else { Some(timeout as u32) }
}

fn poll_wait_bits(
    entries: &[PollFdEntry],
) -> Result<([u64; FDSET_WORDS], [u64; FDSET_WORDS], [u64; FDSET_WORDS], u16), i32> {
    let mut read_bits = [0u64; FDSET_WORDS];
    let mut write_bits = [0u64; FDSET_WORDS];
    let mut error_bits = [0u64; FDSET_WORDS];
    let mut wait_nfds = 0usize;
    for entry in entries {
        if entry.fd < 0 {
            continue;
        }
        let fd = usize::try_from(entry.fd).map_err(|_| ERR_EINVAL)?;
        if fd >= MAX_FDSET_FDS {
            return Err(ERR_ENOSYS);
        }
        set_fd_bit(&mut error_bits, fd);
        if entry.events & (POLL_READ_EVENTS | POLLRDHUP) != 0 {
            set_fd_bit(&mut read_bits, fd);
        }
        if entry.events & POLL_WRITE_EVENTS != 0 {
            set_fd_bit(&mut write_bits, fd);
        }
        wait_nfds = core::cmp::max(wait_nfds, fd + 1);
    }
    Ok((read_bits, write_bits, error_bits, u16::try_from(wait_nfds).map_err(|_| ERR_EINVAL)?))
}

fn set_fd_bit(bits: &mut [u64; FDSET_WORDS], fd: usize) {
    bits[fd / 64] |= 1u64 << (fd % 64);
}

fn encode_pollfds(entries: &[PollFdEntry]) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    out.try_reserve(entries.len().checked_mul(POLLFD_SIZE).ok_or(ERR_EINVAL)?)
        .map_err(|_| ERR_EINVAL)?;
    for entry in entries {
        out.extend_from_slice(&entry.fd.to_le_bytes());
        out.extend_from_slice(&entry.events.to_le_bytes());
        out.extend_from_slice(&entry.revents.to_le_bytes());
    }
    Ok(out)
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
