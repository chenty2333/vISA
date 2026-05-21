use alloc::vec::Vec;

use vmos_abi::{ERR_EBADF, ERR_EEXIST, ERR_EINVAL, ERR_ENOMEM, ERR_ENOSYS, ERR_EOPNOTSUPP};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{
        CAP_IPC_LOCK, GenericLockedMmapRange, GenericMmapRegion, RLIMIT_AS, RLIMIT_MEMLOCK,
        RLIMIT_NOFILE,
    },
};

const PAGE_SIZE: u64 = 4096;
const GENERIC_MMAP_ALLOC_BASE: u64 = 0x2000_0000;
const GENERIC_MMAP_ALLOC_LIMIT: u64 = 0x3000_0000;
const GENERIC_USER_MIN: u64 = 0x0001_0000;
const GENERIC_USER_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;
const MCL_CURRENT: u64 = 0x1;
const MCL_FUTURE: u64 = 0x2;
const MCL_ONFAULT: u64 = 0x4;
const MLOCK_ONFAULT: u64 = 0x1;
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
        match self.apply_generic_mmap(
            plan.args[0],
            plan.args[1],
            plan.args[2],
            plan.args[3],
            plan.args[4],
            plan.args[5],
        ) {
            Ok(addr) => Ok(LinuxCallResult::Ret(addr as i64)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_munmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        match self.apply_generic_munmap(plan.args[0], plan.args[1]) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_mlock(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        match self.apply_generic_mlock(plan.args[0], plan.args[1], plan.args[2]) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_munlock(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_generic_munlock(plan.args[0], plan.args[1]) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_mlockall(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.apply_generic_mlockall(plan.args[0]) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    pub(super) fn plan_munlockall(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid = self.current_pid();
        self.remove_generic_locked_mmap_ranges(pid, 0, GENERIC_USER_LIMIT);
        self.generic_mlock_future_pids.retain(|future_pid| *future_pid != pid);
        Ok(LinuxCallResult::Ret(0))
    }

    fn apply_generic_mmap(
        &mut self,
        hint: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> Result<u64, i32> {
        let len = align_page(len).ok_or(ERR_EINVAL)?;
        if len == 0 {
            return Err(ERR_EINVAL);
        }
        let shared = flags & MAP_SHARED != 0;
        let private = flags & MAP_PRIVATE != 0;
        if shared == private {
            return Err(ERR_EINVAL);
        }
        let anonymous = flags & MAP_ANONYMOUS != 0;
        if !anonymous {
            if offset & (PAGE_SIZE - 1) != 0 {
                return Err(ERR_EINVAL);
            }
            if u32::try_from(fd).is_err() {
                return Err(ERR_EBADF);
            }
            return Err(ERR_EOPNOTSUPP);
        }

        let pid = self.current_pid();
        let fixed = flags & MAP_FIXED != 0;
        let fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;
        let fixed_address = fixed || fixed_noreplace;
        let addr = if fixed_address {
            validate_generic_fixed_range(hint, len)?;
            hint
        } else {
            self.allocate_generic_mmap_addr(pid, hint, len)?
        };
        let end = checked_range_end(addr, len).ok_or(ERR_EINVAL)?;

        let overlap = self.generic_mmap_overlap_bytes(pid, addr, end);
        if fixed_noreplace && overlap != 0 {
            return Err(ERR_EEXIST);
        }
        let mapped_after = self
            .generic_mmap_mapped_bytes(pid)
            .saturating_sub(overlap)
            .checked_add(len)
            .ok_or(ERR_ENOMEM)?;
        let as_limit = self.get_rlimit(pid, RLIMIT_AS).cur;
        if as_limit != u64::MAX && mapped_after > as_limit {
            return Err(ERR_ENOMEM);
        }
        if self.generic_mlock_future_enabled(pid) {
            self.enforce_generic_memlock_limit_for_replacement(
                pid,
                fixed.then_some((addr, end)),
                &[(addr, end)],
            )?;
        }

        if fixed {
            self.remove_generic_mmap_range(pid, addr, end);
        }
        let (readable, writable, executable) = prot_user_region_permissions(prot);
        self.generic_mmap_regions.push(GenericMmapRegion {
            pid,
            start: addr,
            end,
            readable,
            writable,
            executable,
        });
        self.record_guest_memory_region(addr, len, readable, writable, executable);
        if self.generic_mlock_future_enabled(pid) {
            self.insert_generic_locked_mmap_range(pid, addr, end);
        }
        Ok(addr)
    }

    fn apply_generic_munmap(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        if addr & (PAGE_SIZE - 1) != 0 {
            return Err(ERR_EINVAL);
        }
        let len = align_page(len).ok_or(ERR_EINVAL)?;
        if len == 0 {
            return Err(ERR_EINVAL);
        }
        let end = checked_range_end(addr, len).ok_or(ERR_EINVAL)?;
        if !generic_munmap_range_valid(addr, end) {
            return Err(ERR_EINVAL);
        }
        self.remove_generic_mmap_range(self.current_pid(), addr, end);
        Ok(())
    }

    fn apply_generic_mlock(&mut self, addr: u64, len: u64, flags: u64) -> Result<(), i32> {
        if flags & !MLOCK_ONFAULT != 0 {
            return Err(ERR_EINVAL);
        }
        if flags & MLOCK_ONFAULT != 0 {
            return Err(ERR_ENOSYS);
        }
        let Some((start, end)) = page_rounded_lock_range(addr, len)? else {
            return Ok(());
        };
        let pid = self.current_pid();
        self.validate_generic_mapped_range(pid, start, end)?;
        self.enforce_generic_memlock_limit(pid, &[(start, end)])?;
        self.insert_generic_locked_mmap_range(pid, start, end);
        Ok(())
    }

    fn apply_generic_munlock(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        let Some((start, end)) = page_rounded_lock_range(addr, len)? else {
            return Ok(());
        };
        let pid = self.current_pid();
        self.validate_generic_mapped_range(pid, start, end)?;
        self.remove_generic_locked_mmap_ranges(pid, start, end);
        Ok(())
    }

    fn apply_generic_mlockall(&mut self, flags: u64) -> Result<(), i32> {
        if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
            return Err(ERR_EINVAL);
        }
        if flags & MCL_ONFAULT != 0 {
            return Err(ERR_ENOSYS);
        }
        let pid = self.current_pid();
        if flags & MCL_CURRENT != 0 {
            let ranges = self
                .generic_mmap_regions
                .iter()
                .filter(|region| region.pid == pid)
                .map(|region| (region.start, region.end))
                .collect::<Vec<_>>();
            self.enforce_generic_memlock_limit(pid, &ranges)?;
            for (start, end) in ranges {
                self.insert_generic_locked_mmap_range(pid, start, end);
            }
        }
        if flags & MCL_FUTURE != 0 && !self.generic_mlock_future_enabled(pid) {
            self.generic_mlock_future_pids.push(pid);
        }
        Ok(())
    }

    pub(super) fn plan_poll(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let nfds = match usize::try_from(plan.args[1]) {
            Ok(nfds) => nfds,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let nofile = self.get_rlimit(self.current_pid(), RLIMIT_NOFILE).cur;
        if !poll_nfds_within_rlimit(nfds, nofile) {
            return Ok(errno_ret(ERR_EINVAL));
        }
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

    fn allocate_generic_mmap_addr(&mut self, pid: u32, hint: u64, len: u64) -> Result<u64, i32> {
        if hint != 0
            && hint & (PAGE_SIZE - 1) == 0
            && checked_range_end(hint, len).is_some_and(|end| {
                generic_user_range_valid(hint, end)
                    && self.generic_mmap_range_is_free(pid, hint, end)
            })
        {
            return Ok(hint);
        }

        let cursor = if self.generic_mmap_cursor < GENERIC_MMAP_ALLOC_BASE {
            GENERIC_MMAP_ALLOC_BASE
        } else {
            align_page(self.generic_mmap_cursor).ok_or(ERR_ENOMEM)?
        };
        let addr = self
            .find_generic_mmap_gap(pid, cursor, len)
            .or_else(|| self.find_generic_mmap_gap(pid, GENERIC_MMAP_ALLOC_BASE, len))
            .ok_or(ERR_ENOMEM)?;
        self.generic_mmap_cursor = checked_range_end(addr, len).unwrap_or(GENERIC_MMAP_ALLOC_BASE);
        if self.generic_mmap_cursor >= GENERIC_MMAP_ALLOC_LIMIT {
            self.generic_mmap_cursor = GENERIC_MMAP_ALLOC_BASE;
        }
        Ok(addr)
    }

    fn find_generic_mmap_gap(&self, pid: u32, start: u64, len: u64) -> Option<u64> {
        let mut ranges: Vec<(u64, u64)> = self
            .generic_mmap_regions
            .iter()
            .filter(|region| region.pid == pid)
            .map(|region| (region.start, region.end))
            .collect();
        ranges.sort_by_key(|range| range.0);

        let mut cursor = core::cmp::max(align_page(start)?, GENERIC_MMAP_ALLOC_BASE);
        for (region_start, region_end) in ranges {
            if region_end <= cursor {
                continue;
            }
            if cursor.checked_add(len)? <= region_start {
                return Some(cursor);
            }
            cursor = align_page(region_end)?;
            if cursor >= GENERIC_MMAP_ALLOC_LIMIT {
                return None;
            }
        }
        if cursor.checked_add(len)? <= GENERIC_MMAP_ALLOC_LIMIT { Some(cursor) } else { None }
    }

    fn generic_mmap_range_is_free(&self, pid: u32, start: u64, end: u64) -> bool {
        self.generic_mmap_regions
            .iter()
            .filter(|region| region.pid == pid)
            .all(|region| region.end <= start || end <= region.start)
    }

    fn generic_mmap_mapped_bytes(&self, pid: u32) -> u64 {
        self.generic_mmap_regions
            .iter()
            .filter(|region| region.pid == pid)
            .map(|region| region.end.saturating_sub(region.start))
            .sum()
    }

    fn generic_mmap_overlap_bytes(&self, pid: u32, start: u64, end: u64) -> u64 {
        self.generic_mmap_regions
            .iter()
            .filter(|region| region.pid == pid)
            .map(|region| overlap_len(start, end, region.start, region.end))
            .sum()
    }

    fn remove_generic_mmap_range(&mut self, pid: u32, start: u64, end: u64) -> u64 {
        let mut next = Vec::new();
        let mut removed = 0u64;
        for region in core::mem::take(&mut self.generic_mmap_regions) {
            if region.pid != pid || region.end <= start || end <= region.start {
                next.push(region);
                continue;
            }

            let remove_start = core::cmp::max(start, region.start);
            let remove_end = core::cmp::min(end, region.end);
            let remove_len = remove_end.saturating_sub(remove_start);
            if remove_len != 0 {
                self.record_guest_memory_unmap(remove_start, remove_len);
                self.remove_generic_locked_mmap_ranges(pid, remove_start, remove_end);
                removed = removed.saturating_add(remove_len);
            }
            if region.start < remove_start {
                next.push(GenericMmapRegion { end: remove_start, ..region });
            }
            if remove_end < region.end {
                next.push(GenericMmapRegion { start: remove_end, ..region });
            }
        }
        self.generic_mmap_regions = next;
        removed
    }

    fn validate_generic_mapped_range(&self, pid: u32, start: u64, end: u64) -> Result<(), i32> {
        if start >= end || end > GENERIC_USER_LIMIT {
            return Err(ERR_EINVAL);
        }
        let mut ranges = self
            .generic_mmap_regions
            .iter()
            .filter(|region| region.pid == pid)
            .map(|region| (region.start, region.end))
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| (range.0, range.1));
        let mut cursor = start;
        for (range_start, range_end) in ranges {
            if range_end <= cursor {
                continue;
            }
            if range_start > cursor {
                return Err(ERR_ENOMEM);
            }
            cursor = cursor.max(range_end);
            if cursor >= end {
                return Ok(());
            }
        }
        Err(ERR_ENOMEM)
    }

    fn generic_mlock_future_enabled(&self, pid: u32) -> bool {
        self.generic_mlock_future_pids.iter().any(|future_pid| *future_pid == pid)
    }

    fn enforce_generic_memlock_limit(&self, pid: u32, ranges: &[(u64, u64)]) -> Result<(), i32> {
        self.enforce_generic_memlock_limit_for_replacement(pid, None, ranges)
    }

    fn enforce_generic_memlock_limit_for_replacement(
        &self,
        pid: u32,
        removed: Option<(u64, u64)>,
        ranges: &[(u64, u64)],
    ) -> Result<(), i32> {
        if self.current_access_state().cap_effective & CAP_IPC_LOCK != 0 {
            return Ok(());
        }
        let mut locked = self
            .generic_locked_mmap_ranges
            .iter()
            .filter(|range| range.pid == pid)
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>();
        if let Some((start, end)) = removed {
            remove_plain_ranges(&mut locked, start, end);
        }
        for (start, end) in ranges {
            insert_plain_range(&mut locked, *start, *end);
        }
        let locked_bytes = plain_ranges_total_len(&locked);
        let limit = self.get_rlimit(pid, RLIMIT_MEMLOCK).cur;
        if limit != u64::MAX && locked_bytes > limit {
            return Err(ERR_ENOMEM);
        }
        Ok(())
    }

    fn insert_generic_locked_mmap_range(&mut self, pid: u32, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut ranges = self
            .generic_locked_mmap_ranges
            .iter()
            .filter(|range| range.pid == pid)
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>();
        insert_plain_range(&mut ranges, start, end);
        self.generic_locked_mmap_ranges.retain(|range| range.pid != pid);
        self.generic_locked_mmap_ranges.extend(
            ranges.into_iter().map(|(start, end)| GenericLockedMmapRange { pid, start, end }),
        );
    }

    fn remove_generic_locked_mmap_ranges(&mut self, pid: u32, start: u64, end: u64) {
        let mut ranges = self
            .generic_locked_mmap_ranges
            .iter()
            .filter(|range| range.pid == pid)
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>();
        remove_plain_ranges(&mut ranges, start, end);
        self.generic_locked_mmap_ranges.retain(|range| range.pid != pid);
        self.generic_locked_mmap_ranges.extend(
            ranges.into_iter().map(|(start, end)| GenericLockedMmapRange { pid, start, end }),
        );
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

fn align_page(len: u64) -> Option<u64> {
    len.checked_add(PAGE_SIZE - 1).map(|value| value & !(PAGE_SIZE - 1))
}

fn page_rounded_lock_range(addr: u64, len: u64) -> Result<Option<(u64, u64)>, i32> {
    if len == 0 {
        return Ok(None);
    }
    let start = addr & !(PAGE_SIZE - 1);
    let raw_end = addr.checked_add(len).ok_or(ERR_EINVAL)?;
    let end = align_page(raw_end).ok_or(ERR_EINVAL)?;
    if !generic_user_range_valid(start, end) {
        return Err(ERR_ENOMEM);
    }
    Ok(Some((start, end)))
}

fn checked_range_end(start: u64, len: u64) -> Option<u64> {
    start.checked_add(len)
}

fn validate_generic_fixed_range(start: u64, len: u64) -> Result<(), i32> {
    if start == 0 || start & (PAGE_SIZE - 1) != 0 {
        return Err(ERR_EINVAL);
    }
    let end = checked_range_end(start, len).ok_or(ERR_EINVAL)?;
    if generic_user_range_valid(start, end) { Ok(()) } else { Err(ERR_EINVAL) }
}

fn generic_user_range_valid(start: u64, end: u64) -> bool {
    start >= GENERIC_USER_MIN && start < end && end <= GENERIC_USER_LIMIT
}

fn generic_munmap_range_valid(start: u64, end: u64) -> bool {
    start < end && end <= GENERIC_USER_LIMIT
}

fn overlap_len(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> u64 {
    let start = core::cmp::max(left_start, right_start);
    let end = core::cmp::min(left_end, right_end);
    end.saturating_sub(start)
}

fn plain_ranges_total_len(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().map(|(start, end)| end.saturating_sub(*start)).sum()
}

fn insert_plain_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    ranges.push((start, end));
    ranges.sort_by_key(|range| (range.0, range.1));
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (range_start, range_end) in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range_start <= last.1
        {
            last.1 = last.1.max(range_end);
            continue;
        }
        merged.push((range_start, range_end));
    }
    *ranges = merged;
}

fn remove_plain_ranges(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let mut next = Vec::with_capacity(ranges.len().saturating_add(1));
    for (range_start, range_end) in ranges.drain(..) {
        if range_end <= start || end <= range_start {
            next.push((range_start, range_end));
            continue;
        }
        if range_start < start {
            next.push((range_start, start));
        }
        if end < range_end {
            next.push((end, range_end));
        }
    }
    *ranges = next;
}

fn poll_timeout_ms(timeout_arg: u64) -> Option<u32> {
    let timeout = timeout_arg as i32;
    if timeout < 0 { None } else { Some(timeout as u32) }
}

fn poll_nfds_within_rlimit(nfds: usize, nofile: u64) -> bool {
    u64::try_from(nfds).is_ok_and(|nfds| nfds <= nofile)
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use vmos_abi::{
        ERR_ENOMEM, SYS_MLOCK, SYS_MLOCKALL, SYS_MMAP, SYS_MUNLOCK, SYS_MUNLOCKALL, SyscallContext,
    };

    use super::{
        super::{engine::RuntimeOnlyExecutor, types::Rlimit},
        *,
    };

    #[test]
    fn poll_nfds_honors_rlimit_nofile_boundary() {
        assert!(poll_nfds_within_rlimit(0, 0));
        assert!(poll_nfds_within_rlimit(1024, 1024));
        assert!(!poll_nfds_within_rlimit(1025, 1024));
    }

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

    #[test]
    fn generic_mlock_honors_rlimit_memlock_and_munlock_releases() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let process = runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == pid)
            .expect("current process");
        process.access.cap_effective = 0;
        process.access.cap_permitted = 0;
        assert!(runtime.set_rlimit(pid, RLIMIT_MEMLOCK, Rlimit { cur: 4096, max: 4096 }));

        let mapped = runtime
            .dispatch_linux_syscall_raw(
                "test_mmap_for_mlock",
                SyscallContext::new(
                    SYS_MMAP,
                    [0, 8192, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                ),
            )
            .expect("mmap dispatch");
        let addr = expect_ret(mapped) as u64;

        let first_lock = runtime
            .dispatch_linux_syscall_raw(
                "test_mlock_first_page",
                SyscallContext::new(SYS_MLOCK, [addr, 4096, 0, 0, 0, 0]),
            )
            .expect("first mlock dispatch");
        assert_eq!(expect_ret(first_lock), 0);

        let second_lock = runtime
            .dispatch_linux_syscall_raw(
                "test_mlock_second_page_denied",
                SyscallContext::new(SYS_MLOCK, [addr + 4096, 4096, 0, 0, 0, 0]),
            )
            .expect("second mlock dispatch");
        assert_eq!(expect_ret(second_lock), -(ERR_ENOMEM as i64));

        let unlock = runtime
            .dispatch_linux_syscall_raw(
                "test_munlock_first_page",
                SyscallContext::new(SYS_MUNLOCK, [addr, 4096, 0, 0, 0, 0]),
            )
            .expect("munlock dispatch");
        assert_eq!(expect_ret(unlock), 0);

        let second_lock = runtime
            .dispatch_linux_syscall_raw(
                "test_mlock_second_page_allowed_after_unlock",
                SyscallContext::new(SYS_MLOCK, [addr + 4096, 4096, 0, 0, 0, 0]),
            )
            .expect("second mlock retry dispatch");
        assert_eq!(expect_ret(second_lock), 0);
    }

    #[test]
    fn generic_mlockall_future_bounds_later_mmap_until_munlockall() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let process = runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == pid)
            .expect("current process");
        process.access.cap_effective = 0;
        process.access.cap_permitted = 0;
        assert!(runtime.set_rlimit(pid, RLIMIT_MEMLOCK, Rlimit { cur: 4096, max: 4096 }));

        let future = runtime
            .dispatch_linux_syscall_raw(
                "test_mlockall_future",
                SyscallContext::new(SYS_MLOCKALL, [MCL_FUTURE, 0, 0, 0, 0, 0]),
            )
            .expect("mlockall dispatch");
        assert_eq!(expect_ret(future), 0);

        let too_large = runtime
            .dispatch_linux_syscall_raw(
                "test_future_locked_mmap_denied",
                SyscallContext::new(
                    SYS_MMAP,
                    [0, 8192, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                ),
            )
            .expect("future mmap dispatch");
        assert_eq!(expect_ret(too_large), -(ERR_ENOMEM as i64));

        let unlock_all = runtime
            .dispatch_linux_syscall_raw(
                "test_munlockall_clears_future",
                SyscallContext::new(SYS_MUNLOCKALL, [0, 0, 0, 0, 0, 0]),
            )
            .expect("munlockall dispatch");
        assert_eq!(expect_ret(unlock_all), 0);

        let mapped = runtime
            .dispatch_linux_syscall_raw(
                "test_unlocked_mmap_after_munlockall",
                SyscallContext::new(
                    SYS_MMAP,
                    [0, 8192, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
                ),
            )
            .expect("post munlockall mmap dispatch");
        assert!(expect_ret(mapped) > 0);
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
