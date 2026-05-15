use alloc::vec::Vec;
use core::ptr::null_mut;

use crate::{
    substrate::ring3::UserReturnContext,
    supervisor::{
        PrototypeRuntime, TaskId,
        types::{CAP_SETGID, CAP_SETUID, FdTableSnapshot, LINUX_KNOWN_CAPS},
    },
};

#[derive(Clone, Copy)]
pub(crate) struct UserRegion {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) writable: bool,
}

pub(crate) struct LoadedUserImage {
    pub(crate) entry: u64,
    pub(crate) stack_top: u64,
    pub(crate) regions: Vec<UserRegion>,
}

#[derive(Clone, Copy)]
pub(crate) struct ClockAdjustmentState {
    pub(crate) freq_scaled_ppm: i64,
    pub(crate) maxerror_us: i64,
    pub(crate) esterror_us: i64,
    pub(crate) status: i32,
    pub(crate) constant: i64,
    pub(crate) tick_us: i64,
    pub(crate) tai: i32,
    pub(crate) nano: bool,
}

pub(crate) struct ActiveUserContext {
    pub(crate) supervisor: &'static mut PrototypeRuntime<'static>,
    pub(crate) regions: Vec<UserRegion>,
    pub(crate) task_id: TaskId,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) activation_id: u64,
    cwd: Vec<u8>,
    brk_base: u64,
    brk_current: u64,
    brk_end: u64,
    mmap_cursor: u64,
    mmap_end: u64,
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    supplementary_groups: Vec<u32>,
    cap_bounding: u64,
    cap_inheritable: u64,
    cap_permitted: u64,
    cap_effective: u64,
    cap_ambient: u64,
    io_owner: i64,
    io_owner_ex_type: u32,
    io_owner_ex_pid: i32,
    io_signal: u32,
    pending_io_signal: Option<u32>,
    next_activation_id: u64,
    alarm_seconds: u64,
    realtime_epoch_ns: u64,
    realtime_epoch_tick: u64,
    clock_adj: ClockAdjustmentState,
    physical_memory_offset: u64,
    suspended_vfork_parent: Option<SuspendedVforkParent>,
    suspended_clone_parent: Option<SuspendedCloneParent>,
}

pub(crate) struct SuspendedVforkParent {
    pub(crate) task_id: TaskId,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) child_pid: u32,
    pub(crate) next_activation_id: u64,
    pub(crate) return_context: UserReturnContext,
    cwd: Vec<u8>,
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    supplementary_groups: Vec<u32>,
    cap_bounding: u64,
    cap_inheritable: u64,
    cap_permitted: u64,
    cap_effective: u64,
    cap_ambient: u64,
    io_owner: i64,
    io_owner_ex_type: u32,
    io_owner_ex_pid: i32,
    io_signal: u32,
    pending_io_signal: Option<u32>,
    alarm_seconds: u64,
    realtime_epoch_ns: u64,
    realtime_epoch_tick: u64,
    clock_adj: ClockAdjustmentState,
}

pub(crate) struct SuspendedCloneParent {
    pub(crate) task_id: TaskId,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) child_pid: u32,
    pub(crate) next_activation_id: u64,
    pub(crate) return_context: UserReturnContext,
    fs_shared: bool,
    cwd: Vec<u8>,
    files_shared: bool,
    fd_snapshot: Option<FdTableSnapshot>,
    credential: CredentialState,
    io_owner: i64,
    io_owner_ex_type: u32,
    io_owner_ex_pid: i32,
    io_signal: u32,
    pending_io_signal: Option<u32>,
    alarm_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct CredentialState {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) suid: u32,
    pub(crate) sgid: u32,
    pub(crate) supplementary_groups: Vec<u32>,
    pub(crate) cap_bounding: u64,
    pub(crate) cap_inheritable: u64,
    pub(crate) cap_permitted: u64,
    pub(crate) cap_effective: u64,
    pub(crate) cap_ambient: u64,
}

static mut ACTIVE_CONTEXT: *mut ActiveUserContext = null_mut();

impl ActiveUserContext {
    pub(crate) fn new(
        supervisor: &'static mut PrototypeRuntime<'static>,
        regions: Vec<UserRegion>,
        task_id: TaskId,
        pid: u32,
        tid: u32,
        brk_base: u64,
        brk_end: u64,
        mmap_base: u64,
        mmap_end: u64,
        physical_memory_offset: u64,
    ) -> Self {
        Self {
            supervisor,
            regions,
            task_id,
            pid,
            tid,
            activation_id: 0,
            cwd: b"/tmp".to_vec(),
            brk_base,
            brk_current: brk_base,
            brk_end,
            mmap_cursor: mmap_base,
            mmap_end,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            supplementary_groups: Vec::new(),
            cap_bounding: LINUX_KNOWN_CAPS,
            cap_inheritable: 0,
            cap_permitted: LINUX_KNOWN_CAPS,
            cap_effective: LINUX_KNOWN_CAPS,
            cap_ambient: 0,
            io_owner: 0,
            io_owner_ex_type: 0,
            io_owner_ex_pid: 0,
            io_signal: 0,
            pending_io_signal: None,
            next_activation_id: (task_id as u64) << 32 | 1,
            alarm_seconds: 0,
            realtime_epoch_ns: 1_000_000_000,
            realtime_epoch_tick: 0,
            clock_adj: ClockAdjustmentState::default(),
            physical_memory_offset,
            suspended_vfork_parent: None,
            suspended_clone_parent: None,
        }
    }

    pub(crate) fn begin_activation(&mut self) -> u64 {
        let activation_id = self.next_activation_id;
        self.next_activation_id += 1;
        self.activation_id = activation_id;
        activation_id
    }

    pub(crate) fn finish_activation(&mut self, activation_id: u64) {
        if self.activation_id == activation_id {
            self.activation_id = 0;
        }
    }

    pub(crate) fn allocate_mmap(&mut self, len: u64, align: u64) -> Option<u64> {
        let align = align.max(1);
        let start = align_up(self.mmap_cursor, align)?;
        let end = start.checked_add(align_up(len, align)?)?;
        if end > self.mmap_end {
            return None;
        }
        self.mmap_cursor = end;
        Some(start)
    }

    pub(crate) fn record_user_region(&mut self, start: u64, len: u64, writable: bool) {
        if let Some(end) = start.checked_add(len) {
            replace_user_region_range(&mut self.regions, start, end, Some(writable));
        }
    }

    pub(crate) fn unmap_user_region(&mut self, start: u64, len: u64) {
        if let Some(end) = start.checked_add(len) {
            replace_user_region_range(&mut self.regions, start, end, None);
        }
    }

    pub(crate) fn mapped_user_bytes(&self) -> u64 {
        self.regions
            .iter()
            .map(|region| region.end.saturating_sub(region.start))
            .fold(0u64, u64::saturating_add)
    }

    pub(crate) fn mapped_user_subranges(&self, start: u64, len: u64) -> Vec<(u64, u64)> {
        let Some(end) = start.checked_add(len) else {
            return Vec::new();
        };
        self.regions
            .iter()
            .filter_map(|region| {
                let range_start = core::cmp::max(start, region.start);
                let range_end = core::cmp::min(end, region.end);
                (range_start < range_end).then_some((range_start, range_end))
            })
            .collect()
    }

    pub(crate) fn physical_memory_offset(&self) -> u64 {
        self.physical_memory_offset
    }

    pub(crate) fn set_program_break(&mut self, requested: u64) -> u64 {
        if requested == 0 {
            return self.brk_current;
        }
        if requested < self.brk_base || requested > self.brk_end {
            return self.brk_current;
        }
        self.brk_current = requested;
        self.brk_current
    }

    pub(crate) fn cwd(&self) -> &[u8] {
        &self.cwd
    }

    pub(crate) fn set_cwd(&mut self, path: Vec<u8>) {
        self.cwd = path;
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }

    pub(crate) fn euid(&self) -> u32 {
        self.euid
    }

    pub(crate) fn egid(&self) -> u32 {
        self.egid
    }

    pub(crate) fn suid(&self) -> u32 {
        self.suid
    }

    pub(crate) fn sgid(&self) -> u32 {
        self.sgid
    }

    pub(crate) fn supplementary_groups(&self) -> &[u32] {
        &self.supplementary_groups
    }

    pub(crate) fn cap_inheritable(&self) -> u64 {
        self.cap_inheritable
    }

    pub(crate) fn cap_permitted(&self) -> u64 {
        self.cap_permitted
    }

    pub(crate) fn cap_effective(&self) -> u64 {
        self.cap_effective
    }

    pub(crate) fn cap_ambient(&self) -> u64 {
        self.cap_ambient
    }

    pub(crate) fn has_effective_capability(&self, capability: u64) -> bool {
        self.cap_effective & capability != 0
    }

    pub(crate) fn credential_state(&self) -> CredentialState {
        CredentialState {
            uid: self.uid,
            gid: self.gid,
            euid: self.euid,
            egid: self.egid,
            suid: self.suid,
            sgid: self.sgid,
            supplementary_groups: self.supplementary_groups.clone(),
            cap_bounding: self.cap_bounding,
            cap_inheritable: self.cap_inheritable,
            cap_permitted: self.cap_permitted,
            cap_effective: self.cap_effective,
            cap_ambient: self.cap_ambient,
        }
    }

    pub(crate) fn restore_credential_state(&mut self, state: CredentialState) {
        self.uid = state.uid;
        self.gid = state.gid;
        self.euid = state.euid;
        self.egid = state.egid;
        self.suid = state.suid;
        self.sgid = state.sgid;
        self.supplementary_groups = state.supplementary_groups;
        self.cap_bounding = state.cap_bounding;
        self.cap_inheritable = state.cap_inheritable;
        self.cap_permitted = state.cap_permitted;
        self.cap_effective = state.cap_effective;
        self.cap_ambient = state.cap_ambient;
    }

    pub(crate) fn set_uid(&mut self, uid: u32) -> bool {
        let old_uid = self.uid;
        let old_euid = self.euid;
        let old_suid = self.suid;
        if self.has_effective_capability(CAP_SETUID) {
            self.uid = uid;
            self.euid = uid;
            self.suid = uid;
            self.fixup_capabilities_after_uid_change(old_uid, old_euid, old_suid);
            return true;
        }
        if uid == self.uid || uid == self.euid || uid == self.suid {
            self.euid = uid;
            self.fixup_capabilities_after_uid_change(old_uid, old_euid, old_suid);
            return true;
        }
        false
    }

    pub(crate) fn set_gid(&mut self, gid: u32) -> bool {
        if self.has_effective_capability(CAP_SETGID) {
            self.gid = gid;
            self.egid = gid;
            self.sgid = gid;
            return true;
        }
        if gid == self.gid || gid == self.egid || gid == self.sgid {
            self.egid = gid;
            return true;
        }
        false
    }

    pub(crate) fn set_reuid(&mut self, ruid: Option<u32>, euid: Option<u32>) -> bool {
        let privileged = self.has_effective_capability(CAP_SETUID);
        let old_ruid = self.uid;
        let old_euid = self.euid;
        let old_suid = self.suid;
        if !privileged {
            for uid in [ruid, euid].into_iter().flatten() {
                if uid != old_ruid && uid != old_euid && uid != old_suid {
                    return false;
                }
            }
        }
        if let Some(uid) = ruid {
            self.uid = uid;
        }
        if let Some(uid) = euid {
            self.euid = uid;
        }
        if (privileged && (ruid.is_some() || euid.is_some()))
            || ruid.is_some()
            || euid.is_some_and(|uid| uid != old_ruid)
        {
            self.suid = self.euid;
        }
        self.fixup_capabilities_after_uid_change(old_ruid, old_euid, old_suid);
        true
    }

    pub(crate) fn set_regid(&mut self, rgid: Option<u32>, egid: Option<u32>) -> bool {
        let privileged = self.has_effective_capability(CAP_SETGID);
        let old_rgid = self.gid;
        let old_egid = self.egid;
        let old_sgid = self.sgid;
        if !privileged {
            for gid in [rgid, egid].into_iter().flatten() {
                if gid != old_rgid && gid != old_egid && gid != old_sgid {
                    return false;
                }
            }
        }
        if let Some(gid) = rgid {
            self.gid = gid;
        }
        if let Some(gid) = egid {
            self.egid = gid;
        }
        if (privileged && (rgid.is_some() || egid.is_some()))
            || rgid.is_some()
            || egid.is_some_and(|gid| gid != old_rgid)
        {
            self.sgid = self.egid;
        }
        true
    }

    pub(crate) fn set_groups(&mut self, groups: Vec<u32>) -> bool {
        if !self.has_effective_capability(CAP_SETGID) {
            return false;
        }
        self.supplementary_groups = groups;
        true
    }

    pub(crate) fn set_capability_sets(
        &mut self,
        permitted: u64,
        effective: u64,
        inheritable: u64,
        ambient: u64,
    ) -> bool {
        let permitted = permitted & LINUX_KNOWN_CAPS;
        let effective = effective & LINUX_KNOWN_CAPS;
        let inheritable = inheritable & LINUX_KNOWN_CAPS;
        let ambient = ambient & LINUX_KNOWN_CAPS;
        if permitted & !self.cap_bounding != 0
            || permitted & !self.cap_permitted != 0
            || effective & !permitted != 0
            || ambient & !permitted != 0
        {
            return false;
        }
        self.cap_permitted = permitted;
        self.cap_effective = effective;
        self.cap_inheritable = inheritable;
        self.cap_ambient = ambient;
        true
    }

    fn fixup_capabilities_after_uid_change(&mut self, old_uid: u32, old_euid: u32, old_suid: u32) {
        let had_root_uid = old_uid == 0 || old_euid == 0 || old_suid == 0;
        let has_root_uid = self.uid == 0 || self.euid == 0 || self.suid == 0;
        if had_root_uid && !has_root_uid {
            self.cap_effective = 0;
            self.cap_permitted = 0;
            self.cap_ambient = 0;
            return;
        }
        if old_euid == 0 && self.euid != 0 {
            self.cap_effective = 0;
            return;
        }
        if old_euid != 0 && self.euid == 0 {
            self.cap_effective = self.cap_permitted & self.cap_bounding;
        }
    }

    pub(crate) fn open_owner_ids(&self) -> u64 {
        ((self.euid as u64) << 32) | self.egid as u64
    }

    pub(crate) fn io_owner(&self) -> i64 {
        self.io_owner
    }

    pub(crate) fn set_io_owner(&mut self, owner: i64) {
        self.io_owner = owner;
        if owner < 0 {
            self.io_owner_ex_type = 2;
            self.io_owner_ex_pid = owner.saturating_abs().min(i32::MAX as i64) as i32;
        } else {
            self.io_owner_ex_type = 1;
            self.io_owner_ex_pid = owner.min(i32::MAX as i64) as i32;
        }
    }

    pub(crate) fn io_owner_ex(&self) -> (u32, i32) {
        (self.io_owner_ex_type, self.io_owner_ex_pid)
    }

    pub(crate) fn set_io_owner_ex(&mut self, owner_type: u32, pid: i32) {
        self.io_owner_ex_type = owner_type;
        self.io_owner_ex_pid = pid;
        self.io_owner = match owner_type {
            2 => -(pid as i64),
            _ => pid as i64,
        };
    }

    pub(crate) fn io_signal(&self) -> u32 {
        self.io_signal
    }

    pub(crate) fn set_io_signal(&mut self, signal: u32) {
        self.io_signal = signal;
    }

    pub(crate) fn queue_io_signal(&mut self) {
        if self.io_owner == 0 && self.io_owner_ex_pid == 0 {
            return;
        }
        if self.io_signal != 0 {
            self.pending_io_signal = Some(self.io_signal);
        }
    }

    pub(crate) fn consume_io_signal(&mut self) -> Option<u32> {
        self.pending_io_signal.take()
    }

    pub(crate) fn replace_alarm(&mut self, seconds: u64) -> u64 {
        let previous = self.alarm_seconds;
        self.alarm_seconds = seconds;
        previous
    }

    pub(crate) fn realtime_now_ns(&self, tick_count: u64, timer_hz: u64) -> u64 {
        let elapsed_ticks = tick_count.saturating_sub(self.realtime_epoch_tick);
        let elapsed_ns = elapsed_ticks.saturating_mul(1_000_000_000) / timer_hz.max(1);
        let correction = (elapsed_ns as i128)
            .saturating_mul(self.clock_adj.freq_scaled_ppm as i128)
            / 65_536
            / 1_000_000;
        let adjusted_elapsed = elapsed_ns as i128 + correction;
        if adjusted_elapsed >= 0 {
            self.realtime_epoch_ns.saturating_add(adjusted_elapsed as u64)
        } else {
            self.realtime_epoch_ns.saturating_sub((-adjusted_elapsed) as u64)
        }
    }

    pub(crate) fn set_realtime_ns(&mut self, now_ns: u64, tick_count: u64) {
        self.realtime_epoch_ns = now_ns;
        self.realtime_epoch_tick = tick_count;
    }

    pub(crate) fn adjust_realtime_ns(&mut self, delta_ns: i128, tick_count: u64, timer_hz: u64) {
        let now_ns = self.realtime_now_ns(tick_count, timer_hz);
        let adjusted = if delta_ns >= 0 {
            now_ns.saturating_add(delta_ns as u64)
        } else {
            now_ns.saturating_sub((-delta_ns) as u64)
        };
        self.set_realtime_ns(adjusted, tick_count);
    }

    pub(crate) fn clock_adj_state(&self) -> ClockAdjustmentState {
        self.clock_adj
    }

    pub(crate) fn set_clock_adj_state(&mut self, clock_adj: ClockAdjustmentState) {
        self.clock_adj = clock_adj;
    }

    pub(crate) fn suspend_for_vfork_child(
        &mut self,
        child_task_id: TaskId,
        child_pid: u32,
        child_tid: u32,
        return_context: UserReturnContext,
    ) {
        debug_assert!(self.suspended_vfork_parent.is_none());
        self.suspended_vfork_parent = Some(SuspendedVforkParent {
            task_id: self.task_id,
            pid: self.pid,
            tid: self.tid,
            child_pid,
            next_activation_id: self.next_activation_id,
            return_context,
            cwd: self.cwd.clone(),
            uid: self.uid,
            gid: self.gid,
            euid: self.euid,
            egid: self.egid,
            suid: self.suid,
            sgid: self.sgid,
            supplementary_groups: self.supplementary_groups.clone(),
            cap_bounding: self.cap_bounding,
            cap_inheritable: self.cap_inheritable,
            cap_permitted: self.cap_permitted,
            cap_effective: self.cap_effective,
            cap_ambient: self.cap_ambient,
            io_owner: self.io_owner,
            io_owner_ex_type: self.io_owner_ex_type,
            io_owner_ex_pid: self.io_owner_ex_pid,
            io_signal: self.io_signal,
            pending_io_signal: self.pending_io_signal,
            alarm_seconds: self.alarm_seconds,
            realtime_epoch_ns: self.realtime_epoch_ns,
            realtime_epoch_tick: self.realtime_epoch_tick,
            clock_adj: self.clock_adj,
        });
        self.task_id = child_task_id;
        self.pid = child_pid;
        self.tid = child_tid;
        self.activation_id = 0;
        self.next_activation_id = (child_task_id as u64) << 32 | 1;
    }

    pub(crate) fn suspend_for_clone_child(
        &mut self,
        child_task_id: TaskId,
        child_pid: u32,
        child_tid: u32,
        return_context: UserReturnContext,
        fs_shared: bool,
        files_shared: bool,
        fd_snapshot: Option<FdTableSnapshot>,
    ) {
        debug_assert!(self.suspended_clone_parent.is_none());
        self.suspended_clone_parent = Some(SuspendedCloneParent {
            task_id: self.task_id,
            pid: self.pid,
            tid: self.tid,
            child_pid,
            next_activation_id: self.next_activation_id,
            return_context,
            fs_shared,
            cwd: self.cwd.clone(),
            files_shared,
            fd_snapshot,
            credential: self.credential_state(),
            io_owner: self.io_owner,
            io_owner_ex_type: self.io_owner_ex_type,
            io_owner_ex_pid: self.io_owner_ex_pid,
            io_signal: self.io_signal,
            pending_io_signal: self.pending_io_signal,
            alarm_seconds: self.alarm_seconds,
        });
        self.task_id = child_task_id;
        self.pid = child_pid;
        self.tid = child_tid;
        self.activation_id = 0;
        self.next_activation_id = (child_task_id as u64) << 32 | 1;
    }

    pub(crate) fn has_suspended_vfork_parent(&self) -> bool {
        self.suspended_vfork_parent.is_some()
    }

    pub(crate) fn has_suspended_clone_parent(&self) -> bool {
        self.suspended_clone_parent.is_some()
    }

    pub(crate) fn take_vfork_parent_for_child(
        &mut self,
        child_pid: u32,
    ) -> Option<SuspendedVforkParent> {
        if self.suspended_vfork_parent.as_ref().is_some_and(|parent| parent.child_pid == child_pid)
        {
            self.suspended_vfork_parent.take()
        } else {
            None
        }
    }

    pub(crate) fn restore_vfork_parent(&mut self, parent: SuspendedVforkParent) {
        let SuspendedVforkParent {
            task_id,
            pid,
            tid,
            child_pid: _,
            next_activation_id,
            return_context: _,
            cwd,
            uid,
            gid,
            euid,
            egid,
            suid,
            sgid,
            supplementary_groups,
            cap_bounding,
            cap_inheritable,
            cap_permitted,
            cap_effective,
            cap_ambient,
            io_owner,
            io_owner_ex_type,
            io_owner_ex_pid,
            io_signal,
            pending_io_signal,
            alarm_seconds,
            realtime_epoch_ns,
            realtime_epoch_tick,
            clock_adj,
        } = parent;
        self.task_id = task_id;
        self.pid = pid;
        self.tid = tid;
        self.activation_id = 0;
        self.next_activation_id = next_activation_id;
        self.cwd = cwd;
        self.uid = uid;
        self.gid = gid;
        self.euid = euid;
        self.egid = egid;
        self.suid = suid;
        self.sgid = sgid;
        self.supplementary_groups = supplementary_groups;
        self.cap_bounding = cap_bounding;
        self.cap_inheritable = cap_inheritable;
        self.cap_permitted = cap_permitted;
        self.cap_effective = cap_effective;
        self.cap_ambient = cap_ambient;
        self.io_owner = io_owner;
        self.io_owner_ex_type = io_owner_ex_type;
        self.io_owner_ex_pid = io_owner_ex_pid;
        self.io_signal = io_signal;
        self.pending_io_signal = pending_io_signal;
        self.alarm_seconds = alarm_seconds;
        self.realtime_epoch_ns = realtime_epoch_ns;
        self.realtime_epoch_tick = realtime_epoch_tick;
        self.clock_adj = clock_adj;
    }

    pub(crate) fn take_clone_parent_for_child(
        &mut self,
        child_pid: u32,
    ) -> Option<SuspendedCloneParent> {
        if self.suspended_clone_parent.as_ref().is_some_and(|parent| parent.child_pid == child_pid)
        {
            self.suspended_clone_parent.take()
        } else {
            None
        }
    }

    pub(crate) fn restore_clone_parent(&mut self, parent: SuspendedCloneParent) {
        let SuspendedCloneParent {
            task_id,
            pid,
            tid,
            child_pid: _,
            next_activation_id,
            return_context: _,
            fs_shared,
            cwd,
            files_shared,
            fd_snapshot,
            credential,
            io_owner,
            io_owner_ex_type,
            io_owner_ex_pid,
            io_signal,
            pending_io_signal,
            alarm_seconds,
        } = parent;
        if !files_shared {
            self.supervisor.close_active_fd_table_for_process_exit();
            self.supervisor.pop_hidden_fd_table_refs();
            if let Some(fd_snapshot) = fd_snapshot {
                self.supervisor.restore_fd_table_snapshot(fd_snapshot);
            }
        }
        self.task_id = task_id;
        self.pid = pid;
        self.tid = tid;
        self.activation_id = 0;
        self.next_activation_id = next_activation_id;
        if !fs_shared {
            self.cwd = cwd;
        }
        self.restore_credential_state(credential);
        self.io_owner = io_owner;
        self.io_owner_ex_type = io_owner_ex_type;
        self.io_owner_ex_pid = io_owner_ex_pid;
        self.io_signal = io_signal;
        self.pending_io_signal = pending_io_signal;
        self.alarm_seconds = alarm_seconds;
    }
}

impl ClockAdjustmentState {
    pub(crate) const fn default() -> Self {
        Self {
            freq_scaled_ppm: 0,
            maxerror_us: 0,
            esterror_us: 0,
            status: 0,
            constant: 0,
            tick_us: 10_000,
            tai: 0,
            nano: true,
        }
    }
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

fn replace_user_region_range(
    regions: &mut Vec<UserRegion>,
    start: u64,
    end: u64,
    replacement_writable: Option<bool>,
) {
    if start >= end {
        return;
    }

    let mut updated = Vec::with_capacity(regions.len().saturating_add(1));
    for region in regions.drain(..) {
        if region.end <= start || region.start >= end {
            updated.push(region);
            continue;
        }
        if region.start < start {
            updated.push(UserRegion { start: region.start, end: start, writable: region.writable });
        }
        if region.end > end {
            updated.push(UserRegion { start: end, end: region.end, writable: region.writable });
        }
    }

    if let Some(writable) = replacement_writable {
        updated.push(UserRegion { start, end, writable });
    }

    updated.sort_by_key(|region| (region.start, region.end));
    for region in updated {
        if region.start >= region.end {
            continue;
        }
        if let Some(last) = regions.last_mut()
            && last.writable == region.writable
            && last.end >= region.start
        {
            last.end = last.end.max(region.end);
            continue;
        }
        regions.push(region);
    }
}

pub(crate) fn install_active_context(context: &mut ActiveUserContext) {
    unsafe {
        ACTIVE_CONTEXT = context as *mut _;
    }
}

pub(crate) fn active_context() -> &'static mut ActiveUserContext {
    unsafe {
        if ACTIVE_CONTEXT.is_null() {
            panic!("ring3 context was not installed");
        }
        &mut *ACTIVE_CONTEXT
    }
}
