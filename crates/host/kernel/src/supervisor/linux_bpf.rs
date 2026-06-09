use alloc::{vec, vec::Vec};

use visa_abi::{
    ERR_E2BIG, ERR_EBADF, ERR_EEXIST, ERR_EFAULT, ERR_EINVAL, ERR_EMFILE, ERR_ENOENT,
    ERR_EOPNOTSUPP, ERR_EPERM,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{BpfMapEntry, BpfMapKind, BpfMapState, CAP_SYS_ADMIN, FdEntry, FdResource},
};

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;

const MAX_BPF_KEY_SIZE: u32 = 256;
const MAX_BPF_VALUE_SIZE: u32 = 4096;
const MAX_BPF_MAP_ENTRIES: u32 = 1024;
const MAX_BPF_MAP_BYTES: usize = 1024 * 1024;
const BPF_ATTR_MAX_SIZE: usize = 256;
const BPF_ATTR_MAP_CREATE_SIZE: usize = 20;
const BPF_ATTR_MAP_LOOKUP_SIZE: usize = 24;
const BPF_ATTR_MAP_UPDATE_SIZE: usize = 32;
const BPF_ATTR_MAP_DELETE_SIZE: usize = 16;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_bpf(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        match self.apply_bpf_plan(plan) {
            Ok(ret) => Ok(LinuxCallResult::Ret(ret)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }

    fn apply_bpf_plan(&mut self, plan: LinuxPlan) -> Result<i64, i32> {
        let cmd = u32::try_from(plan.args[0]).map_err(|_| ERR_EINVAL)?;
        let attr_ptr = plan.args[1];
        let attr_size = usize::try_from(plan.args[2]).map_err(|_| ERR_E2BIG)?;

        match cmd {
            BPF_MAP_CREATE => {
                if self.current_access_state().cap_effective & CAP_SYS_ADMIN == 0 {
                    return Err(ERR_EPERM);
                }
                let attr = self.read_bpf_attr(attr_ptr, attr_size, BPF_ATTR_MAP_CREATE_SIZE)?;
                let map_type = read_u32_from(&attr, 0)?;
                let key_size = read_u32_from(&attr, 4)?;
                let value_size = read_u32_from(&attr, 8)?;
                let max_entries = read_u32_from(&attr, 12)?;
                let map_flags = read_u32_from(&attr, 16)?;
                self.bpf_map_create(map_type, key_size, value_size, max_entries, map_flags)
                    .map(|fd| fd as i64)
            }
            BPF_MAP_LOOKUP_ELEM => {
                let attr = self.read_bpf_attr(attr_ptr, attr_size, BPF_ATTR_MAP_LOOKUP_SIZE)?;
                let map_fd = read_u32_from(&attr, 0)?;
                let key_ptr = read_u64_from(&attr, 8)?;
                let value_ptr = read_u64_from(&attr, 16)?;
                let (key_size, _) = self.bpf_map_shape_for_fd(map_fd)?;
                let key = self.read_bpf_user_bytes(key_ptr, key_size)?;
                let value = self.bpf_map_lookup_elem(map_fd, &key)?;
                self.write_bpf_user_bytes(value_ptr, &value)?;
                Ok(0)
            }
            BPF_MAP_UPDATE_ELEM => {
                let attr = self.read_bpf_attr(attr_ptr, attr_size, BPF_ATTR_MAP_UPDATE_SIZE)?;
                let map_fd = read_u32_from(&attr, 0)?;
                let key_ptr = read_u64_from(&attr, 8)?;
                let value_ptr = read_u64_from(&attr, 16)?;
                let flags = read_u64_from(&attr, 24)?;
                let (key_size, value_size) = self.bpf_map_shape_for_fd(map_fd)?;
                let key = self.read_bpf_user_bytes(key_ptr, key_size)?;
                let value = self.read_bpf_user_bytes(value_ptr, value_size)?;
                self.bpf_map_update_elem(map_fd, &key, &value, flags)?;
                Ok(0)
            }
            BPF_MAP_DELETE_ELEM => {
                let attr = self.read_bpf_attr(attr_ptr, attr_size, BPF_ATTR_MAP_DELETE_SIZE)?;
                let map_fd = read_u32_from(&attr, 0)?;
                let key_ptr = read_u64_from(&attr, 8)?;
                let (key_size, _) = self.bpf_map_shape_for_fd(map_fd)?;
                let key = self.read_bpf_user_bytes(key_ptr, key_size)?;
                self.bpf_map_delete_elem(map_fd, &key)?;
                Ok(0)
            }
            _ => Err(ERR_EOPNOTSUPP),
        }
    }

    pub(crate) fn bpf_map_create(
        &mut self,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> Result<u32, i32> {
        if map_flags != 0 {
            return Err(ERR_EOPNOTSUPP);
        }
        let kind = match map_type {
            BPF_MAP_TYPE_HASH => BpfMapKind::Hash,
            BPF_MAP_TYPE_ARRAY => BpfMapKind::Array,
            _ => return Err(ERR_EOPNOTSUPP),
        };
        validate_bpf_map_shape(kind, key_size, value_size, max_entries)?;
        if !self.can_allocate_fds(1) {
            return Err(ERR_EMFILE);
        }

        let id = self.next_bpf_map_id;
        self.next_bpf_map_id = self.next_bpf_map_id.saturating_add(1).max(1);
        let entries = match kind {
            BpfMapKind::Hash => Vec::new(),
            BpfMapKind::Array => {
                let value = vec![0u8; value_size as usize];
                vec![BpfMapEntry { key: Vec::new(), value }; max_entries as usize]
            }
        };
        self.bpf_maps.push(BpfMapState { id, kind, key_size, value_size, max_entries, entries });

        match self.alloc_fd(FdEntry {
            resource: FdResource::BpfMap { map_id: id },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        }) {
            Ok(fd) => Ok(fd),
            Err(errno) => {
                self.remove_bpf_map(id);
                Err(errno)
            }
        }
    }

    pub(crate) fn bpf_map_shape_for_fd(&mut self, fd: u32) -> Result<(usize, usize), i32> {
        let map_id = self.bpf_map_id_for_fd(fd)?;
        let map = self.bpf_map(map_id)?;
        Ok((map.key_size as usize, map.value_size as usize))
    }

    pub(crate) fn bpf_map_lookup_elem(&mut self, fd: u32, key: &[u8]) -> Result<Vec<u8>, i32> {
        let map_id = self.bpf_map_id_for_fd(fd)?;
        let map = self.bpf_map(map_id)?;
        validate_bpf_key(map, key)?;
        match map.kind {
            BpfMapKind::Hash => map
                .entries
                .iter()
                .find(|entry| entry.key == key)
                .map(|entry| entry.value.clone())
                .ok_or(ERR_ENOENT),
            BpfMapKind::Array => {
                let index = bpf_array_index(map, key)?;
                Ok(map.entries[index].value.clone())
            }
        }
    }

    pub(crate) fn bpf_map_update_elem(
        &mut self,
        fd: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), i32> {
        if !matches!(flags, BPF_ANY | BPF_NOEXIST | BPF_EXIST) {
            return Err(ERR_EINVAL);
        }
        let map_id = self.bpf_map_id_for_fd(fd)?;
        let map = self.bpf_map_mut(map_id)?;
        validate_bpf_key(map, key)?;
        validate_bpf_value(map, value)?;

        match map.kind {
            BpfMapKind::Hash => {
                if let Some(index) = hash_entry_index(map, key) {
                    if flags == BPF_NOEXIST {
                        return Err(ERR_EEXIST);
                    }
                    map.entries[index].value.copy_from_slice(value);
                    Ok(())
                } else {
                    if flags == BPF_EXIST {
                        return Err(ERR_ENOENT);
                    }
                    if map.entries.len() >= map.max_entries as usize {
                        return Err(ERR_E2BIG);
                    }
                    map.entries.push(BpfMapEntry { key: key.to_vec(), value: value.to_vec() });
                    Ok(())
                }
            }
            BpfMapKind::Array => {
                if flags == BPF_NOEXIST {
                    return Err(ERR_EEXIST);
                }
                let index = bpf_array_index(map, key)?;
                map.entries[index].value.copy_from_slice(value);
                Ok(())
            }
        }
    }

    pub(crate) fn bpf_map_delete_elem(&mut self, fd: u32, key: &[u8]) -> Result<(), i32> {
        let map_id = self.bpf_map_id_for_fd(fd)?;
        let map = self.bpf_map_mut(map_id)?;
        validate_bpf_key(map, key)?;
        match map.kind {
            BpfMapKind::Hash => {
                let Some(index) = hash_entry_index(map, key) else {
                    return Err(ERR_ENOENT);
                };
                map.entries.remove(index);
                Ok(())
            }
            BpfMapKind::Array => Err(ERR_EINVAL),
        }
    }

    pub(super) fn has_other_bpf_map_fd_ref(&self, closing_fd: u32, map_id: u64) -> bool {
        self.fd_table.iter().enumerate().any(|(fd, entry)| {
            fd != closing_fd as usize
                && matches!(
                    entry.as_ref().map(|entry| &entry.resource),
                    Some(FdResource::BpfMap { map_id: other }) if *other == map_id
                )
        }) || self.hidden_fd_table_refs.iter().any(|table| {
            table.iter().filter_map(Option::as_ref).any(|entry| {
                matches!(entry.resource, FdResource::BpfMap { map_id: other } if other == map_id)
            })
        })
    }

    pub(super) fn remove_bpf_map(&mut self, map_id: u64) -> bool {
        let before = self.bpf_maps.len();
        self.bpf_maps.retain(|map| map.id != map_id);
        self.bpf_maps.len() != before
    }

    fn bpf_map_id_for_fd(&mut self, fd: u32) -> Result<u64, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        match entry.resource {
            FdResource::BpfMap { map_id } => Ok(map_id),
            _ => Err(ERR_EBADF),
        }
    }

    fn bpf_map(&self, map_id: u64) -> Result<&BpfMapState, i32> {
        self.bpf_maps.iter().find(|map| map.id == map_id).ok_or(ERR_EBADF)
    }

    fn bpf_map_mut(&mut self, map_id: u64) -> Result<&mut BpfMapState, i32> {
        self.bpf_maps.iter_mut().find(|map| map.id == map_id).ok_or(ERR_EBADF)
    }

    fn read_bpf_attr(&mut self, ptr: u64, size: usize, min_size: usize) -> Result<Vec<u8>, i32> {
        if ptr == 0 {
            return Err(ERR_EFAULT);
        }
        if size < min_size {
            return Err(ERR_EINVAL);
        }
        if size > BPF_ATTR_MAX_SIZE {
            return Err(ERR_E2BIG);
        }
        self.read_bpf_user_bytes(ptr, size)
    }

    fn read_bpf_user_bytes(&mut self, ptr: u64, len: usize) -> Result<Vec<u8>, i32> {
        let ptr = u32::try_from(ptr).map_err(|_| ERR_EFAULT)?;
        let len = u32::try_from(len).map_err(|_| ERR_EINVAL)?;
        self.linux.read_bytes(ptr, len).map_err(|_| ERR_EFAULT)
    }

    fn write_bpf_user_bytes(&mut self, ptr: u64, bytes: &[u8]) -> Result<(), i32> {
        let ptr = u32::try_from(ptr).map_err(|_| ERR_EFAULT)?;
        self.linux.write_bytes(ptr, bytes).map_err(|_| ERR_EFAULT)
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

fn read_u32_from(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    let end = offset.checked_add(4).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_u64_from(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    let end = offset.checked_add(8).ok_or(ERR_EINVAL)?;
    let raw = bytes.get(offset..end).ok_or(ERR_EINVAL)?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn validate_bpf_map_shape(
    kind: BpfMapKind,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> Result<(), i32> {
    if key_size == 0
        || value_size == 0
        || max_entries == 0
        || key_size > MAX_BPF_KEY_SIZE
        || value_size > MAX_BPF_VALUE_SIZE
        || max_entries > MAX_BPF_MAP_ENTRIES
    {
        return Err(ERR_EINVAL);
    }
    if kind == BpfMapKind::Array && key_size != 4 {
        return Err(ERR_EINVAL);
    }
    let bytes_per_entry = (key_size as usize).checked_add(value_size as usize).ok_or(ERR_EINVAL)?;
    let total = bytes_per_entry.checked_mul(max_entries as usize).ok_or(ERR_EINVAL)?;
    if total > MAX_BPF_MAP_BYTES {
        return Err(ERR_E2BIG);
    }
    Ok(())
}

fn validate_bpf_key(map: &BpfMapState, key: &[u8]) -> Result<(), i32> {
    if key.len() == map.key_size as usize { Ok(()) } else { Err(ERR_EINVAL) }
}

fn validate_bpf_value(map: &BpfMapState, value: &[u8]) -> Result<(), i32> {
    if value.len() == map.value_size as usize { Ok(()) } else { Err(ERR_EINVAL) }
}

fn hash_entry_index(map: &BpfMapState, key: &[u8]) -> Option<usize> {
    map.entries.iter().position(|entry| entry.key == key)
}

fn bpf_array_index(map: &BpfMapState, key: &[u8]) -> Result<usize, i32> {
    let raw = u32::from_le_bytes(key.try_into().map_err(|_| ERR_EINVAL)?);
    let index = raw as usize;
    if index < map.max_entries as usize { Ok(index) } else { Err(ERR_E2BIG) }
}
