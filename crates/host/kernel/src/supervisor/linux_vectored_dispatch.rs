use alloc::vec::Vec;

use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_EOPNOTSUPP, PlanKind};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::FdResource,
};

const IOV_MAX: usize = 1024;
const LINUX_IOVEC_SIZE: usize = 16;
const LINUX_MSGHDR_SIZE: u32 = 56;
const MSGHDR_NAMELEN_OFFSET: u32 = 8;
const MSGHDR_CONTROLLEN_OFFSET: u32 = 40;
const MSGHDR_FLAGS_OFFSET: u32 = 48;

#[derive(Clone, Copy)]
struct LinuxIovec {
    base: u32,
    len: u32,
}

#[derive(Clone, Copy)]
struct LinuxMsgHdr {
    name: u64,
    namelen: u32,
    iov_ptr: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_readv(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "readv fd overflowed")?;
        let is_socket = self.fd_is_socket(fd);
        if is_socket && let Err(result) = self.require_socket_recv_capability() {
            return Ok(result);
        }
        let iovecs = match self.read_iovecs(plan.args[1], plan.args[2]) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if iovecs.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        if let Err(errno) = self.prevalidate_iovec_writes(&iovecs) {
            return Ok(errno_ret(errno));
        }
        if self.is_eventfd_fd(fd) {
            let total_len = match total_iovec_len(&iovecs) {
                Ok(total_len) => total_len,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            let bytes = match self.read_eventfd_value(fd, total_len) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            if let Err(errno) = self.write_iovec_bytes(&iovecs, &bytes) {
                return Ok(errno_ret(errno));
            }
            return Ok(LinuxCallResult::Ret(bytes.len() as i64));
        }
        if is_socket {
            let total_len = match total_iovec_len(&iovecs) {
                Ok(total_len) => total_len,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            if total_len == 0 {
                return Ok(LinuxCallResult::Ret(0));
            }
            let total_len = match u32::try_from(total_len) {
                Ok(total_len) => total_len,
                Err(_) => return Ok(errno_ret(ERR_EINVAL)),
            };
            let received = self.recv_socket_bytes_from_fd_authorized(fd, total_len, 0)?;
            return match received {
                LinuxCallResult::Bytes(bytes) => {
                    if let Err(errno) = self.write_iovec_bytes(&iovecs, &bytes) {
                        Ok(errno_ret(errno))
                    } else {
                        Ok(LinuxCallResult::Ret(bytes.len() as i64))
                    }
                }
                other => Ok(other),
            };
        }

        let mut total = 0usize;
        for iov in iovecs {
            if iov.len == 0 {
                continue;
            }
            let read = self.plan_read(LinuxPlan {
                kind: PlanKind::Read,
                args: [fd as u64, iov.len as u64, 0, 0, 0, 0],
            })?;
            match read {
                LinuxCallResult::Bytes(bytes) => {
                    let read_len = bytes.len();
                    if read_len != 0 && self.linux.write_bytes(iov.base, &bytes).is_err() {
                        return Ok(if total == 0 {
                            errno_ret(ERR_EFAULT)
                        } else {
                            LinuxCallResult::Ret(total as i64)
                        });
                    }
                    total = match total.checked_add(read_len) {
                        Some(total) => total,
                        None => return Ok(errno_ret(ERR_EINVAL)),
                    };
                    if read_len < iov.len as usize {
                        return Ok(LinuxCallResult::Ret(total as i64));
                    }
                }
                LinuxCallResult::Ret(ret) if ret >= 0 => {
                    total = match total.checked_add(ret as usize) {
                        Some(total) => total,
                        None => return Ok(errno_ret(ERR_EINVAL)),
                    };
                    return Ok(LinuxCallResult::Ret(total as i64));
                }
                LinuxCallResult::Ret(_) if total > 0 => {
                    return Ok(LinuxCallResult::Ret(total as i64));
                }
                LinuxCallResult::Ret(ret) => return Ok(LinuxCallResult::Ret(ret)),
                LinuxCallResult::Pending(token) if total == 0 => {
                    return Ok(LinuxCallResult::Pending(token));
                }
                LinuxCallResult::Pending(_) => return Ok(LinuxCallResult::Ret(total as i64)),
                LinuxCallResult::SeccompContinue { .. } => {
                    return Err("readv chunk returned seccomp continue");
                }
                LinuxCallResult::Exit(code) => return Ok(LinuxCallResult::Exit(code)),
            }
        }
        Ok(LinuxCallResult::Ret(total as i64))
    }

    pub(super) fn plan_recvmsg(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if let Err(result) = self.require_socket_recv_capability() {
            return Ok(result);
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "recvmsg fd overflowed")?;
        let msg_ptr = match u32::try_from(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EFAULT)),
        };
        let flags = plan.args[2] as u32;
        let msg = match self.read_msghdr(msg_ptr) {
            Ok(msg) => msg,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let iovecs = match self.read_iovecs(msg.iov_ptr, msg.iovlen) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if let Err(errno) = self.prevalidate_recvmsg_writes(msg_ptr, msg, &iovecs) {
            return Ok(errno_ret(errno));
        }
        let total_len = match total_iovec_len(&iovecs) {
            Ok(total_len) => total_len,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if let Err(errno) = self.require_socket_fd(fd) {
            return Ok(errno_ret(errno));
        }
        if total_len == 0 {
            return self.finish_recvmsg_writeback(fd, msg_ptr, msg, &iovecs, Vec::new());
        }
        let total_len = match u32::try_from(total_len) {
            Ok(total_len) => total_len,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        match self.recv_socket_bytes_from_fd_authorized(fd, total_len, flags)? {
            LinuxCallResult::Bytes(bytes) => {
                self.finish_recvmsg_writeback(fd, msg_ptr, msg, &iovecs, bytes)
            }
            LinuxCallResult::Ret(0) => {
                self.finish_recvmsg_writeback(fd, msg_ptr, msg, &iovecs, Vec::new())
            }
            other => Ok(other),
        }
    }

    pub(super) fn plan_sendmsg(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if let Err(result) = self.require_socket_send_capability() {
            return Ok(result);
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "sendmsg fd overflowed")?;
        let msg_ptr = match u32::try_from(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(errno_ret(ERR_EFAULT)),
        };
        let flags = plan.args[2] as u32;
        let msg = match self.read_msghdr(msg_ptr) {
            Ok(msg) => msg,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if msg.name != 0 || msg.namelen != 0 || msg.controllen != 0 {
            return Ok(errno_ret(ERR_EOPNOTSUPP));
        }
        let iovecs = match self.read_iovecs(msg.iov_ptr, msg.iovlen) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let bytes = match self.read_iovec_bytes(&iovecs) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if let Err(errno) = self.require_socket_fd(fd) {
            return Ok(errno_ret(errno));
        }
        if bytes.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.send_socket_bytes_from_fd_authorized(fd, &bytes, flags)
    }

    pub(super) fn plan_writev(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "writev fd overflowed")?;
        let is_socket = self.fd_is_socket(fd);
        if is_socket && let Err(result) = self.require_socket_send_capability() {
            return Ok(result);
        }
        let iovecs = match self.read_iovecs(plan.args[1], plan.args[2]) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if iovecs.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        if self.is_eventfd_fd(fd) {
            let total_len = match total_iovec_len(&iovecs) {
                Ok(total_len) => total_len,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            let value_bytes = match self.read_iovec_prefix(&iovecs, 8) {
                Ok(bytes) if bytes.len() == 8 => bytes,
                Ok(_) => return Ok(errno_ret(ERR_EINVAL)),
                Err(errno) => return Ok(errno_ret(errno)),
            };
            let value = u64::from_le_bytes(
                value_bytes[..8].try_into().map_err(|_| "eventfd writev value was short")?,
            );
            return match self.write_eventfd_value(fd, value, total_len) {
                Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                Err(errno) => Ok(errno_ret(errno)),
            };
        }
        if is_socket {
            let bytes = match self.read_iovec_bytes(&iovecs) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            if bytes.is_empty() {
                return Ok(LinuxCallResult::Ret(0));
            }
            return self.send_socket_bytes_from_fd_authorized(fd, &bytes, 0);
        }

        let mut chunks = Vec::new();
        for iov in &iovecs {
            if iov.len == 0 {
                chunks.push(Vec::new());
                continue;
            }
            match self.linux.read_bytes(iov.base, iov.len) {
                Ok(bytes) => chunks.push(bytes),
                Err(_) => return Ok(errno_ret(ERR_EFAULT)),
            }
        }

        if self.is_vfs_file_fd(fd) {
            let chunk_refs = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
            return match self.write_vfs_fd_chunks(fd, &chunk_refs) {
                Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                Err(errno) => Ok(errno_ret(errno)),
            };
        }

        let mut total = 0usize;
        for bytes in chunks {
            if bytes.is_empty() {
                continue;
            }
            let ptr_len = match self.linux.write_arg_bytes(&bytes) {
                Ok(ptr_len) => ptr_len,
                Err(_) => return Ok(errno_ret(ERR_EFAULT)),
            };
            let written = self.plan_write(LinuxPlan {
                kind: PlanKind::Write,
                args: [fd as u64, ptr_len.0 as u64, ptr_len.1 as u64, 0, 0, 0],
            })?;
            match written {
                LinuxCallResult::Ret(ret) if ret >= 0 => {
                    total = match total.checked_add(ret as usize) {
                        Some(total) => total,
                        None => return Ok(errno_ret(ERR_EINVAL)),
                    };
                    if ret as usize != bytes.len() {
                        return Ok(LinuxCallResult::Ret(total as i64));
                    }
                }
                LinuxCallResult::Ret(_) if total > 0 => {
                    return Ok(LinuxCallResult::Ret(total as i64));
                }
                LinuxCallResult::Ret(ret) => return Ok(LinuxCallResult::Ret(ret)),
                LinuxCallResult::Pending(token) if total == 0 => {
                    return Ok(LinuxCallResult::Pending(token));
                }
                LinuxCallResult::Pending(_) => return Ok(LinuxCallResult::Ret(total as i64)),
                LinuxCallResult::SeccompContinue { .. } => {
                    return Err("writev chunk returned seccomp continue");
                }
                LinuxCallResult::Bytes(_) => return Err("writev chunk returned bytes"),
                LinuxCallResult::Exit(code) => return Ok(LinuxCallResult::Exit(code)),
            }
        }
        Ok(LinuxCallResult::Ret(total as i64))
    }

    fn read_iovecs(&mut self, iov_ptr: u64, iovcnt: u64) -> Result<Vec<LinuxIovec>, i32> {
        let iovcnt = usize::try_from(iovcnt).map_err(|_| ERR_EINVAL)?;
        if iovcnt > IOV_MAX {
            return Err(ERR_EINVAL);
        }
        if iovcnt == 0 {
            return Ok(Vec::new());
        }
        let iov_ptr = u32::try_from(iov_ptr).map_err(|_| ERR_EFAULT)?;
        let byte_len = iovcnt.checked_mul(LINUX_IOVEC_SIZE).ok_or(ERR_EINVAL)?;
        let bytes = self
            .linux
            .read_bytes(iov_ptr, u32::try_from(byte_len).map_err(|_| ERR_EINVAL)?)
            .map_err(|_| ERR_EFAULT)?;
        let mut iovecs = Vec::with_capacity(iovcnt);
        for chunk in bytes.chunks_exact(LINUX_IOVEC_SIZE) {
            let base = u64::from_le_bytes(chunk[0..8].try_into().map_err(|_| ERR_EINVAL)?);
            let len = u64::from_le_bytes(chunk[8..16].try_into().map_err(|_| ERR_EINVAL)?);
            let len = u32::try_from(len).map_err(|_| ERR_EINVAL)?;
            iovecs.push(LinuxIovec {
                base: if len == 0 { 0 } else { u32::try_from(base).map_err(|_| ERR_EFAULT)? },
                len,
            });
        }
        Ok(iovecs)
    }

    fn prevalidate_iovec_writes(&mut self, iovecs: &[LinuxIovec]) -> Result<(), i32> {
        for iov in iovecs {
            if iov.len != 0 && self.linux.read_bytes(iov.base, iov.len).is_err() {
                return Err(ERR_EFAULT);
            }
        }
        Ok(())
    }

    fn read_msghdr(&mut self, msg_ptr: u32) -> Result<LinuxMsgHdr, i32> {
        let bytes = self.linux.read_bytes(msg_ptr, LINUX_MSGHDR_SIZE).map_err(|_| ERR_EFAULT)?;
        Ok(LinuxMsgHdr {
            name: read_u64_le(&bytes, 0)?,
            namelen: read_u32_le(&bytes, MSGHDR_NAMELEN_OFFSET as usize)?,
            iov_ptr: read_u64_le(&bytes, 16)?,
            iovlen: read_u64_le(&bytes, 24)?,
            control: read_u64_le(&bytes, 32)?,
            controllen: read_u64_le(&bytes, MSGHDR_CONTROLLEN_OFFSET as usize)?,
        })
    }

    fn prevalidate_recvmsg_writes(
        &mut self,
        msg_ptr: u32,
        msg: LinuxMsgHdr,
        iovecs: &[LinuxIovec],
    ) -> Result<(), i32> {
        self.prevalidate_iovec_writes(iovecs)?;
        self.prevalidate_linux_writeback(msg_field_ptr(msg_ptr, MSGHDR_CONTROLLEN_OFFSET)?, 8)?;
        self.prevalidate_linux_writeback(msg_field_ptr(msg_ptr, MSGHDR_FLAGS_OFFSET)?, 4)?;
        if msg.name != 0 {
            if msg.namelen < 16 {
                return Err(ERR_EINVAL);
            }
            let name_ptr = u32::try_from(msg.name).map_err(|_| ERR_EFAULT)?;
            self.prevalidate_linux_writeback(name_ptr, 16)?;
            self.prevalidate_linux_writeback(msg_field_ptr(msg_ptr, MSGHDR_NAMELEN_OFFSET)?, 4)?;
        }
        if msg.controllen != 0 {
            let control_ptr = u32::try_from(msg.control).map_err(|_| ERR_EFAULT)?;
            if control_ptr == 0 {
                return Err(ERR_EFAULT);
            }
            let controllen = u32::try_from(msg.controllen).map_err(|_| ERR_EINVAL)?;
            self.prevalidate_linux_writeback(control_ptr, controllen)?;
        }
        Ok(())
    }

    fn prevalidate_linux_writeback(&mut self, ptr: u32, len: u32) -> Result<(), i32> {
        if len != 0 && self.linux.read_bytes(ptr, len).is_err() { Err(ERR_EFAULT) } else { Ok(()) }
    }

    fn fd_is_socket(&self, fd: u32) -> bool {
        self.fd_entry(fd).is_some_and(|entry| matches!(entry.resource, FdResource::Socket { .. }))
    }

    fn write_iovec_bytes(&mut self, iovecs: &[LinuxIovec], bytes: &[u8]) -> Result<(), i32> {
        let mut offset = 0usize;
        for iov in iovecs {
            if offset == bytes.len() {
                break;
            }
            let len = (iov.len as usize).min(bytes.len() - offset);
            if len == 0 {
                continue;
            }
            self.linux
                .write_bytes(iov.base, &bytes[offset..offset + len])
                .map_err(|_| ERR_EFAULT)?;
            offset += len;
        }
        if offset == bytes.len() { Ok(()) } else { Err(ERR_EINVAL) }
    }

    fn finish_recvmsg_writeback(
        &mut self,
        fd: u32,
        msg_ptr: u32,
        msg: LinuxMsgHdr,
        iovecs: &[LinuxIovec],
        bytes: Vec<u8>,
    ) -> Result<LinuxCallResult, &'static str> {
        if let Err(errno) = self.write_iovec_bytes(iovecs, &bytes) {
            return Ok(errno_ret(errno));
        }
        if msg.name != 0 {
            let name_ptr = match u32::try_from(msg.name) {
                Ok(ptr) => ptr,
                Err(_) => return Ok(errno_ret(ERR_EFAULT)),
            };
            let namelen_ptr = match msg_field_ptr(msg_ptr, MSGHDR_NAMELEN_OFFSET) {
                Ok(ptr) => ptr,
                Err(errno) => return Ok(errno_ret(errno)),
            };
            if let Err(errno) = self.write_generic_socket_peer_sockaddr(fd, name_ptr, namelen_ptr) {
                return Ok(errno_ret(errno));
            }
        }
        if self
            .linux
            .write_bytes(
                msg_field_ptr(msg_ptr, MSGHDR_CONTROLLEN_OFFSET)
                    .map_err(|_| "recvmsg controllen pointer overflowed after prevalidation")?,
                &0u64.to_le_bytes(),
            )
            .is_err()
        {
            return Ok(errno_ret(ERR_EFAULT));
        }
        if self
            .linux
            .write_bytes(
                msg_field_ptr(msg_ptr, MSGHDR_FLAGS_OFFSET)
                    .map_err(|_| "recvmsg flags pointer overflowed after prevalidation")?,
                &0u32.to_le_bytes(),
            )
            .is_err()
        {
            return Ok(errno_ret(ERR_EFAULT));
        }
        Ok(LinuxCallResult::Ret(bytes.len() as i64))
    }

    fn read_iovec_prefix(&mut self, iovecs: &[LinuxIovec], len: usize) -> Result<Vec<u8>, i32> {
        let mut out = Vec::with_capacity(len);
        for iov in iovecs {
            if out.len() == len {
                break;
            }
            let take = (iov.len as usize).min(len - out.len());
            if take == 0 {
                continue;
            }
            let take = u32::try_from(take).map_err(|_| ERR_EINVAL)?;
            out.extend_from_slice(&self.linux.read_bytes(iov.base, take).map_err(|_| ERR_EFAULT)?);
        }
        Ok(out)
    }

    fn read_iovec_bytes(&mut self, iovecs: &[LinuxIovec]) -> Result<Vec<u8>, i32> {
        let total_len = total_iovec_len(iovecs)?;
        let mut out = Vec::with_capacity(total_len);
        for iov in iovecs {
            if iov.len == 0 {
                continue;
            }
            out.extend_from_slice(
                &self.linux.read_bytes(iov.base, iov.len).map_err(|_| ERR_EFAULT)?,
            );
        }
        Ok(out)
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    Ok(u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_err(|_| ERR_EINVAL)?))
}

fn msg_field_ptr(msg_ptr: u32, offset: u32) -> Result<u32, i32> {
    msg_ptr.checked_add(offset).ok_or(ERR_EFAULT)
}

fn total_iovec_len(iovecs: &[LinuxIovec]) -> Result<usize, i32> {
    iovecs
        .iter()
        .try_fold(0usize, |total, iov| total.checked_add(iov.len as usize).ok_or(ERR_EINVAL))
}
