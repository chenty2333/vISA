use alloc::vec::Vec;

use vmos_abi::{ERR_EFAULT, ERR_EINVAL, PlanKind};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::FdResource,
};

const IOV_MAX: usize = 1024;
const LINUX_IOVEC_SIZE: usize = 16;

#[derive(Clone, Copy)]
struct LinuxIovec {
    base: u32,
    len: u32,
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

fn total_iovec_len(iovecs: &[LinuxIovec]) -> Result<usize, i32> {
    iovecs
        .iter()
        .try_fold(0usize, |total, iov| total.checked_add(iov.len as usize).ok_or(ERR_EINVAL))
}
