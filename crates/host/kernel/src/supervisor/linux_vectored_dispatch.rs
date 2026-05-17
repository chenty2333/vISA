use alloc::vec::Vec;

use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_EOPNOTSUPP, PlanKind};

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
        if self.fd_uses_blocking_socket_path(fd) {
            return Ok(errno_ret(ERR_EOPNOTSUPP));
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
                LinuxCallResult::Exit(code) => return Ok(LinuxCallResult::Exit(code)),
            }
        }
        Ok(LinuxCallResult::Ret(total as i64))
    }

    pub(super) fn plan_writev(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "writev fd overflowed")?;
        if self.fd_uses_blocking_socket_path(fd) {
            return Ok(errno_ret(ERR_EOPNOTSUPP));
        }
        let iovecs = match self.read_iovecs(plan.args[1], plan.args[2]) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        if iovecs.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
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

    fn fd_uses_blocking_socket_path(&self, fd: u32) -> bool {
        self.fd_entry(fd).is_some_and(|entry| matches!(entry.resource, FdResource::Socket { .. }))
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
