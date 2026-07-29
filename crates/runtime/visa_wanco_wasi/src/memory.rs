use core::ptr;

use visa_wasi_protocol::MAX_FRAME_BYTES;

use crate::ExecEnv;

pub(crate) const WASM_PAGE_BYTES: usize = 65_536;
pub(crate) const MAX_IO_BYTES: usize = MAX_FRAME_BYTES - 4_096;
const MAX_IOVECS: usize = 4_096;
const WASM32_MAX_PAGES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryError {
    InvalidEnvironment,
    OutOfBounds,
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Iovec {
    pub offset: u32,
    pub length: u32,
}

pub(crate) struct GuestMemory {
    base: *mut u8,
    length: usize,
}

impl GuestMemory {
    pub(crate) fn from_exec_env(exec_env: *const ExecEnv) -> Result<Self, MemoryError> {
        // SAFETY: The caller-facing ABI permits a null pointer, which is
        // rejected before a reference is formed. A non-null ExecEnv is owned
        // by Wanco for the duration of the host call.
        let exec_env = unsafe { exec_env.as_ref() }.ok_or(MemoryError::InvalidEnvironment)?;
        let pages = usize::try_from(exec_env.memory_size_pages)
            .map_err(|_| MemoryError::InvalidEnvironment)?;
        if pages > WASM32_MAX_PAGES {
            return Err(MemoryError::InvalidEnvironment);
        }
        let length = pages.checked_mul(WASM_PAGE_BYTES).ok_or(MemoryError::InvalidEnvironment)?;
        if length != 0 && exec_env.memory_base.is_null() {
            return Err(MemoryError::InvalidEnvironment);
        }
        Ok(Self { base: exec_env.memory_base, length })
    }

    #[cfg(test)]
    pub(crate) fn length(&self) -> usize {
        self.length
    }

    pub(crate) fn validate(&self, offset: i32, length: usize) -> Result<usize, MemoryError> {
        let offset = offset as u32 as usize;
        let end = offset.checked_add(length).ok_or(MemoryError::OutOfBounds)?;
        if end > self.length {
            return Err(MemoryError::OutOfBounds);
        }
        Ok(offset)
    }

    pub(crate) fn read(&self, offset: i32, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = self.validate(offset, length)?;
        let mut bytes = vec![0_u8; length];
        if length != 0 {
            // SAFETY: `validate` proves the entire source range lies in the
            // linear memory advertised by Wanco. `bytes` is a disjoint owned
            // destination with exactly `length` initialized bytes.
            unsafe {
                ptr::copy_nonoverlapping(self.base.add(offset), bytes.as_mut_ptr(), length);
            }
        }
        Ok(bytes)
    }

    pub(crate) fn write(&self, offset: i32, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = self.validate(offset, bytes.len())?;
        if !bytes.is_empty() {
            // SAFETY: `validate` proves the entire destination range lies in
            // Wanco linear memory, and the source slice is valid and disjoint.
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.add(offset), bytes.len());
            }
        }
        Ok(())
    }

    pub(crate) fn read_u8(&self, offset: i32) -> Result<u8, MemoryError> {
        Ok(self.read(offset, 1)?[0])
    }

    pub(crate) fn read_u16(&self, offset: i32) -> Result<u16, MemoryError> {
        let bytes: [u8; 2] =
            self.read(offset, 2)?.try_into().map_err(|_| MemoryError::OutOfBounds)?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub(crate) fn read_u32(&self, offset: i32) -> Result<u32, MemoryError> {
        let bytes: [u8; 4] =
            self.read(offset, 4)?.try_into().map_err(|_| MemoryError::OutOfBounds)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(crate) fn read_u64(&self, offset: i32) -> Result<u64, MemoryError> {
        let bytes: [u8; 8] =
            self.read(offset, 8)?.try_into().map_err(|_| MemoryError::OutOfBounds)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn write_u32(&self, offset: i32, value: u32) -> Result<(), MemoryError> {
        self.write(offset, &value.to_le_bytes())
    }

    pub(crate) fn write_u64(&self, offset: i32, value: u64) -> Result<(), MemoryError> {
        self.write(offset, &value.to_le_bytes())
    }

    pub(crate) fn read_iovecs(
        &self,
        descriptors: i32,
        count: i32,
    ) -> Result<(Vec<Iovec>, usize), MemoryError> {
        let count = count as u32 as usize;
        if count > MAX_IOVECS {
            return Err(MemoryError::TooLarge);
        }
        let descriptor_bytes = count.checked_mul(8).ok_or(MemoryError::TooLarge)?;
        self.validate(descriptors, descriptor_bytes)?;
        let mut iovecs = Vec::with_capacity(count);
        let mut total = 0_usize;
        for index in 0..count {
            let relative = index.checked_mul(8).ok_or(MemoryError::TooLarge)?;
            let descriptor = (descriptors as u32)
                .checked_add(u32::try_from(relative).map_err(|_| MemoryError::TooLarge)?)
                .ok_or(MemoryError::OutOfBounds)? as i32;
            let offset = self.read_u32(descriptor)?;
            let length = self.read_u32(descriptor.wrapping_add(4))?;
            self.validate(offset as i32, length as usize)?;
            total = total.checked_add(length as usize).ok_or(MemoryError::TooLarge)?;
            if total > MAX_IO_BYTES {
                return Err(MemoryError::TooLarge);
            }
            iovecs.push(Iovec { offset, length });
        }
        Ok((iovecs, total))
    }

    pub(crate) fn gather(&self, iovecs: &[Iovec], total: usize) -> Result<Vec<u8>, MemoryError> {
        if total > MAX_IO_BYTES {
            return Err(MemoryError::TooLarge);
        }
        let mut output = Vec::with_capacity(total);
        for iovec in iovecs {
            output.extend_from_slice(&self.read(iovec.offset as i32, iovec.length as usize)?);
        }
        if output.len() != total {
            return Err(MemoryError::OutOfBounds);
        }
        Ok(output)
    }

    pub(crate) fn scatter(&self, iovecs: &[Iovec], bytes: &[u8]) -> Result<(), MemoryError> {
        let capacity = iovecs.iter().try_fold(0_usize, |total, iovec| {
            total.checked_add(iovec.length as usize).ok_or(MemoryError::TooLarge)
        })?;
        if bytes.len() > capacity {
            return Err(MemoryError::OutOfBounds);
        }
        let mut source = 0_usize;
        for iovec in iovecs {
            if source == bytes.len() {
                break;
            }
            let count = (iovec.length as usize).min(bytes.len() - source);
            self.write(iovec.offset as i32, &bytes[source..source + count])?;
            source += count;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;

    use super::*;

    fn environment(bytes: &mut [u8], pages: i32) -> ExecEnv {
        ExecEnv {
            memory_base: bytes.as_mut_ptr(),
            memory_size_pages: pages,
            migration_state: 0,
            argc: 0,
            argv: core::ptr::null_mut::<*mut c_char>(),
        }
    }

    #[test]
    fn uses_the_advertised_page_count_and_accepts_last_byte() {
        let mut bytes = vec![0_u8; WASM_PAGE_BYTES * 2];
        let environment = environment(&mut bytes, 2);
        let memory = GuestMemory::from_exec_env(&environment).unwrap();
        assert_eq!(memory.length(), WASM_PAGE_BYTES * 2);
        memory.write((memory.length() - 1) as i32, &[0x5a]).unwrap();
        assert_eq!(bytes[WASM_PAGE_BYTES * 2 - 1], 0x5a);
        assert_eq!(memory.write(memory.length() as i32, &[1]), Err(MemoryError::OutOfBounds));
    }

    #[test]
    fn rejects_null_negative_and_wrapping_environments() {
        assert!(matches!(
            GuestMemory::from_exec_env(core::ptr::null()),
            Err(MemoryError::InvalidEnvironment)
        ));
        let negative = ExecEnv {
            memory_base: core::ptr::dangling_mut(),
            memory_size_pages: -1,
            migration_state: 0,
            argc: 0,
            argv: core::ptr::null_mut(),
        };
        assert!(matches!(
            GuestMemory::from_exec_env(&negative),
            Err(MemoryError::InvalidEnvironment)
        ));
        let null = ExecEnv {
            memory_base: core::ptr::null_mut(),
            memory_size_pages: 1,
            migration_state: 0,
            argc: 0,
            argv: core::ptr::null_mut(),
        };
        assert!(matches!(GuestMemory::from_exec_env(&null), Err(MemoryError::InvalidEnvironment)));
        let too_large = ExecEnv {
            memory_base: core::ptr::dangling_mut(),
            memory_size_pages: (WASM32_MAX_PAGES + 1) as i32,
            migration_state: 0,
            argc: 0,
            argv: core::ptr::null_mut(),
        };
        assert!(matches!(
            GuestMemory::from_exec_env(&too_large),
            Err(MemoryError::InvalidEnvironment)
        ));
    }

    #[test]
    fn iovecs_are_checked_before_data_is_gathered() {
        let mut bytes = vec![0_u8; WASM_PAGE_BYTES];
        bytes[100..104].copy_from_slice(&200_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&3_u32.to_le_bytes());
        bytes[108..112].copy_from_slice(&(WASM_PAGE_BYTES as u32 - 1).to_le_bytes());
        bytes[112..116].copy_from_slice(&2_u32.to_le_bytes());
        bytes[200..203].copy_from_slice(b"abc");
        let environment = environment(&mut bytes, 1);
        let memory = GuestMemory::from_exec_env(&environment).unwrap();
        assert_eq!(memory.read_iovecs(100, 2), Err(MemoryError::OutOfBounds));
        bytes[112..116].copy_from_slice(&1_u32.to_le_bytes());
        let (iovecs, total) = memory.read_iovecs(100, 2).unwrap();
        assert_eq!(total, 4);
        assert_eq!(memory.gather(&iovecs, total).unwrap(), b"abc\0");
    }

    #[test]
    fn iovec_count_and_aggregate_size_are_bounded() {
        let pages = (MAX_IO_BYTES / WASM_PAGE_BYTES) + 2;
        let mut bytes = vec![0_u8; WASM_PAGE_BYTES * pages];
        let environment = environment(&mut bytes, pages as i32);
        let memory = GuestMemory::from_exec_env(&environment).unwrap();
        assert_eq!(memory.read_iovecs(0, (MAX_IOVECS + 1) as i32), Err(MemoryError::TooLarge));
        bytes[0..4].copy_from_slice(&8_u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&((MAX_IO_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(memory.read_iovecs(0, 1), Err(MemoryError::TooLarge));
    }
}
