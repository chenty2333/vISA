use std::{
    env,
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{FileTypeExt, MetadataExt},
    },
    sync::OnceLock,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use visa_wasi_protocol::{
    DirectoryEntry, FdStat, FileStat, LockLevel, Operation, OperationResult, SeekWhence, errno,
};

use crate::{
    ExecEnv,
    memory::{GuestMemory, Iovec, MAX_IO_BYTES, MemoryError},
    transport,
};

const ERRNO_FAULT: u16 = 21;
const FILETYPE_CHARACTER_DEVICE: u8 = 2;
const RIGHT_FD_READ: u64 = 1 << 1;
const RIGHT_FD_WRITE: u64 = 1 << 6;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_ARGUMENTS: usize = 4_096;
const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 16_384;
const POLL_MAX_SUBSCRIPTIONS: usize = 4_096;
const EVENTTYPE_CLOCK: u8 = 0;
const EVENTTYPE_FD_READ: u8 = 1;
const EVENTTYPE_FD_WRITE: u8 = 2;
const SUBSCRIPTION_BYTES: usize = 48;
const EVENT_BYTES: usize = 32;
const SUBCLOCK_ABSTIME: u16 = 1;
const PLATFORM_ENVIRONMENT: [&[u8]; 6] = [
    b"VISA_WASI_SOCKET",
    b"VISA_WASI_SESSION_ID",
    b"VISA_WASI_OWNER_ID",
    b"VISA_WASI_CLIENT_ID",
    b"VISA_WASI_GUEST_CAPABILITY",
    b"VISA_WASI_AUTHORITY_EPOCH",
];

static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn result_code(result: Result<(), u16>) -> i32 {
    match result {
        Ok(()) => i32::from(errno::SUCCESS),
        Err(value) => i32::from(value),
    }
}

fn memory(exec_env: *const ExecEnv) -> Result<GuestMemory, u16> {
    GuestMemory::from_exec_env(exec_env).map_err(memory_errno)
}

fn memory_errno(error: MemoryError) -> u16 {
    match error {
        MemoryError::InvalidEnvironment | MemoryError::OutOfBounds => ERRNO_FAULT,
        MemoryError::TooLarge => errno::INVAL,
    }
}

fn as_u16(value: i32) -> Result<u16, u16> {
    u16::try_from(value as u32).map_err(|_| errno::INVAL)
}

fn masked_u16(value: i32, allowed: u16) -> Result<u16, u16> {
    let value = as_u16(value)?;
    if value & !allowed != 0 {
        return Err(errno::INVAL);
    }
    Ok(value)
}

fn lookup_flags(value: i32) -> Result<u32, u16> {
    let value = value as u32;
    if value & !1 != 0 {
        return Err(errno::INVAL);
    }
    Ok(value)
}

fn file_time_flags(value: i32) -> Result<u16, u16> {
    let value = masked_u16(value, 0x0f)?;
    if value & 0x03 == 0x03 || value & 0x0c == 0x0c {
        return Err(errno::INVAL);
    }
    Ok(value)
}

fn guest_path(memory: &GuestMemory, pointer: i32, length: i32) -> Result<Vec<u8>, u16> {
    let length = length as u32 as usize;
    if length > MAX_PATH_BYTES {
        return Err(errno::NAMETOOLONG);
    }
    let path = memory.read(pointer, length).map_err(memory_errno)?;
    if path.contains(&0) {
        return Err(errno::INVAL);
    }
    Ok(path)
}

fn provider(operation: Operation) -> Result<OperationResult, u16> {
    transport::invoke(operation)
}

fn expect_none(operation: Operation) -> Result<(), u16> {
    match provider(operation)? {
        OperationResult::None => Ok(()),
        _ => Err(errno::IO),
    }
}

fn guest_arguments(exec_env: *const ExecEnv) -> Result<Vec<Vec<u8>>, u16> {
    // SAFETY: Null is checked before forming the reference. Wanco owns this
    // native execution record and its argv array for the entire host call.
    let exec_env = unsafe { exec_env.as_ref() }.ok_or(ERRNO_FAULT)?;
    let argc = usize::try_from(exec_env.argc).map_err(|_| errno::INVAL)?;
    if argc > MAX_ARGUMENTS || (argc != 0 && exec_env.argv.is_null()) {
        return Err(errno::INVAL);
    }
    let mut arguments = Vec::new();
    let mut after_separator = false;
    let mut bytes = 0_usize;
    for index in 0..argc {
        // SAFETY: The Wanco runtime supplies an argv array containing `argc`
        // valid NUL-terminated native strings.
        let pointer = unsafe { *exec_env.argv.add(index) };
        if pointer.is_null() {
            return Err(errno::INVAL);
        }
        // SAFETY: This is the native process argv contract guaranteed by
        // Wanco, not a guest-controlled linear-memory pointer.
        let argument = unsafe { CStr::from_ptr(pointer) }.to_bytes();
        if argument == b"--" {
            after_separator = true;
            continue;
        }
        if index != 0 && !after_separator {
            continue;
        }
        bytes = bytes
            .checked_add(argument.len().checked_add(1).ok_or(errno::INVAL)?)
            .ok_or(errno::INVAL)?;
        if bytes > MAX_ARGUMENT_BYTES {
            return Err(errno::INVAL);
        }
        arguments.push(argument.to_vec());
    }
    Ok(arguments)
}

fn guest_environment() -> Result<Vec<Vec<u8>>, u16> {
    let mut values = Vec::new();
    let mut total = 0_usize;
    for (name, value) in env::vars_os() {
        let name = name.as_bytes();
        if PLATFORM_ENVIRONMENT.contains(&name) || name.contains(&0) {
            continue;
        }
        let value = value.into_vec();
        if value.contains(&0) {
            continue;
        }
        let mut entry = Vec::with_capacity(name.len() + value.len() + 1);
        entry.extend_from_slice(name);
        entry.push(b'=');
        entry.extend_from_slice(&value);
        total = total
            .checked_add(entry.len().checked_add(1).ok_or(errno::INVAL)?)
            .ok_or(errno::INVAL)?;
        if total > MAX_ARGUMENT_BYTES || values.len() >= MAX_ENVIRONMENT_ENTRIES {
            return Err(errno::INVAL);
        }
        values.push(entry);
    }
    values.sort();
    Ok(values)
}

fn write_string_vector(
    memory: &GuestMemory,
    pointers: i32,
    buffer: i32,
    values: &[Vec<u8>],
) -> Result<(), u16> {
    let pointer_bytes = values.len().checked_mul(4).ok_or(errno::INVAL)?;
    let buffer_bytes = values
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(value.len() + 1).ok_or(errno::INVAL))?;
    memory.validate(pointers, pointer_bytes).map_err(memory_errno)?;
    memory.validate(buffer, buffer_bytes).map_err(memory_errno)?;
    let mut cursor = buffer as u32;
    for (index, value) in values.iter().enumerate() {
        let pointer_at = (pointers as u32)
            .checked_add(u32::try_from(index * 4).map_err(|_| errno::INVAL)?)
            .ok_or(ERRNO_FAULT)?;
        memory.write_u32(pointer_at as i32, cursor).map_err(memory_errno)?;
        memory.write(cursor as i32, value).map_err(memory_errno)?;
        let terminator = cursor.checked_add(value.len() as u32).ok_or(ERRNO_FAULT)?;
        memory.write(terminator as i32, &[0]).map_err(memory_errno)?;
        cursor = terminator.checked_add(1).ok_or(ERRNO_FAULT)?;
    }
    Ok(())
}

fn write_sizes(
    memory: &GuestMemory,
    count_pointer: i32,
    bytes_pointer: i32,
    values: &[Vec<u8>],
) -> Result<(), u16> {
    memory.validate(count_pointer, 4).map_err(memory_errno)?;
    memory.validate(bytes_pointer, 4).map_err(memory_errno)?;
    let count = u32::try_from(values.len()).map_err(|_| errno::OVERFLOW)?;
    let bytes = values.iter().try_fold(0_u32, |total, value| {
        total
            .checked_add(u32::try_from(value.len() + 1).map_err(|_| errno::OVERFLOW)?)
            .ok_or(errno::OVERFLOW)
    })?;
    memory.write_u32(count_pointer, count).map_err(memory_errno)?;
    memory.write_u32(bytes_pointer, bytes).map_err(memory_errno)
}

fn local_fdstat(fd: u32) -> Option<FdStat> {
    let rights = match fd {
        0 => RIGHT_FD_READ,
        1 | 2 => RIGHT_FD_WRITE,
        _ => return None,
    };
    Some(FdStat {
        file_type: local_metadata(fd)
            .as_ref()
            .map_or(FILETYPE_CHARACTER_DEVICE, |metadata| wasi_file_type(&metadata.file_type())),
        flags: 0,
        rights_base: rights,
        rights_inheriting: 0,
    })
}

fn local_metadata(fd: u32) -> Option<std::fs::Metadata> {
    std::fs::metadata(format!("/proc/self/fd/{fd}")).ok()
}

fn wasi_file_type(file_type: &std::fs::FileType) -> u8 {
    if file_type.is_block_device() {
        1
    } else if file_type.is_char_device() {
        2
    } else if file_type.is_dir() {
        3
    } else if file_type.is_file() {
        4
    } else if file_type.is_socket() {
        6
    } else if file_type.is_symlink() {
        7
    } else {
        0
    }
}

fn unix_time_ns(seconds: i64, nanoseconds: i64) -> u64 {
    let total = i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds);
    total.clamp(0, i128::from(u64::MAX)) as u64
}

fn encode_fdstat(stat: FdStat) -> [u8; 24] {
    let mut output = [0_u8; 24];
    output[0] = stat.file_type;
    output[2..4].copy_from_slice(&stat.flags.to_le_bytes());
    output[8..16].copy_from_slice(&stat.rights_base.to_le_bytes());
    output[16..24].copy_from_slice(&stat.rights_inheriting.to_le_bytes());
    output
}

fn encode_filestat(stat: FileStat) -> [u8; 64] {
    let mut output = [0_u8; 64];
    output[0..8].copy_from_slice(&stat.device.to_le_bytes());
    output[8..16].copy_from_slice(&stat.inode.to_le_bytes());
    output[16] = stat.file_type;
    output[24..32].copy_from_slice(&stat.link_count.to_le_bytes());
    output[32..40].copy_from_slice(&stat.size.to_le_bytes());
    output[40..48].copy_from_slice(&stat.accessed_ns.to_le_bytes());
    output[48..56].copy_from_slice(&stat.modified_ns.to_le_bytes());
    output[56..64].copy_from_slice(&stat.changed_ns.to_le_bytes());
    output
}

fn local_filestat(fd: u32) -> Option<FileStat> {
    local_fdstat(fd).map(|stat| {
        local_metadata(fd).map_or(
            FileStat {
                device: 0,
                inode: u64::from(fd),
                file_type: stat.file_type,
                link_count: 1,
                size: 0,
                accessed_ns: 0,
                modified_ns: 0,
                changed_ns: 0,
            },
            |metadata| FileStat {
                device: metadata.dev(),
                inode: metadata.ino(),
                file_type: wasi_file_type(&metadata.file_type()),
                link_count: metadata.nlink(),
                size: metadata.size(),
                accessed_ns: unix_time_ns(metadata.atime(), metadata.atime_nsec()),
                modified_ns: unix_time_ns(metadata.mtime(), metadata.mtime_nsec()),
                changed_ns: unix_time_ns(metadata.ctime(), metadata.ctime_nsec()),
            },
        )
    })
}

fn read_iovecs(memory: &GuestMemory, pointer: i32, count: i32) -> Result<(Vec<Iovec>, usize), u16> {
    memory.read_iovecs(pointer, count).map_err(memory_errno)
}

fn local_write(fd: u32, bytes: &[u8]) -> Result<(), u16> {
    match fd {
        1 => {
            let mut output = std::io::stdout().lock();
            output.write_all(bytes).and_then(|()| output.flush()).map_err(|_| errno::IO)
        }
        2 => {
            let mut output = std::io::stderr().lock();
            output.write_all(bytes).and_then(|()| output.flush()).map_err(|_| errno::IO)
        }
        _ => Err(errno::BADF),
    }
}

fn local_read(fd: u32, length: usize) -> Result<Vec<u8>, u16> {
    if fd != 0 {
        return Err(errno::BADF);
    }
    let mut bytes = vec![0_u8; length];
    let count = std::io::stdin().lock().read(&mut bytes).map_err(|_| errno::IO)?;
    bytes.truncate(count);
    Ok(bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_args_sizes_get(
    exec_env: *const ExecEnv,
    count: i32,
    bytes: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        write_sizes(&memory, count, bytes, &guest_arguments(exec_env)?)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_args_get(
    exec_env: *const ExecEnv,
    pointers: i32,
    buffer: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        write_string_vector(&memory, pointers, buffer, &guest_arguments(exec_env)?)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_environ_sizes_get(
    exec_env: *const ExecEnv,
    count: i32,
    bytes: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        write_sizes(&memory, count, bytes, &guest_environment()?)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_environ_get(
    exec_env: *const ExecEnv,
    pointers: i32,
    buffer: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        write_string_vector(&memory, pointers, buffer, &guest_environment()?)
    })())
}

fn clock_now(clock: u32) -> Result<u64, u16> {
    match clock {
        0 => {
            let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| errno::IO)?;
            u64::try_from(elapsed.as_nanos()).map_err(|_| errno::OVERFLOW)
        }
        1..=3 => {
            let elapsed = MONOTONIC_ORIGIN.get_or_init(Instant::now).elapsed();
            u64::try_from(elapsed.as_nanos()).map_err(|_| errno::OVERFLOW)
        }
        _ => Err(errno::INVAL),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_clock_res_get(
    exec_env: *const ExecEnv,
    clock: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 8).map_err(memory_errno)?;
        match clock as u32 {
            0..=3 => memory.write_u64(result, 1).map_err(memory_errno),
            _ => Err(errno::INVAL),
        }
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_clock_time_get(
    exec_env: *const ExecEnv,
    clock: i32,
    _precision: i64,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 8).map_err(memory_errno)?;
        memory.write_u64(result, clock_now(clock as u32)?).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_random_get(
    exec_env: *const ExecEnv,
    buffer: i32,
    length: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let length = length as u32 as usize;
        memory.validate(buffer, length).map_err(memory_errno)?;
        let mut random = File::open("/dev/urandom").map_err(|_| errno::IO)?;
        let mut scratch = vec![0_u8; length.min(64 * 1024)];
        let mut completed = 0_usize;
        while completed < length {
            let count = scratch.len().min(length - completed);
            random.read_exact(&mut scratch[..count]).map_err(|_| errno::IO)?;
            let offset = (buffer as u32)
                .checked_add(u32::try_from(completed).map_err(|_| ERRNO_FAULT)?)
                .ok_or(ERRNO_FAULT)?;
            memory.write(offset as i32, &scratch[..count]).map_err(memory_errno)?;
            completed += count;
        }
        Ok(())
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_sched_yield(_exec_env: *const ExecEnv) -> i32 {
    thread::yield_now();
    i32::from(errno::SUCCESS)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_proc_raise(
    _exec_env: *const ExecEnv,
    _signal: i32,
) -> i32 {
    i32::from(errno::NOTSUP)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_proc_exit(_exec_env: *const ExecEnv, status: i32) {
    std::process::exit(status);
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_advise(
    _exec_env: *const ExecEnv,
    fd: i32,
    offset: i64,
    length: i64,
    advice: i32,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::BADF);
    }
    result_code((|| {
        let advice = u8::try_from(advice as u32).map_err(|_| errno::INVAL)?;
        if advice > 5 {
            return Err(errno::INVAL);
        }
        expect_none(Operation::FdAdvise {
            fd: fd as u32,
            offset: offset as u64,
            length: length as u64,
            advice,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_allocate(
    _exec_env: *const ExecEnv,
    fd: i32,
    offset: i64,
    length: i64,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::BADF);
    }
    result_code(expect_none(Operation::FdAllocate {
        fd: fd as u32,
        offset: offset as u64,
        length: length as u64,
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_close(_exec_env: *const ExecEnv, fd: i32) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::SUCCESS);
    }
    result_code(expect_none(Operation::FdClose { fd: fd as u32 }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_datasync(_exec_env: *const ExecEnv, fd: i32) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::SUCCESS);
    }
    result_code(expect_none(Operation::FdDataSync { fd: fd as u32 }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_sync(_exec_env: *const ExecEnv, fd: i32) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::SUCCESS);
    }
    result_code(expect_none(Operation::FdSync { fd: fd as u32 }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_fdstat_get(
    exec_env: *const ExecEnv,
    fd: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 24).map_err(memory_errno)?;
        let stat = if let Some(stat) = local_fdstat(fd as u32) {
            stat
        } else {
            match provider(Operation::FdStatGet { fd: fd as u32 })? {
                OperationResult::FdStat(stat) => stat,
                _ => return Err(errno::IO),
            }
        };
        memory.write(result, &encode_fdstat(stat)).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_fdstat_set_flags(
    _exec_env: *const ExecEnv,
    fd: i32,
    flags: i32,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::NOTSUP);
    }
    result_code((|| {
        expect_none(Operation::FdStatSetFlags { fd: fd as u32, flags: masked_u16(flags, 0x1f)? })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_fdstat_set_rights(
    _exec_env: *const ExecEnv,
    fd: i32,
    rights_base: i64,
    rights_inheriting: i64,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::NOTSUP);
    }
    result_code(expect_none(Operation::FdStatSetRights {
        fd: fd as u32,
        rights_base: rights_base as u64,
        rights_inheriting: rights_inheriting as u64,
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_filestat_get(
    exec_env: *const ExecEnv,
    fd: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 64).map_err(memory_errno)?;
        let stat = if let Some(stat) = local_filestat(fd as u32) {
            stat
        } else {
            match provider(Operation::FdFileStatGet { fd: fd as u32 })? {
                OperationResult::FileStat(stat) => stat,
                _ => return Err(errno::IO),
            }
        };
        memory.write(result, &encode_filestat(stat)).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_filestat_set_size(
    _exec_env: *const ExecEnv,
    fd: i32,
    size: i64,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::BADF);
    }
    result_code(expect_none(Operation::FdFileStatSetSize { fd: fd as u32, size: size as u64 }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_filestat_set_times(
    _exec_env: *const ExecEnv,
    fd: i32,
    atim: i64,
    mtim: i64,
    fst_flags: i32,
) -> i32 {
    if (fd as u32) < 3 {
        return i32::from(errno::BADF);
    }
    result_code((|| {
        expect_none(Operation::FdFileStatSetTimes {
            fd: fd as u32,
            atim: atim as u64,
            mtim: mtim as u64,
            fst_flags: file_time_flags(fst_flags)?,
        })
    })())
}

fn fd_read_impl(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs_pointer: i32,
    iovecs_count: i32,
    offset: Option<i64>,
    result: i32,
) -> Result<(), u16> {
    let memory = memory(exec_env)?;
    memory.validate(result, 4).map_err(memory_errno)?;
    let (iovecs, capacity) = read_iovecs(&memory, iovecs_pointer, iovecs_count)?;
    let bytes = if (fd as u32) < 3 {
        if offset.is_some() {
            return Err(errno::SPIPE);
        }
        local_read(fd as u32, capacity)?
    } else {
        let length = u32::try_from(capacity).map_err(|_| errno::INVAL)?;
        let operation = offset.map_or(Operation::FdRead { fd: fd as u32, length }, |offset| {
            Operation::FdPread { fd: fd as u32, length, offset: offset as u64 }
        });
        match provider(operation)? {
            OperationResult::Bytes(bytes) => bytes,
            _ => return Err(errno::IO),
        }
    };
    if bytes.len() > capacity {
        return Err(errno::IO);
    }
    memory.scatter(&iovecs, &bytes).map_err(memory_errno)?;
    memory
        .write_u32(result, u32::try_from(bytes.len()).map_err(|_| errno::OVERFLOW)?)
        .map_err(memory_errno)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_read(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    result: i32,
) -> i32 {
    result_code(fd_read_impl(exec_env, fd, iovecs, iovecs_len, None, result))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_pread(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    offset: i64,
    result: i32,
) -> i32 {
    result_code(fd_read_impl(exec_env, fd, iovecs, iovecs_len, Some(offset), result))
}

fn fd_write_impl(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs_pointer: i32,
    iovecs_count: i32,
    offset: Option<i64>,
    result: i32,
) -> Result<(), u16> {
    let memory = memory(exec_env)?;
    memory.validate(result, 4).map_err(memory_errno)?;
    let (iovecs, total) = read_iovecs(&memory, iovecs_pointer, iovecs_count)?;
    let bytes = memory.gather(&iovecs, total).map_err(memory_errno)?;
    let written = if (fd as u32) < 3 {
        if offset.is_some() {
            return Err(errno::SPIPE);
        }
        local_write(fd as u32, &bytes)?;
        bytes.len()
    } else {
        let operation = match offset {
            Some(offset) => Operation::FdPwrite { fd: fd as u32, bytes, offset: offset as u64 },
            None => Operation::FdWrite { fd: fd as u32, bytes },
        };
        match provider(operation)? {
            OperationResult::Count(count) => count as usize,
            _ => return Err(errno::IO),
        }
    };
    if written > total {
        return Err(errno::IO);
    }
    memory
        .write_u32(result, u32::try_from(written).map_err(|_| errno::OVERFLOW)?)
        .map_err(memory_errno)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_write(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    result: i32,
) -> i32 {
    result_code(fd_write_impl(exec_env, fd, iovecs, iovecs_len, None, result))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_pwrite(
    exec_env: *const ExecEnv,
    fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    offset: i64,
    result: i32,
) -> i32 {
    result_code(fd_write_impl(exec_env, fd, iovecs, iovecs_len, Some(offset), result))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_seek(
    exec_env: *const ExecEnv,
    fd: i32,
    delta: i64,
    whence: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 8).map_err(memory_errno)?;
        if (fd as u32) < 3 {
            return Err(errno::SPIPE);
        }
        let whence = match whence as u32 {
            0 => SeekWhence::Set,
            1 => SeekWhence::Current,
            2 => SeekWhence::End,
            _ => return Err(errno::INVAL),
        };
        let offset = match provider(Operation::FdSeek { fd: fd as u32, delta, whence })? {
            OperationResult::Offset(offset) => offset,
            _ => return Err(errno::IO),
        };
        memory.write_u64(result, offset).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_tell(
    exec_env: *const ExecEnv,
    fd: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 8).map_err(memory_errno)?;
        if (fd as u32) < 3 {
            return Err(errno::SPIPE);
        }
        let offset = match provider(Operation::FdTell { fd: fd as u32 })? {
            OperationResult::Offset(offset) => offset,
            _ => return Err(errno::IO),
        };
        memory.write_u64(result, offset).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_renumber(
    _exec_env: *const ExecEnv,
    from: i32,
    to: i32,
) -> i32 {
    if (from as u32) < 3 || (to as u32) < 3 {
        return i32::from(errno::BADF);
    }
    result_code(expect_none(Operation::FdRenumber { from: from as u32, to: to as u32 }))
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_prestat_get(
    exec_env: *const ExecEnv,
    fd: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 8).map_err(memory_errno)?;
        if (fd as u32) < 3 {
            return Err(errno::BADF);
        }
        let name = match provider(Operation::FdPrestatGet { fd: fd as u32 })? {
            OperationResult::Prestat { name } => name,
            _ => return Err(errno::IO),
        };
        let mut encoded = [0_u8; 8];
        encoded[0] = 0;
        encoded[4..8].copy_from_slice(
            &u32::try_from(name.len()).map_err(|_| errno::OVERFLOW)?.to_le_bytes(),
        );
        memory.write(result, &encoded).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_prestat_dir_name(
    exec_env: *const ExecEnv,
    fd: i32,
    path: i32,
    path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let path_len = path_len as u32 as usize;
        memory.validate(path, path_len).map_err(memory_errno)?;
        if (fd as u32) < 3 {
            return Err(errno::BADF);
        }
        let name = match provider(Operation::FdPrestatDirName { fd: fd as u32 })? {
            OperationResult::Prestat { name } => name,
            _ => return Err(errno::IO),
        };
        if name.len() > path_len {
            return Err(errno::NAMETOOLONG);
        }
        memory.write(path, &name).map_err(memory_errno)
    })())
}

fn encode_directory(entries: Vec<DirectoryEntry>, capacity: usize) -> Result<Vec<u8>, u16> {
    let mut output = Vec::new();
    for entry in entries {
        let name_len = u32::try_from(entry.name.len()).map_err(|_| errno::OVERFLOW)?;
        let mut encoded = Vec::with_capacity(24 + entry.name.len());
        encoded.extend_from_slice(&entry.next_cookie.to_le_bytes());
        encoded.extend_from_slice(&entry.inode.to_le_bytes());
        encoded.extend_from_slice(&name_len.to_le_bytes());
        encoded.push(entry.file_type);
        encoded.extend_from_slice(&[0_u8; 3]);
        encoded.extend_from_slice(&entry.name);
        let available = capacity.saturating_sub(output.len());
        if available == 0 {
            break;
        }
        let count = encoded.len().min(available);
        output.extend_from_slice(&encoded[..count]);
        if count != encoded.len() {
            break;
        }
    }
    Ok(output)
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_fd_readdir(
    exec_env: *const ExecEnv,
    fd: i32,
    buffer: i32,
    buffer_len: i32,
    cookie: i64,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let capacity = buffer_len as u32 as usize;
        if capacity > MAX_IO_BYTES {
            return Err(errno::INVAL);
        }
        memory.validate(buffer, capacity).map_err(memory_errno)?;
        memory.validate(result, 4).map_err(memory_errno)?;
        if (fd as u32) < 3 {
            return Err(errno::NOTDIR);
        }
        let entries = match provider(Operation::FdReadDir {
            fd: fd as u32,
            cookie: cookie as u64,
            buffer_len: capacity as u32,
        })? {
            OperationResult::Directory(entries) => entries,
            _ => return Err(errno::IO),
        };
        let encoded = encode_directory(entries, capacity)?;
        memory.write(buffer, &encoded).map_err(memory_errno)?;
        memory
            .write_u32(result, u32::try_from(encoded.len()).map_err(|_| errno::OVERFLOW)?)
            .map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_create_directory(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathCreateDirectory {
            dir_fd: dir_fd as u32,
            path: guest_path(&memory, path, path_len)?,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_filestat_get(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    lookup_flags: i32,
    path: i32,
    path_len: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 64).map_err(memory_errno)?;
        let path = guest_path(&memory, path, path_len)?;
        let stat = match provider(Operation::PathFileStatGet {
            dir_fd: dir_fd as u32,
            lookup_flags: self::lookup_flags(lookup_flags)?,
            path,
        })? {
            OperationResult::FileStat(stat) => stat,
            _ => return Err(errno::IO),
        };
        memory.write(result, &encode_filestat(stat)).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_filestat_set_times(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    lookup_flags: i32,
    path: i32,
    path_len: i32,
    atim: i64,
    mtim: i64,
    fst_flags: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathFileStatSetTimes {
            dir_fd: dir_fd as u32,
            lookup_flags: self::lookup_flags(lookup_flags)?,
            path: guest_path(&memory, path, path_len)?,
            atim: atim as u64,
            mtim: mtim as u64,
            fst_flags: file_time_flags(fst_flags)?,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_link(
    exec_env: *const ExecEnv,
    old_dir_fd: i32,
    old_lookup_flags: i32,
    old_path: i32,
    old_path_len: i32,
    new_dir_fd: i32,
    new_path: i32,
    new_path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let old_path = guest_path(&memory, old_path, old_path_len)?;
        let new_path = guest_path(&memory, new_path, new_path_len)?;
        expect_none(Operation::PathLink {
            old_dir_fd: old_dir_fd as u32,
            old_lookup_flags: lookup_flags(old_lookup_flags)?,
            old_path,
            new_dir_fd: new_dir_fd as u32,
            new_path,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_open(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    lookup_flags: i32,
    path: i32,
    path_len: i32,
    open_flags: i32,
    rights_base: i64,
    rights_inheriting: i64,
    fd_flags: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 4).map_err(memory_errno)?;
        let path = guest_path(&memory, path, path_len)?;
        let fd = match provider(Operation::PathOpen {
            dir_fd: dir_fd as u32,
            lookup_flags: self::lookup_flags(lookup_flags)?,
            path,
            open_flags: masked_u16(open_flags, 0x0f)?,
            rights_base: rights_base as u64,
            rights_inheriting: rights_inheriting as u64,
            fd_flags: masked_u16(fd_flags, 0x1f)?,
        })? {
            OperationResult::FileDescriptor(fd) => fd,
            _ => return Err(errno::IO),
        };
        memory.write_u32(result, fd).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_readlink(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
    buffer: i32,
    buffer_len: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let capacity = buffer_len as u32 as usize;
        if capacity > MAX_IO_BYTES {
            return Err(errno::INVAL);
        }
        memory.validate(buffer, capacity).map_err(memory_errno)?;
        memory.validate(result, 4).map_err(memory_errno)?;
        let path = guest_path(&memory, path, path_len)?;
        let bytes = match provider(Operation::PathReadLink {
            dir_fd: dir_fd as u32,
            path,
            buffer_len: capacity as u32,
        })? {
            OperationResult::Bytes(bytes) => bytes,
            _ => return Err(errno::IO),
        };
        if bytes.len() > capacity {
            return Err(errno::IO);
        }
        memory.write(buffer, &bytes).map_err(memory_errno)?;
        memory
            .write_u32(result, u32::try_from(bytes.len()).map_err(|_| errno::OVERFLOW)?)
            .map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_remove_directory(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathRemoveDirectory {
            dir_fd: dir_fd as u32,
            path: guest_path(&memory, path, path_len)?,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_rename(
    exec_env: *const ExecEnv,
    old_dir_fd: i32,
    old_path: i32,
    old_path_len: i32,
    new_dir_fd: i32,
    new_path: i32,
    new_path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let old_path = guest_path(&memory, old_path, old_path_len)?;
        let new_path = guest_path(&memory, new_path, new_path_len)?;
        expect_none(Operation::PathRename {
            old_dir_fd: old_dir_fd as u32,
            old_path,
            new_dir_fd: new_dir_fd as u32,
            new_path,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_symlink(
    exec_env: *const ExecEnv,
    old_path: i32,
    old_path_len: i32,
    dir_fd: i32,
    new_path: i32,
    new_path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let old_path = guest_path(&memory, old_path, old_path_len)?;
        let new_path = guest_path(&memory, new_path, new_path_len)?;
        expect_none(Operation::PathSymlink { old_path, dir_fd: dir_fd as u32, new_path })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_path_unlink_file(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathUnlinkFile {
            dir_fd: dir_fd as u32,
            path: guest_path(&memory, path, path_len)?,
        })
    })())
}

fn duration_until(clock: u32, timeout: u64, absolute: bool) -> Result<Duration, u16> {
    if !absolute {
        return Ok(Duration::from_nanos(timeout));
    }
    let now = clock_now(clock)?;
    Ok(Duration::from_nanos(timeout.saturating_sub(now)))
}

#[derive(Clone, Copy)]
struct PollSubscription {
    userdata: u64,
    event_type: u8,
    delay: Duration,
}

fn read_poll_subscription(memory: &GuestMemory, pointer: i32) -> Result<PollSubscription, u16> {
    let userdata = memory.read_u64(pointer).map_err(memory_errno)?;
    let event_type = memory.read_u8(pointer.wrapping_add(8)).map_err(memory_errno)?;
    match event_type {
        EVENTTYPE_CLOCK => {
            let clock = memory.read_u32(pointer.wrapping_add(16)).map_err(memory_errno)?;
            let timeout = memory.read_u64(pointer.wrapping_add(24)).map_err(memory_errno)?;
            let flags = memory.read_u16(pointer.wrapping_add(40)).map_err(memory_errno)?;
            if flags & !SUBCLOCK_ABSTIME != 0 {
                return Err(errno::INVAL);
            }
            Ok(PollSubscription {
                userdata,
                event_type,
                delay: duration_until(clock, timeout, flags & SUBCLOCK_ABSTIME != 0)?,
            })
        }
        EVENTTYPE_FD_READ | EVENTTYPE_FD_WRITE => {
            let _fd = memory.read_u32(pointer.wrapping_add(16)).map_err(memory_errno)?;
            Ok(PollSubscription { userdata, event_type, delay: Duration::ZERO })
        }
        _ => Err(errno::INVAL),
    }
}

fn encode_event(subscription: PollSubscription) -> [u8; EVENT_BYTES] {
    let mut event = [0_u8; EVENT_BYTES];
    event[0..8].copy_from_slice(&subscription.userdata.to_le_bytes());
    event[8..10].copy_from_slice(&errno::SUCCESS.to_le_bytes());
    event[10] = subscription.event_type;
    event
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_poll_oneoff(
    exec_env: *const ExecEnv,
    input: i32,
    output: i32,
    subscriptions: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let count = subscriptions as u32 as usize;
        if count == 0 || count > POLL_MAX_SUBSCRIPTIONS {
            return Err(errno::INVAL);
        }
        let input_bytes = count.checked_mul(SUBSCRIPTION_BYTES).ok_or(errno::INVAL)?;
        let output_bytes = count.checked_mul(EVENT_BYTES).ok_or(errno::INVAL)?;
        memory.validate(input, input_bytes).map_err(memory_errno)?;
        memory.validate(output, output_bytes).map_err(memory_errno)?;
        memory.validate(result, 4).map_err(memory_errno)?;

        let mut parsed = Vec::with_capacity(count);
        for index in 0..count {
            let offset = u32::try_from(index * SUBSCRIPTION_BYTES).map_err(|_| errno::INVAL)?;
            parsed.push(read_poll_subscription(
                &memory,
                (input as u32).checked_add(offset).ok_or(ERRNO_FAULT)? as i32,
            )?);
        }
        let delay = parsed.iter().map(|value| value.delay).min().unwrap_or(Duration::ZERO);
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let ready = parsed.into_iter().filter(|value| value.delay <= delay).collect::<Vec<_>>();
        for (index, subscription) in ready.iter().copied().enumerate() {
            let offset = u32::try_from(index * EVENT_BYTES).map_err(|_| errno::INVAL)?;
            let target = (output as u32).checked_add(offset).ok_or(ERRNO_FAULT)?;
            memory.write(target as i32, &encode_event(subscription)).map_err(memory_errno)?;
        }
        memory
            .write_u32(result, u32::try_from(ready.len()).map_err(|_| errno::OVERFLOW)?)
            .map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_sock_accept(
    exec_env: *const ExecEnv,
    _fd: i32,
    _flags: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        memory(exec_env)?.validate(result, 4).map_err(memory_errno)?;
        Err(errno::NOTSUP)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_sock_recv(
    exec_env: *const ExecEnv,
    _fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    _flags: i32,
    result_len: i32,
    result_flags: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let _ = read_iovecs(&memory, iovecs, iovecs_len)?;
        memory.validate(result_len, 4).map_err(memory_errno)?;
        memory.validate(result_flags, 2).map_err(memory_errno)?;
        Err(errno::NOTSUP)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_sock_send(
    exec_env: *const ExecEnv,
    _fd: i32,
    iovecs: i32,
    iovecs_len: i32,
    _flags: i32,
    result: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        let _ = read_iovecs(&memory, iovecs, iovecs_len)?;
        memory.validate(result, 4).map_err(memory_errno)?;
        Err(errno::NOTSUP)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_snapshot_preview1_sock_shutdown(
    _exec_env: *const ExecEnv,
    _fd: i32,
    _how: i32,
) -> i32 {
    i32::from(errno::NOTSUP)
}

fn lock_level(value: i32) -> Result<LockLevel, u16> {
    match value as u32 {
        0 => Ok(LockLevel::None),
        1 => Ok(LockLevel::Shared),
        2 => Ok(LockLevel::Reserved),
        3 => Ok(LockLevel::Pending),
        4 => Ok(LockLevel::Exclusive),
        _ => Err(errno::INVAL),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_vfs_lock(_exec_env: *const ExecEnv, fd: i32, level: i32) -> i32 {
    result_code((|| expect_none(Operation::VfsLock { fd: fd as u32, level: lock_level(level)? }))())
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_vfs_unlock(_exec_env: *const ExecEnv, fd: i32, level: i32) -> i32 {
    result_code(
        (|| expect_none(Operation::VfsUnlock { fd: fd as u32, level: lock_level(level)? }))(),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_vfs_check_reserved(exec_env: *const ExecEnv, fd: i32, result: i32) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        memory.validate(result, 4).map_err(memory_errno)?;
        let reserved = match provider(Operation::VfsCheckReserved { fd: fd as u32 })? {
            OperationResult::Reserved(reserved) => reserved,
            _ => return Err(errno::IO),
        };
        memory.write_u32(result, u32::from(reserved)).map_err(memory_errno)
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_wasi_vfs_lock(exec_env: *const ExecEnv, fd: i32, level: i32) -> i32 {
    visa_vfs_lock(exec_env, fd, level)
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_wasi_vfs_unlock(exec_env: *const ExecEnv, fd: i32, level: i32) -> i32 {
    visa_vfs_unlock(exec_env, fd, level)
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_wasi_vfs_check_reserved(
    exec_env: *const ExecEnv,
    fd: i32,
    result: i32,
) -> i32 {
    visa_vfs_check_reserved(exec_env, fd, result)
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_wasi_metadata_path_chmod(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
    mode: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathChmod {
            dir_fd: dir_fd as u32,
            path: guest_path(&memory, path, path_len)?,
            mode: mode as u32,
        })
    })())
}

#[unsafe(no_mangle)]
pub extern "C" fn visa_wasi_metadata_path_chown(
    exec_env: *const ExecEnv,
    dir_fd: i32,
    path: i32,
    path_len: i32,
    uid: i32,
    gid: i32,
) -> i32 {
    result_code((|| {
        let memory = memory(exec_env)?;
        expect_none(Operation::PathChown {
            dir_fd: dir_fd as u32,
            path: guest_path(&memory, path, path_len)?,
            uid: uid as u32,
            gid: gid as u32,
        })
    })())
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;
    use std::ffi::CString;

    use super::*;
    use crate::memory::WASM_PAGE_BYTES;

    struct Fixture {
        bytes: Vec<u8>,
        arguments: Vec<CString>,
        pointers: Vec<*mut c_char>,
        environment: ExecEnv,
    }

    impl Fixture {
        fn new(arguments: &[&str]) -> Self {
            let mut bytes = vec![0_u8; WASM_PAGE_BYTES];
            let arguments =
                arguments.iter().map(|value| CString::new(*value).unwrap()).collect::<Vec<_>>();
            let mut pointers =
                arguments.iter().map(|value| value.as_ptr().cast_mut()).collect::<Vec<_>>();
            let environment = ExecEnv {
                memory_base: bytes.as_mut_ptr(),
                memory_size_pages: 1,
                migration_state: 0,
                argc: pointers.len() as i32,
                argv: pointers.as_mut_ptr(),
            };
            Self { bytes, arguments, pointers, environment }
        }

        fn refresh(&mut self) {
            self.environment.memory_base = self.bytes.as_mut_ptr();
            self.environment.argv = self.pointers.as_mut_ptr();
            assert_eq!(self.environment.argc as usize, self.arguments.len());
        }
    }

    #[test]
    fn exec_env_layout_matches_wanco_aot_header() {
        assert_eq!(core::mem::offset_of!(ExecEnv, memory_base), 0);
        assert_eq!(core::mem::offset_of!(ExecEnv, memory_size_pages), 8);
        assert_eq!(core::mem::offset_of!(ExecEnv, migration_state), 12);
        assert_eq!(core::mem::offset_of!(ExecEnv, argc), 16);
        assert_eq!(core::mem::offset_of!(ExecEnv, argv), 24);
        assert_eq!(core::mem::size_of::<ExecEnv>(), 32);
    }

    #[test]
    fn args_follow_wanco_separator_contract() {
        let mut fixture =
            Fixture::new(&["runtime", "--restore", "checkpoint.pb", "--", "-d", "x.zst"]);
        fixture.refresh();
        assert_eq!(
            wasi_snapshot_preview1_args_sizes_get(&fixture.environment, 0, 4),
            i32::from(errno::SUCCESS)
        );
        assert_eq!(u32::from_le_bytes(fixture.bytes[0..4].try_into().unwrap()), 3);
        assert_eq!(
            wasi_snapshot_preview1_args_get(&fixture.environment, 16, 64),
            i32::from(errno::SUCCESS)
        );
        let first = u32::from_le_bytes(fixture.bytes[16..20].try_into().unwrap()) as usize;
        assert_eq!(&fixture.bytes[first..first + 8], b"runtime\0");
    }

    #[test]
    fn result_pointer_is_validated_before_stdio_side_effect() {
        let mut fixture = Fixture::new(&["runtime"]);
        fixture.refresh();
        fixture.bytes[0..4].copy_from_slice(&32_u32.to_le_bytes());
        fixture.bytes[4..8].copy_from_slice(&3_u32.to_le_bytes());
        fixture.bytes[32..35].copy_from_slice(b"abc");
        assert_eq!(
            wasi_snapshot_preview1_fd_write(&fixture.environment, 1, 0, 1, WASM_PAGE_BYTES as i32),
            i32::from(ERRNO_FAULT)
        );
    }

    #[test]
    fn structure_encodings_match_preview1_layout() {
        let fdstat = encode_fdstat(FdStat {
            file_type: 4,
            flags: 0x1234,
            rights_base: 0x0102_0304_0506_0708,
            rights_inheriting: 0x1112_1314_1516_1718,
        });
        assert_eq!(fdstat[0], 4);
        assert_eq!(&fdstat[2..4], &0x1234_u16.to_le_bytes());
        assert_eq!(u64::from_le_bytes(fdstat[8..16].try_into().unwrap()), 0x0102_0304_0506_0708);
        let filestat = encode_filestat(FileStat {
            device: 1,
            inode: 2,
            file_type: 4,
            link_count: 3,
            size: 4,
            accessed_ns: 5,
            modified_ns: 6,
            changed_ns: 7,
        });
        assert_eq!(filestat.len(), 64);
        assert_eq!(filestat[16], 4);
        assert_eq!(u64::from_le_bytes(filestat[56..64].try_into().unwrap()), 7);
    }

    #[test]
    fn invalid_lock_level_and_path_range_fail_closed() {
        assert_eq!(lock_level(5), Err(errno::INVAL));
        assert_eq!(lookup_flags(2), Err(errno::INVAL));
        assert_eq!(file_time_flags(0x03), Err(errno::INVAL));
        assert_eq!(file_time_flags(0x0c), Err(errno::INVAL));
        assert_eq!(masked_u16(0x20, 0x1f), Err(errno::INVAL));
        let mut fixture = Fixture::new(&["runtime"]);
        fixture.refresh();
        assert_eq!(
            visa_wasi_metadata_path_chmod(
                &fixture.environment,
                3,
                (WASM_PAGE_BYTES - 1) as i32,
                2,
                0o644,
            ),
            i32::from(ERRNO_FAULT)
        );
    }

    #[test]
    fn provider_binding_environment_is_not_guest_visible() {
        for name in [
            b"VISA_WASI_SOCKET".as_slice(),
            b"VISA_WASI_SESSION_ID",
            b"VISA_WASI_OWNER_ID",
            b"VISA_WASI_CLIENT_ID",
            b"VISA_WASI_GUEST_CAPABILITY",
            b"VISA_WASI_AUTHORITY_EPOCH",
        ] {
            assert!(PLATFORM_ENVIRONMENT.contains(&name));
        }
    }

    #[test]
    fn directory_encoding_truncates_only_at_guest_capacity() {
        let encoded = encode_directory(
            vec![DirectoryEntry { next_cookie: 1, inode: 9, file_type: 4, name: b"file".to_vec() }],
            26,
        )
        .unwrap();
        assert_eq!(encoded.len(), 26);
        assert_eq!(u32::from_le_bytes(encoded[16..20].try_into().unwrap()), 4);
        assert_eq!(&encoded[24..], b"fi");
    }
}
