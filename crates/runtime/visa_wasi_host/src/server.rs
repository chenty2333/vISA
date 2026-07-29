use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

use visa_wasi_protocol::{
    AdminRequest, AdminResponse, GuestRequest, GuestResponse, MAX_FRAME_BYTES, WireRequest,
    WireResponse, decode_request, decode_response, encode_request, encode_response,
};

use crate::{Provider, ProviderError};

pub struct ProviderServer;

impl ProviderServer {
    pub fn serve(mut provider: Provider, socket: &Path) -> Result<(), ProviderError> {
        require_private_parent(socket)?;
        if fs::symlink_metadata(socket).is_ok() {
            return Err(ProviderError::AlreadyExists);
        }
        let listener = UnixListener::bind(socket)?;
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(socket)?;
        let guard = SocketGuard {
            path: socket.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        for incoming in listener.incoming() {
            let mut stream = incoming?;
            let request_bytes = match read_frame(&mut stream) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let request = match decode_request(&request_bytes) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let response = match request {
                WireRequest::Guest(request) => WireResponse::Guest(provider.handle_guest(request)),
                WireRequest::Admin(request) => WireResponse::Admin(provider.handle_admin(request)),
            };
            let response_bytes = encode_response(&response).map_err(|_| ProviderError::Codec)?;
            write_frame(&mut stream, &response_bytes)?;
            if provider.shutdown_requested() {
                break;
            }
        }
        drop(listener);
        guard.remove()
    }
}

pub fn send_admin(socket: &Path, request: &AdminRequest) -> Result<AdminResponse, ProviderError> {
    match exchange(socket, &WireRequest::Admin(request.clone()))? {
        WireResponse::Admin(response) => Ok(response),
        WireResponse::Guest(_) => Err(ProviderError::Integrity("wrong response family")),
    }
}

pub fn send_guest(socket: &Path, request: &GuestRequest) -> Result<GuestResponse, ProviderError> {
    match exchange(socket, &WireRequest::Guest(request.clone()))? {
        WireResponse::Guest(response) => Ok(response),
        WireResponse::Admin(_) => Err(ProviderError::Integrity("wrong response family")),
    }
}

fn exchange(socket: &Path, request: &WireRequest) -> Result<WireResponse, ProviderError> {
    let bytes = encode_request(request).map_err(|_| ProviderError::Codec)?;
    let mut stream = UnixStream::connect(socket)?;
    write_frame(&mut stream, &bytes)?;
    let response = read_frame(&mut stream)?;
    decode_response(&response).map_err(|_| ProviderError::Codec)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ProviderError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProviderError::Invalid("wire frame length"));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), ProviderError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProviderError::Invalid("wire frame length"));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| ProviderError::Invalid("wire frame length"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn require_private_parent(socket: &Path) -> Result<(), ProviderError> {
    let parent = socket
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(ProviderError::Invalid("socket has no parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProviderError::Invalid("socket parent is not private"));
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketGuard {
    fn remove(self) -> Result<(), ProviderError> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(ProviderError::Integrity("provider socket path was replaced"));
        }
        fs::remove_file(&self.path)?;
        Ok(())
    }
}
