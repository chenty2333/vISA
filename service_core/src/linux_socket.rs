use crate::net_contract::{canonical_socket_protocol, validate_linux_socket_contract};
use vmos_abi::{ERR_EBADF, ERR_EIO, ERR_EOPNOTSUPP};

pub const MAX_SOCKETS: usize = 16;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LinuxSocket {
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
    active: bool,
}

impl LinuxSocket {
    const EMPTY: Self = Self {
        socket_id: 0,
        domain: 0,
        ty: 0,
        protocol: 0,
        ready_key: 0,
        state: 0,
        active: false,
    };
}

pub struct LinuxSocketState {
    sockets: [LinuxSocket; MAX_SOCKETS],
}

impl LinuxSocketState {
    pub const fn new() -> Self {
        Self {
            sockets: [LinuxSocket::EMPTY; MAX_SOCKETS],
        }
    }

    pub fn register_socket(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
        ready_key: u64,
    ) -> Result<(), i32> {
        if !validate_linux_socket_contract(domain, ty, protocol) {
            return Err(ERR_EOPNOTSUPP);
        }
        let protocol = canonical_socket_protocol(protocol) as u32;
        for socket in &mut self.sockets {
            if !socket.active {
                *socket = LinuxSocket {
                    socket_id,
                    domain,
                    ty,
                    protocol,
                    ready_key,
                    state: 1,
                    active: true,
                };
                return Ok(());
            }
        }
        Err(ERR_EIO)
    }

    pub fn close_socket(&mut self, socket_id: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        self.sockets[index] = LinuxSocket::EMPTY;
        Ok(())
    }

    pub fn bind_socket(&mut self, socket_id: u32, _addr_len: u32) -> Result<(), i32> {
        self.set_state(socket_id, 2)
    }

    pub fn connect_socket(&mut self, socket_id: u32, _addr_len: u32) -> Result<(), i32> {
        self.set_state(socket_id, 3)
    }

    pub fn listen_socket(&mut self, socket_id: u32, _backlog: u32) -> Result<(), i32> {
        self.set_state(socket_id, 4)
    }

    pub fn accept_socket(&self, _socket_id: u32) -> Result<u32, i32> {
        Err(ERR_EOPNOTSUPP)
    }

    pub fn send_socket(&self, socket_id: u32, len: u32) -> Result<u32, i32> {
        self.socket_index(socket_id)?;
        Ok(len)
    }

    pub fn recv_socket(&self, socket_id: u32, len: u32) -> Result<u32, i32> {
        self.socket_index(socket_id)?;
        Ok(len)
    }

    pub fn setsockopt(
        &self,
        socket_id: u32,
        _level: u32,
        _optname: u32,
        _optlen: u32,
    ) -> Result<(), i32> {
        self.socket_index(socket_id)?;
        Ok(())
    }

    pub fn getsockopt(&self, socket_id: u32, _level: u32, _optname: u32) -> Result<u32, i32> {
        self.socket_index(socket_id)?;
        Ok(0)
    }

    pub fn fcntl(&self, socket_id: u32, _cmd: u32, _arg: u64) -> Result<u32, i32> {
        self.socket_index(socket_id)?;
        Ok(0)
    }

    pub fn socket_count(&self) -> u32 {
        self.sockets.iter().filter(|socket| socket.active).count() as u32
    }

    fn set_state(&mut self, socket_id: u32, state: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        self.sockets[index].state = state;
        Ok(())
    }

    fn socket_index(&self, socket_id: u32) -> Result<usize, i32> {
        self.sockets
            .iter()
            .position(|socket| socket.active && socket.socket_id == socket_id)
            .ok_or(ERR_EBADF)
    }
}

impl Default for LinuxSocketState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmos_abi::{AF_INET, SOCK_DGRAM, SOCK_STREAM};

    #[test]
    fn register_socket_enforces_network_contract() {
        let mut state = LinuxSocketState::new();

        assert!(
            state
                .register_socket(1, AF_INET, SOCK_STREAM, 0, 42)
                .is_ok()
        );
        assert_eq!(
            state.register_socket(2, AF_INET, SOCK_DGRAM, 0, 43),
            Err(ERR_EOPNOTSUPP)
        );
        assert_eq!(
            state.register_socket(3, AF_INET + 1, SOCK_STREAM, 0, 44),
            Err(ERR_EOPNOTSUPP)
        );
    }
}
