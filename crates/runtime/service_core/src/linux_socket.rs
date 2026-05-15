use vmos_abi::{
    AF_INET, ERR_EAGAIN, ERR_EBADF, ERR_ECONNREFUSED, ERR_EINVAL, ERR_EIO, ERR_EISCONN,
    ERR_EOPNOTSUPP, SOCK_STREAM,
};

use crate::net_contract::{canonical_socket_protocol, validate_linux_socket_contract};

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
    backlog: u32,
    pending_accepts: u32,
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
        backlog: 0,
        pending_accepts: 0,
        active: false,
    };
}

const SOCKET_OPEN: u32 = 1;
const SOCKET_BOUND: u32 = 2;
const SOCKET_CONNECTED: u32 = 3;
const SOCKET_LISTENING: u32 = 4;

pub struct LinuxSocketState {
    sockets: [LinuxSocket; MAX_SOCKETS],
}

impl LinuxSocketState {
    pub const fn new() -> Self {
        Self { sockets: [LinuxSocket::EMPTY; MAX_SOCKETS] }
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
                    state: SOCKET_OPEN,
                    backlog: 0,
                    pending_accepts: 0,
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
        self.set_state(socket_id, SOCKET_BOUND)
    }

    pub fn connect_socket(&mut self, socket_id: u32, _addr_len: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].state == SOCKET_CONNECTED {
            return Err(ERR_EISCONN);
        }
        if self.sockets[index].domain != AF_INET || self.sockets[index].ty != SOCK_STREAM {
            self.sockets[index].state = SOCKET_CONNECTED;
            return Ok(());
        }
        let Some(listener_index) = self.listener_index_for(index) else {
            return Err(ERR_ECONNREFUSED);
        };
        if self.sockets[listener_index].pending_accepts >= self.sockets[listener_index].backlog {
            return Err(ERR_ECONNREFUSED);
        }
        self.sockets[listener_index].pending_accepts =
            self.sockets[listener_index].pending_accepts.saturating_add(1);
        self.sockets[index].state = SOCKET_CONNECTED;
        Ok(())
    }

    pub fn listen_socket(&mut self, socket_id: u32, backlog: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].domain != AF_INET || self.sockets[index].ty != SOCK_STREAM {
            return Err(ERR_EOPNOTSUPP);
        }
        self.sockets[index].state = SOCKET_LISTENING;
        self.sockets[index].backlog = backlog.max(1);
        self.sockets[index].pending_accepts = 0;
        Ok(())
    }

    pub fn accept_socket(
        &mut self,
        socket_id: u32,
        accepted_socket_id: u32,
        accepted_ready_key: u64,
    ) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].state != SOCKET_LISTENING {
            return Err(ERR_EINVAL);
        }
        if self.sockets[index].pending_accepts == 0 {
            return Err(ERR_EAGAIN);
        }
        let Some(accepted_index) = self.sockets.iter().position(|socket| !socket.active) else {
            return Err(ERR_EIO);
        };
        self.sockets[accepted_index] = LinuxSocket {
            socket_id: accepted_socket_id,
            domain: self.sockets[index].domain,
            ty: self.sockets[index].ty,
            protocol: self.sockets[index].protocol,
            ready_key: accepted_ready_key,
            state: SOCKET_CONNECTED,
            backlog: 0,
            pending_accepts: 0,
            active: true,
        };
        self.sockets[index].pending_accepts -= 1;
        Ok(accepted_socket_id)
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
        Err(ERR_EOPNOTSUPP)
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

    fn listener_index_for(&self, client_index: usize) -> Option<usize> {
        let client = self.sockets[client_index];
        self.sockets.iter().enumerate().position(|(index, socket)| {
            index != client_index
                && socket.active
                && socket.state == SOCKET_LISTENING
                && socket.domain == client.domain
                && socket.ty == client.ty
                && socket.protocol == client.protocol
        })
    }
}

impl Default for LinuxSocketState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use vmos_abi::{AF_INET, ERR_EAGAIN, ERR_ECONNREFUSED, ERR_EINVAL, SOCK_DGRAM, SOCK_STREAM};

    use super::*;

    #[test]
    fn register_socket_enforces_network_contract() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert!(state.register_socket(2, AF_INET, SOCK_DGRAM, 17, 43).is_ok());
        assert_eq!(state.register_socket(3, AF_INET + 1, SOCK_STREAM, 0, 44), Err(ERR_EOPNOTSUPP));
    }

    #[test]
    fn connect_reports_already_connected() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.connect_socket(1, 16), Ok(()));
        assert_eq!(state.connect_socket(1, 16), Err(ERR_EISCONN));
    }

    #[test]
    fn connect_requires_a_listening_stream_socket_and_queues_accept() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.accept_socket(1, 3, 44), Err(ERR_EINVAL));
        assert_eq!(state.connect_socket(1, 16), Err(ERR_ECONNREFUSED));

        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert_eq!(state.connect_socket(1, 16), Ok(()));
        assert_eq!(state.accept_socket(2, 3, 44), Ok(3));
        assert_eq!(state.accept_socket(2, 4, 45), Err(ERR_EAGAIN));
    }

    #[test]
    fn accept_registers_child_socket_as_connected() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert_eq!(state.connect_socket(1, 16), Ok(()));
        assert_eq!(state.accept_socket(2, 7, 99), Ok(7));
        assert_eq!(state.connect_socket(7, 16), Err(ERR_EISCONN));
    }

    #[test]
    fn fcntl_does_not_fake_socket_success() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.fcntl(1, 3, 0), Err(ERR_EOPNOTSUPP));
    }
}
