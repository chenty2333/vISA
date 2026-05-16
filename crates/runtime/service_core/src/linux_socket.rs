use vmos_abi::{
    AF_INET, ERR_EADDRINUSE, ERR_EAGAIN, ERR_EBADF, ERR_ECONNREFUSED, ERR_EINVAL, ERR_EIO,
    ERR_EISCONN, ERR_EOPNOTSUPP, SOCK_STREAM,
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
    local_ipv4: u32,
    local_port: u16,
    remote_ipv4: u32,
    remote_port: u16,
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
        local_ipv4: 0,
        local_port: 0,
        remote_ipv4: 0,
        remote_port: 0,
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
                    local_ipv4: 0,
                    local_port: 0,
                    remote_ipv4: 0,
                    remote_port: 0,
                    active: true,
                };
                return Ok(());
            }
        }
        Err(ERR_EIO)
    }

    pub fn register_connected_socket(
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
                    state: SOCKET_CONNECTED,
                    backlog: 0,
                    pending_accepts: 0,
                    local_ipv4: 0,
                    local_port: 0,
                    remote_ipv4: 0,
                    remote_port: 0,
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

    pub fn bind_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
        family: u32,
        ipv4: u32,
        port: u32,
    ) -> Result<(), i32> {
        if family == AF_INET && addr_len < 16 {
            return Err(ERR_EINVAL);
        }
        if family != AF_INET || port > u16::MAX as u32 {
            return self.set_state(socket_id, SOCKET_BOUND);
        }
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].domain != AF_INET || self.sockets[index].ty != SOCK_STREAM {
            return self.set_state(socket_id, SOCKET_BOUND);
        }
        let port = port as u16;
        if port != 0 && self.bound_port_conflicts(index, ipv4, port) {
            return Err(ERR_EADDRINUSE);
        }
        self.sockets[index].local_ipv4 = ipv4;
        self.sockets[index].local_port = port;
        self.sockets[index].state = SOCKET_BOUND;
        Ok(())
    }

    pub fn connect_socket(
        &mut self,
        socket_id: u32,
        addr_len: u32,
        family: u32,
        remote_ipv4: u32,
        remote_port: u32,
    ) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].state == SOCKET_CONNECTED {
            return Err(ERR_EISCONN);
        }
        if self.sockets[index].domain != AF_INET || self.sockets[index].ty != SOCK_STREAM {
            self.sockets[index].state = SOCKET_CONNECTED;
            return Ok(());
        }
        if family != AF_INET || addr_len < 16 || remote_port == 0 || remote_port > u16::MAX as u32 {
            return Err(ERR_ECONNREFUSED);
        }
        let remote_port = remote_port as u16;
        let Some(listener_index) = self.listener_index_for(index, remote_ipv4, remote_port) else {
            return Err(ERR_ECONNREFUSED);
        };
        if self.sockets[listener_index].pending_accepts >= self.sockets[listener_index].backlog {
            return Err(ERR_ECONNREFUSED);
        }
        self.sockets[listener_index].pending_accepts =
            self.sockets[listener_index].pending_accepts.saturating_add(1);
        self.sockets[index].remote_ipv4 = remote_ipv4;
        self.sockets[index].remote_port = remote_port;
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
            local_ipv4: self.sockets[index].local_ipv4,
            local_port: self.sockets[index].local_port,
            remote_ipv4: 0,
            remote_port: 0,
            active: true,
        };
        self.sockets[index].pending_accepts -= 1;
        Ok(accepted_socket_id)
    }

    pub fn pending_accept_count(&self, socket_id: u32) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].state != SOCKET_LISTENING {
            return Err(ERR_EINVAL);
        }
        Ok(self.sockets[index].pending_accepts)
    }

    pub fn accept_ready_key_for_client(&self, socket_id: u32) -> Result<Option<u64>, i32> {
        let index = self.socket_index(socket_id)?;
        if self.sockets[index].domain != AF_INET || self.sockets[index].ty != SOCK_STREAM {
            return Ok(None);
        }
        let client = self.sockets[index];
        let Some(listener_index) =
            self.listener_index_for(index, client.remote_ipv4, client.remote_port)
        else {
            return Ok(None);
        };
        if self.sockets[listener_index].pending_accepts == 0 {
            return Ok(None);
        }
        Ok(Some(self.sockets[listener_index].ready_key))
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

    fn listener_index_for(
        &self,
        client_index: usize,
        remote_ipv4: u32,
        remote_port: u16,
    ) -> Option<usize> {
        let client = self.sockets[client_index];
        let mut wildcard = None;
        for (index, socket) in self.sockets.iter().copied().enumerate() {
            if index == client_index
                || !socket.active
                || socket.state != SOCKET_LISTENING
                || socket.domain != client.domain
                || socket.ty != client.ty
                || socket.protocol != client.protocol
            {
                continue;
            }
            if socket.local_port == remote_port
                && ipv4_matches_bound_pair(socket.local_ipv4, remote_ipv4)
            {
                return Some(index);
            }
            if socket.local_port == 0 && wildcard.is_none() {
                wildcard = Some(index);
            }
        }
        wildcard
    }

    fn bound_port_conflicts(&self, socket_index: usize, ipv4: u32, port: u16) -> bool {
        self.sockets.iter().enumerate().any(|(index, socket)| {
            index != socket_index
                && socket.active
                && socket.domain == AF_INET
                && socket.ty == SOCK_STREAM
                && socket.local_port == port
                && ipv4_matches_bound_pair(socket.local_ipv4, ipv4)
        })
    }
}

fn ipv4_matches_bound_pair(bound_ipv4: u32, target_ipv4: u32) -> bool {
    bound_ipv4 == 0 || target_ipv4 == 0 || bound_ipv4 == target_ipv4
}

impl Default for LinuxSocketState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use vmos_abi::{
        AF_INET, ERR_EADDRINUSE, ERR_EAGAIN, ERR_ECONNREFUSED, ERR_EINVAL, SOCK_DGRAM, SOCK_STREAM,
    };

    use super::*;

    const LOOPBACK: u32 = 0x7f00_0001;
    const ALT_LOOPBACK: u32 = 0x7f00_0002;

    fn bind_ipv4(
        state: &mut LinuxSocketState,
        socket_id: u32,
        ipv4: u32,
        port: u32,
    ) -> Result<(), i32> {
        state.bind_socket(socket_id, 16, AF_INET, ipv4, port)
    }

    fn connect_ipv4(
        state: &mut LinuxSocketState,
        socket_id: u32,
        ipv4: u32,
        port: u32,
    ) -> Result<(), i32> {
        state.connect_socket(socket_id, 16, AF_INET, ipv4, port)
    }

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
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Ok(()));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Err(ERR_EISCONN));
    }

    #[test]
    fn connect_requires_a_listening_stream_socket_and_queues_accept() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.accept_socket(1, 3, 44), Err(ERR_EINVAL));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Err(ERR_ECONNREFUSED));

        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Ok(()));
        assert_eq!(state.accept_socket(2, 3, 44), Ok(3));
        assert_eq!(state.accept_socket(2, 4, 45), Err(ERR_EAGAIN));
    }

    #[test]
    fn accept_registers_child_socket_as_connected() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Ok(()));
        assert_eq!(state.accept_socket(2, 7, 99), Ok(7));
        assert_eq!(connect_ipv4(&mut state, 7, LOOPBACK, 80), Err(ERR_EISCONN));
    }

    #[test]
    fn register_connected_socket_installs_accepted_stream_state() {
        let mut state = LinuxSocketState::new();

        assert_eq!(state.register_connected_socket(7, AF_INET, SOCK_STREAM, 0, 99), Ok(()));
        assert_eq!(connect_ipv4(&mut state, 7, LOOPBACK, 80), Err(ERR_EISCONN));
        assert_eq!(state.pending_accept_count(7), Err(ERR_EINVAL));
    }

    #[test]
    fn bind_rejects_conflicting_ipv4_stream_listener_ports() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(bind_ipv4(&mut state, 1, LOOPBACK, 8080), Ok(()));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(bind_ipv4(&mut state, 2, LOOPBACK, 8080), Err(ERR_EADDRINUSE));
        assert_eq!(bind_ipv4(&mut state, 2, ALT_LOOPBACK, 8080), Ok(()));
    }

    #[test]
    fn bind_rejects_short_ipv4_sockaddr() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.bind_socket(1, 2, AF_INET, LOOPBACK, 8080), Err(ERR_EINVAL));
    }

    #[test]
    fn connect_matches_bound_listener_port_and_ipv4() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(bind_ipv4(&mut state, 1, LOOPBACK, 8080), Ok(()));
        assert_eq!(state.listen_socket(1, 2), Ok(()));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(bind_ipv4(&mut state, 2, ALT_LOOPBACK, 9090), Ok(()));
        assert_eq!(state.listen_socket(2, 2), Ok(()));

        assert!(state.register_socket(3, AF_INET, SOCK_STREAM, 0, 44).is_ok());
        assert_eq!(connect_ipv4(&mut state, 3, ALT_LOOPBACK, 8080), Err(ERR_ECONNREFUSED));
        assert_eq!(connect_ipv4(&mut state, 3, LOOPBACK, 9090), Err(ERR_ECONNREFUSED));
        assert_eq!(connect_ipv4(&mut state, 3, ALT_LOOPBACK, 9090), Ok(()));
        assert_eq!(state.pending_accept_count(1), Ok(0));
        assert_eq!(state.pending_accept_count(2), Ok(1));
        assert_eq!(state.accept_ready_key_for_client(3), Ok(Some(43)));
    }

    #[test]
    fn wildcard_listener_ipv4_matches_specific_remote_ipv4() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(bind_ipv4(&mut state, 1, 0, 8080), Ok(()));
        assert_eq!(state.listen_socket(1, 1), Ok(()));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());

        assert_eq!(connect_ipv4(&mut state, 2, LOOPBACK, 8080), Ok(()));
        assert_eq!(state.accept_ready_key_for_client(2), Ok(Some(42)));
    }

    #[test]
    fn exact_bound_listener_wins_over_unbound_legacy_listener() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.listen_socket(1, 2), Ok(()));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(bind_ipv4(&mut state, 2, LOOPBACK, 8080), Ok(()));
        assert_eq!(state.listen_socket(2, 2), Ok(()));
        assert!(state.register_socket(3, AF_INET, SOCK_STREAM, 0, 44).is_ok());

        assert_eq!(connect_ipv4(&mut state, 3, LOOPBACK, 8080), Ok(()));
        assert_eq!(state.pending_accept_count(1), Ok(0));
        assert_eq!(state.pending_accept_count(2), Ok(1));
        assert_eq!(state.accept_ready_key_for_client(3), Ok(Some(43)));
    }

    #[test]
    fn fcntl_does_not_fake_socket_success() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.fcntl(1, 3, 0), Err(ERR_EOPNOTSUPP));
    }

    #[test]
    fn pending_accept_count_tracks_listen_backlog() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.pending_accept_count(1), Err(ERR_EINVAL));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 2), Ok(()));
        assert_eq!(state.pending_accept_count(2), Ok(0));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Ok(()));
        assert_eq!(state.pending_accept_count(2), Ok(1));
        assert_eq!(state.accept_socket(2, 7, 99), Ok(7));
        assert_eq!(state.pending_accept_count(2), Ok(0));
    }

    #[test]
    fn connect_exposes_listener_ready_key_for_accept_waiters() {
        let mut state = LinuxSocketState::new();

        assert!(state.register_socket(1, AF_INET, SOCK_STREAM, 0, 42).is_ok());
        assert_eq!(state.accept_ready_key_for_client(1), Ok(None));
        assert!(state.register_socket(2, AF_INET, SOCK_STREAM, 0, 43).is_ok());
        assert_eq!(state.listen_socket(2, 1), Ok(()));
        assert_eq!(connect_ipv4(&mut state, 1, LOOPBACK, 80), Ok(()));
        assert_eq!(state.accept_ready_key_for_client(1), Ok(Some(43)));
    }
}
