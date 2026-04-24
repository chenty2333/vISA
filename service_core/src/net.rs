use vmos_abi::{EPOLLIN, EPOLLOUT, ERR_EAGAIN, ERR_EBADF, ERR_EIO};

pub const MAX_SOCKETS: usize = 16;
pub const QUEUE_CAPACITY: usize = 512;
pub const READY_KEY_BASE: u64 = 0x6e65_7473_6f63_0000;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Socket {
    id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
    rx_len: usize,
    tx_len: usize,
    active: bool,
}

impl Socket {
    const EMPTY: Self = Self {
        id: 0,
        domain: 0,
        ty: 0,
        protocol: 0,
        ready_key: 0,
        state: 0,
        rx_len: 0,
        tx_len: 0,
        active: false,
    };
}

pub struct NetCoreState {
    sockets: [Socket; MAX_SOCKETS],
    rx_queues: [[u8; QUEUE_CAPACITY]; MAX_SOCKETS],
    tx_queues: [[u8; QUEUE_CAPACITY]; MAX_SOCKETS],
    next_socket_id: u32,
}

impl NetCoreState {
    pub const fn new() -> Self {
        Self {
            sockets: [Socket::EMPTY; MAX_SOCKETS],
            rx_queues: [[0; QUEUE_CAPACITY]; MAX_SOCKETS],
            tx_queues: [[0; QUEUE_CAPACITY]; MAX_SOCKETS],
            next_socket_id: 1,
        }
    }

    pub fn create_socket(&mut self, domain: u32, ty: u32, protocol: u32) -> Result<u32, i32> {
        let socket_id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.saturating_add(1);
        for socket in &mut self.sockets {
            if !socket.active {
                *socket = Socket {
                    id: socket_id,
                    domain,
                    ty,
                    protocol,
                    ready_key: READY_KEY_BASE | socket_id as u64,
                    state: 1,
                    rx_len: 0,
                    tx_len: 0,
                    active: true,
                };
                return Ok(socket_id);
            }
        }
        Err(ERR_EIO)
    }

    pub fn close_socket(&mut self, socket_id: u32) -> Result<(), i32> {
        let index = self.socket_index(socket_id)?;
        self.sockets[index] = Socket::EMPTY;
        self.rx_queues[index] = [0; QUEUE_CAPACITY];
        self.tx_queues[index] = [0; QUEUE_CAPACITY];
        Ok(())
    }

    pub fn ready_key(&self, socket_id: u32) -> Result<u64, i32> {
        Ok(self.sockets[self.socket_index(socket_id)?].ready_key)
    }

    pub fn poll_socket(&self, socket_id: u32) -> Result<u32, i32> {
        let socket = self.sockets[self.socket_index(socket_id)?];
        let mut events = EPOLLOUT;
        if socket.rx_len > 0 {
            events |= EPOLLIN;
        }
        Ok(events)
    }

    pub fn send_socket(&mut self, socket_id: u32, bytes: &[u8]) -> Result<u32, i32> {
        if bytes.len() > QUEUE_CAPACITY {
            return Err(ERR_EIO);
        }
        let index = self.socket_index(socket_id)?;
        self.tx_queues[index][..bytes.len()].copy_from_slice(bytes);
        self.sockets[index].tx_len = bytes.len();
        self.sockets[index].state = 2;
        Ok(bytes.len() as u32)
    }

    pub fn recv_socket(&mut self, socket_id: u32, count: u32, out: &mut [u8]) -> Result<u32, i32> {
        let index = self.socket_index(socket_id)?;
        let rx_len = self.sockets[index].rx_len;
        if rx_len == 0 {
            return Err(ERR_EAGAIN);
        }
        let len = rx_len.min(count as usize).min(out.len());
        out[..len].copy_from_slice(&self.rx_queues[index][..len]);
        self.sockets[index].rx_len = 0;
        Ok(len as u32)
    }

    pub fn inject_packet(&mut self, bytes: &[u8]) -> Result<Option<u64>, i32> {
        let len = bytes.len().min(QUEUE_CAPACITY);
        for index in 0..MAX_SOCKETS {
            if !self.sockets[index].active {
                continue;
            }
            self.rx_queues[index][..len].copy_from_slice(&bytes[..len]);
            self.sockets[index].rx_len = len;
            self.sockets[index].state = 3;
            return Ok(Some(self.sockets[index].ready_key));
        }
        Ok(None)
    }

    pub fn socket_count(&self) -> u32 {
        self.sockets.iter().filter(|socket| socket.active).count() as u32
    }

    pub fn queued_rx_bytes(&self) -> u32 {
        self.sockets.iter().fold(0u32, |acc, socket| {
            if socket.active {
                acc.saturating_add(socket.rx_len as u32)
            } else {
                acc
            }
        })
    }

    fn socket_index(&self, socket_id: u32) -> Result<usize, i32> {
        self.sockets
            .iter()
            .position(|socket| socket.active && socket.id == socket_id)
            .ok_or(ERR_EBADF)
    }
}

impl Default for NetCoreState {
    fn default() -> Self {
        Self::new()
    }
}
