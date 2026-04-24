#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

const REQUEST_CAPACITY: usize = 128;
const RESPONSE_CAPACITY: usize = 512;
const FIRST_RX_DELAY_TICKS: u64 = 7;
const NEXT_RX_DELAY_TICKS: u64 = 20;
const PACKET: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nhello vmos\n";

pub const EVENT_NONE: u32 = 0;
pub const EVENT_IRQ: u32 = 1;
pub const EVENT_DMA_SUBMITTED: u32 = 2;
pub const EVENT_DMA_COMPLETED: u32 = 3;
pub const EVENT_DRIVER_COMPLETION: u32 = 4;
pub const EVENT_PACKET_RX: u32 = 5;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut NEXT_TICK: u64 = FIRST_RX_DELAY_TICKS;
static mut PHASE: u32 = EVENT_NONE;
static mut READY: bool = false;
static mut LAST_LEN: u32 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn request_ptr() -> u32 {
    addr_of_mut!(REQUEST) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn request_capacity() -> u32 {
    REQUEST_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn response_ptr() -> u32 {
    addr_of_mut!(RESPONSE) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn response_capacity() -> u32 {
    RESPONSE_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn reset_sequence(now_ticks: u64) {
    unsafe {
        NEXT_TICK = now_ticks.saturating_add(FIRST_RX_DELAY_TICKS);
        PHASE = EVENT_NONE;
        READY = false;
        LAST_LEN = 0;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_device(now_ticks: u64) -> u32 {
    unsafe {
        if READY || now_ticks < NEXT_TICK {
            LAST_LEN = 0;
            return EVENT_NONE;
        }

        PHASE = match PHASE {
            EVENT_NONE => EVENT_IRQ,
            EVENT_IRQ => EVENT_DMA_SUBMITTED,
            EVENT_DMA_SUBMITTED => EVENT_DMA_COMPLETED,
            EVENT_DMA_COMPLETED => EVENT_DRIVER_COMPLETION,
            EVENT_DRIVER_COMPLETION => EVENT_PACKET_RX,
            _ => EVENT_PACKET_RX,
        };

        if PHASE == EVENT_PACKET_RX {
            let len = PACKET.len().min(RESPONSE_CAPACITY);
            core::ptr::copy_nonoverlapping(PACKET.as_ptr(), addr_of_mut!(RESPONSE) as *mut u8, len);
            LAST_LEN = len as u32;
            READY = true;
            NEXT_TICK = now_ticks.saturating_add(NEXT_RX_DELAY_TICKS);
        } else {
            LAST_LEN = 64;
        }

        PHASE
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn event_len() -> u32 {
    unsafe { LAST_LEN }
}

#[unsafe(no_mangle)]
pub extern "C" fn consume_packet() {
    unsafe {
        READY = false;
        PHASE = EVENT_NONE;
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
