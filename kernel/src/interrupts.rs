pub fn init() {
    // Keep the bring-up surface minimal for the prototype.
}

pub fn sleep_ms(delay_ms: u32) {
    let outer_loops = delay_ms.max(1) as u64 * 50_000;
    for _ in 0..outer_loops {
        for _ in 0..32 {
            core::hint::spin_loop();
        }
    }
}
