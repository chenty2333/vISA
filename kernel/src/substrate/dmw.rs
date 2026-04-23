use core::slice;

use spin::Mutex;

const MAX_DMW_SLOTS: usize = 8;

static DMW: Mutex<DmwManager> = Mutex::new(DmwManager::new());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DmwFault {
    NoFreeSlots,
    WindowViolation,
}

#[derive(Clone, Copy)]
struct DmwSlot {
    activation_id: u64,
    generation: u64,
    active: bool,
}

struct DmwManager {
    slots: [DmwSlot; MAX_DMW_SLOTS],
    next_generation: u64,
}

impl DmwManager {
    const fn new() -> Self {
        Self {
            slots: [DmwSlot {
                activation_id: 0,
                generation: 0,
                active: false,
            }; MAX_DMW_SLOTS],
            next_generation: 1,
        }
    }

    fn acquire(&mut self, activation_id: u64) -> Result<(usize, u64), DmwFault> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.active {
                continue;
            }

            let generation = self.next_generation;
            self.next_generation += 1;
            *slot = DmwSlot {
                activation_id,
                generation,
                active: true,
            };
            return Ok((index, generation));
        }

        Err(DmwFault::NoFreeSlots)
    }

    fn release(&mut self, slot_index: usize, generation: u64) {
        let Some(slot) = self.slots.get_mut(slot_index) else {
            return;
        };
        if slot.active && slot.generation == generation {
            slot.active = false;
            slot.activation_id = 0;
        }
    }

    fn assert_quiescent(&self) -> Result<(), &'static str> {
        if self.slots.iter().any(|slot| slot.active) {
            Err("entered Pending with an active DMW lease")
        } else {
            Ok(())
        }
    }

    fn active_lease_count(&self) -> usize {
        self.slots.iter().filter(|slot| slot.active).count()
    }

    fn validate(
        &self,
        slot_index: usize,
        generation: u64,
        activation_id: u64,
    ) -> Result<(), DmwFault> {
        let Some(slot) = self.slots.get(slot_index) else {
            return Err(DmwFault::WindowViolation);
        };
        if slot.active && slot.generation == generation && slot.activation_id == activation_id {
            Ok(())
        } else {
            Err(DmwFault::WindowViolation)
        }
    }

    fn finish_activation(&mut self, activation_id: u64) {
        for slot in &mut self.slots {
            if slot.active && slot.activation_id == activation_id {
                slot.active = false;
                slot.activation_id = 0;
            }
        }
    }
}

pub(crate) struct DmwLease {
    slot_index: usize,
    generation: u64,
    activation_id: u64,
    ptr: u64,
    len: usize,
    writable: bool,
}

impl DmwLease {
    pub(crate) fn slot_index(&self) -> usize {
        self.slot_index
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn activation_id(&self) -> u64 {
        self.activation_id
    }

    pub(crate) fn ptr(&self) -> u64 {
        self.ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn bytes(&self) -> Result<&[u8], DmwFault> {
        DMW.lock()
            .validate(self.slot_index, self.generation, self.activation_id)?;
        Ok(unsafe { slice::from_raw_parts(self.ptr as *const u8, self.len) })
    }

    pub(crate) fn bytes_mut(&mut self) -> Result<&mut [u8], DmwFault> {
        assert!(self.writable, "DMW lease was not writable");
        DMW.lock()
            .validate(self.slot_index, self.generation, self.activation_id)?;
        Ok(unsafe { slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) })
    }
}

impl Drop for DmwLease {
    fn drop(&mut self) {
        DMW.lock().release(self.slot_index, self.generation);
    }
}

pub(crate) fn acquire(
    activation_id: u64,
    ptr: u64,
    len: u64,
    writable: bool,
) -> Result<DmwLease, DmwFault> {
    let (slot_index, generation) = DMW.lock().acquire(activation_id)?;
    Ok(DmwLease {
        slot_index,
        generation,
        activation_id,
        ptr,
        len: len as usize,
        writable,
    })
}

pub(crate) fn assert_quiescent() -> Result<(), &'static str> {
    DMW.lock().assert_quiescent()
}

pub(crate) fn active_lease_count() -> usize {
    DMW.lock().active_lease_count()
}

pub(crate) fn finish_activation(activation_id: u64) {
    DMW.lock().finish_activation(activation_id);
}
