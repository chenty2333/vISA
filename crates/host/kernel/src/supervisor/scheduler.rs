use alloc::collections::BTreeMap;

use super::{
    events::{Event, EventQueue},
    types::TaskId,
};

const BOOTSTRAP_TASK_ID: TaskId = 1;
const DEFAULT_TASK_PRIORITY: u32 = 0;

pub(crate) struct Scheduler {
    current_task: TaskId,
    next_task: TaskId,
    events: EventQueue,
    task_base_priorities: BTreeMap<TaskId, u32>,
    task_effective_priorities: BTreeMap<TaskId, u32>,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            current_task: BOOTSTRAP_TASK_ID,
            next_task: BOOTSTRAP_TASK_ID + 1,
            events: EventQueue::new(),
            task_base_priorities: BTreeMap::new(),
            task_effective_priorities: BTreeMap::new(),
        }
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        BOOTSTRAP_TASK_ID
    }

    pub(crate) fn current_task(&self) -> TaskId {
        self.current_task
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.current_task = task;
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        let task = self.next_task;
        self.next_task += 1;
        self.register_task(task);
        task
    }

    pub(crate) fn register_task(&mut self, task: TaskId) {
        self.task_base_priorities.entry(task).or_insert(DEFAULT_TASK_PRIORITY);
        self.task_effective_priorities.entry(task).or_insert(DEFAULT_TASK_PRIORITY);
    }

    pub(crate) fn task_priority(&self, task: TaskId) -> u32 {
        self.task_effective_priorities
            .get(&task)
            .copied()
            .or_else(|| self.task_base_priorities.get(&task).copied())
            .unwrap_or(DEFAULT_TASK_PRIORITY)
    }

    pub(crate) fn boost_priority(&mut self, task: TaskId, priority: u32) -> bool {
        let base = self.task_base_priorities.entry(task).or_insert(DEFAULT_TASK_PRIORITY);
        let current = self.task_effective_priorities.entry(task).or_insert(*base);
        if priority > *current {
            *current = priority;
            true
        } else {
            false
        }
    }

    pub(crate) fn restore_priority(&mut self, task: TaskId) -> bool {
        let base = *self.task_base_priorities.entry(task).or_insert(DEFAULT_TASK_PRIORITY);
        let current = self.task_effective_priorities.entry(task).or_insert(base);
        if *current != base {
            *current = base;
            true
        } else {
            false
        }
    }

    pub(crate) fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub(crate) fn pop_event(&mut self) -> Option<Event> {
        self.events.pop()
    }
}
