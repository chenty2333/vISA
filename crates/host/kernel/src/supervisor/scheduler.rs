use alloc::{collections::BTreeMap, vec::Vec};

use super::{
    events::{Event, EventQueue},
    types::TaskId,
};

const BOOTSTRAP_TASK_ID: TaskId = 1;
const DEFAULT_TASK_PRIORITY: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulerTaskState {
    Runnable,
    Blocked,
    Exited,
}

pub(crate) struct Scheduler {
    current_task: TaskId,
    next_task: TaskId,
    events: EventQueue,
    task_base_priorities: BTreeMap<TaskId, u32>,
    task_effective_priorities: BTreeMap<TaskId, u32>,
    task_states: BTreeMap<TaskId, SchedulerTaskState>,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        let mut scheduler = Self {
            current_task: BOOTSTRAP_TASK_ID,
            next_task: BOOTSTRAP_TASK_ID + 1,
            events: EventQueue::new(),
            task_base_priorities: BTreeMap::new(),
            task_effective_priorities: BTreeMap::new(),
            task_states: BTreeMap::new(),
        };
        scheduler.register_task(BOOTSTRAP_TASK_ID);
        scheduler
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        BOOTSTRAP_TASK_ID
    }

    pub(crate) fn current_task(&self) -> TaskId {
        self.current_task
    }

    pub(crate) fn set_current_task_or_runnable_fallback(&mut self, task: TaskId) -> TaskId {
        if self.is_task_runnable(task) {
            self.current_task = task;
            return task;
        }
        if let Some(fallback) = self.highest_priority_runnable_task() {
            self.current_task = fallback;
            return fallback;
        }
        self.current_task = task;
        task
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
        self.task_states.entry(task).or_insert(SchedulerTaskState::Runnable);
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

    pub(crate) fn is_task_runnable(&self, task: TaskId) -> bool {
        self.task_states.get(&task).copied().unwrap_or(SchedulerTaskState::Runnable)
            == SchedulerTaskState::Runnable
    }

    pub(crate) fn mark_task_runnable(&mut self, task: TaskId) -> bool {
        self.register_task(task);
        let state = self.task_states.entry(task).or_insert(SchedulerTaskState::Runnable);
        if *state == SchedulerTaskState::Exited {
            return false;
        }
        let changed = *state != SchedulerTaskState::Runnable;
        *state = SchedulerTaskState::Runnable;
        changed
    }

    pub(crate) fn mark_task_blocked(&mut self, task: TaskId) -> bool {
        self.register_task(task);
        let state = self.task_states.entry(task).or_insert(SchedulerTaskState::Runnable);
        if *state == SchedulerTaskState::Exited {
            return false;
        }
        let changed = *state != SchedulerTaskState::Blocked;
        *state = SchedulerTaskState::Blocked;
        changed
    }

    pub(crate) fn mark_task_exited(&mut self, task: TaskId) -> bool {
        self.register_task(task);
        let state = self.task_states.entry(task).or_insert(SchedulerTaskState::Runnable);
        let changed = *state != SchedulerTaskState::Exited;
        *state = SchedulerTaskState::Exited;
        changed
    }

    pub(crate) fn highest_priority_runnable_task(&self) -> Option<TaskId> {
        let mut selected = None;
        let mut selected_priority = DEFAULT_TASK_PRIORITY;
        for (task, state) in &self.task_states {
            if *state != SchedulerTaskState::Runnable {
                continue;
            }
            let priority = self.task_priority(*task);
            if selected.is_none() || priority > selected_priority {
                selected = Some(*task);
                selected_priority = priority;
            }
        }
        selected
    }

    pub(crate) fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub(crate) fn drain_events(&mut self, out: &mut Vec<Event>) {
        while let Some(event) = self.events.pop() {
            out.push(event);
        }
    }

    pub(crate) fn prepend_events(&mut self, events: &mut Vec<Event>) {
        while let Some(event) = events.pop() {
            self.events.push_front(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runnable_selection_skips_blocked_and_exited_tasks() {
        let mut scheduler = Scheduler::new();
        let low = scheduler.allocate_task();
        let blocked_high = scheduler.allocate_task();
        let exited_high = scheduler.allocate_task();

        scheduler.boost_priority(low, 5);
        scheduler.boost_priority(blocked_high, 10);
        scheduler.boost_priority(exited_high, 20);
        scheduler.mark_task_blocked(blocked_high);
        scheduler.mark_task_exited(exited_high);

        assert_eq!(scheduler.highest_priority_runnable_task(), Some(low));

        scheduler.mark_task_runnable(blocked_high);
        assert_eq!(scheduler.highest_priority_runnable_task(), Some(blocked_high));

        assert!(!scheduler.mark_task_runnable(exited_high));
        assert_eq!(scheduler.highest_priority_runnable_task(), Some(blocked_high));
    }

    #[test]
    fn current_task_selection_falls_back_from_non_runnable_request() {
        let mut scheduler = Scheduler::new();
        let runnable = scheduler.allocate_task();
        let blocked = scheduler.allocate_task();
        let exited = scheduler.allocate_task();

        scheduler.boost_priority(runnable, 10);
        scheduler.boost_priority(blocked, 20);
        scheduler.mark_task_blocked(blocked);
        scheduler.mark_task_exited(exited);

        assert_eq!(scheduler.set_current_task_or_runnable_fallback(blocked), runnable);
        assert_eq!(scheduler.current_task(), runnable);

        assert_eq!(scheduler.set_current_task_or_runnable_fallback(exited), runnable);
        assert_eq!(scheduler.current_task(), runnable);
    }

    #[test]
    fn current_task_selection_preserves_runnable_request() {
        let mut scheduler = Scheduler::new();
        let low = scheduler.allocate_task();
        let high = scheduler.allocate_task();

        scheduler.boost_priority(high, 20);

        assert_eq!(scheduler.set_current_task_or_runnable_fallback(low), low);
        assert_eq!(scheduler.current_task(), low);
    }

    #[test]
    fn current_task_selection_preserves_non_runnable_when_no_fallback_exists() {
        let mut scheduler = Scheduler::new();
        let blocked = scheduler.allocate_task();

        scheduler.mark_task_blocked(scheduler.bootstrap_task());
        scheduler.mark_task_blocked(blocked);

        assert_eq!(scheduler.set_current_task_or_runnable_fallback(blocked), blocked);
        assert_eq!(scheduler.current_task(), blocked);
    }
}
