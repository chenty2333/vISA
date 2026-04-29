use alloc::string::String;
use alloc::vec::Vec;

use crate::ids::Generation;
use crate::target_executor::{ContractObjectKind, ContractObjectRef};

pub trait TableObject {
    fn table_ref(&self) -> ContractObjectRef;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectTableError {
    InvalidIdentity,
    DuplicateIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectTable<T> {
    objects: Vec<T>,
    next_id: u64,
}

impl<T> Default for ObjectTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ObjectTable<T> {
    pub const fn new() -> Self {
        Self {
            objects: Vec::new(),
            next_id: 1,
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    pub fn objects(&self) -> &[T] {
        &self.objects
    }
}

impl<T: TableObject> ObjectTable<T> {
    pub fn push(&mut self, object: T) -> Result<(), ObjectTableError> {
        let object_ref = object.table_ref();
        if object_ref.id == 0 || object_ref.generation == 0 {
            return Err(ObjectTableError::InvalidIdentity);
        }
        if self
            .objects
            .iter()
            .any(|entry| entry.table_ref() == object_ref)
        {
            return Err(ObjectTableError::DuplicateIdentity);
        }
        self.next_id = self.next_id.max(object_ref.id.saturating_add(1));
        self.objects.push(object);
        Ok(())
    }

    pub fn contains(&self, object: ContractObjectRef) -> bool {
        self.objects.iter().any(|entry| entry.table_ref() == object)
    }

    pub fn get(&self, object: ContractObjectRef) -> Option<&T> {
        self.objects
            .iter()
            .find(|entry| entry.table_ref() == object)
    }

    pub fn roots(&self) -> Vec<String> {
        self.objects
            .iter()
            .map(|entry| entry.table_ref().summary())
            .collect()
    }
}

pub const fn object_ref(
    kind: ContractObjectKind,
    id: u64,
    generation: Generation,
) -> ContractObjectRef {
    ContractObjectRef::new(kind, id, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestObject {
        object: ContractObjectRef,
    }

    impl TableObject for TestObject {
        fn table_ref(&self) -> ContractObjectRef {
            self.object
        }
    }

    #[test]
    fn object_table_rejects_zero_and_duplicate_identity() {
        let mut table = ObjectTable::new();
        assert_eq!(
            table.push(TestObject {
                object: object_ref(ContractObjectKind::Task, 0, 1),
            }),
            Err(ObjectTableError::InvalidIdentity)
        );
        assert_eq!(
            table.push(TestObject {
                object: object_ref(ContractObjectKind::Task, 7, 0),
            }),
            Err(ObjectTableError::InvalidIdentity)
        );
        assert!(
            table
                .push(TestObject {
                    object: object_ref(ContractObjectKind::Task, 7, 1),
                })
                .is_ok()
        );
        assert_eq!(
            table.push(TestObject {
                object: object_ref(ContractObjectKind::Task, 7, 1),
            }),
            Err(ObjectTableError::DuplicateIdentity)
        );
    }

    #[test]
    fn object_table_tracks_exact_generation_and_roots() {
        let mut table = ObjectTable::new();
        let old_generation = object_ref(ContractObjectKind::Store, 4, 1);
        let new_generation = object_ref(ContractObjectKind::Store, 4, 2);
        assert!(
            table
                .push(TestObject {
                    object: old_generation,
                })
                .is_ok()
        );

        assert!(table.contains(old_generation));
        assert!(!table.contains(new_generation));
        assert_eq!(table.next_id(), 5);
        assert_eq!(table.roots(), vec!["store:4@1".to_string()]);
    }
}
