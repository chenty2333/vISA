use alloc::{string::String, vec::Vec};

use crate::{
    ids::Generation,
    target_executor::{ContractObjectKind, ContractObjectRef},
};

pub trait TableObject {
    fn table_ref(&self) -> ContractObjectRef;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectTableError {
    InvalidIdentity,
    DuplicateIdentity,
    MissingIdentity,
    DuplicateTombstone,
    TombstonedGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectLookup<'a, T> {
    Live(&'a T),
    Tombstoned,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectTable<T> {
    objects: Vec<T>,
    tombstones: Vec<ContractObjectRef>,
    next_id: u64,
}

impl<T> Default for ObjectTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ObjectTable<T> {
    pub const fn new() -> Self {
        Self { objects: Vec::new(), tombstones: Vec::new(), next_id: 1 }
    }

    pub fn allocate_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    pub fn objects(&self) -> &[T] {
        &self.objects
    }

    pub fn tombstones(&self) -> &[ContractObjectRef] {
        &self.tombstones
    }
}

impl<T: TableObject> ObjectTable<T> {
    pub fn push(&mut self, object: T) -> Result<(), ObjectTableError> {
        let object_ref = object.table_ref();
        if object_ref.id == 0 || object_ref.generation == 0 {
            return Err(ObjectTableError::InvalidIdentity);
        }
        if self.objects.iter().any(|entry| entry.table_ref() == object_ref) {
            return Err(ObjectTableError::DuplicateIdentity);
        }
        if self.is_tombstoned(object_ref) {
            return Err(ObjectTableError::TombstonedGeneration);
        }
        self.next_id = self.next_id.max(object_ref.id.saturating_add(1));
        self.objects.push(object);
        Ok(())
    }

    pub fn tombstone(&mut self, object: ContractObjectRef) -> Result<(), ObjectTableError> {
        if object.id == 0 || object.generation == 0 {
            return Err(ObjectTableError::InvalidIdentity);
        }
        if self.is_tombstoned(object) {
            return Err(ObjectTableError::DuplicateTombstone);
        }
        if !self.objects.iter().any(|entry| entry.table_ref() == object) {
            return Err(ObjectTableError::MissingIdentity);
        }
        self.tombstones.push(object);
        Ok(())
    }

    pub fn contains(&self, object: ContractObjectRef) -> bool {
        matches!(self.lookup(object), ObjectLookup::Live(_))
    }

    pub fn contains_historical(&self, object: ContractObjectRef) -> bool {
        self.objects.iter().any(|entry| entry.table_ref() == object) || self.is_tombstoned(object)
    }

    pub fn get(&self, object: ContractObjectRef) -> Option<&T> {
        if self.is_tombstoned(object) {
            return None;
        }
        self.objects.iter().find(|entry| entry.table_ref() == object)
    }

    pub fn get_historical(&self, object: ContractObjectRef) -> Option<&T> {
        self.objects.iter().find(|entry| entry.table_ref() == object)
    }

    pub fn lookup(&self, object: ContractObjectRef) -> ObjectLookup<'_, T> {
        if self.is_tombstoned(object) {
            return ObjectLookup::Tombstoned;
        }
        self.get(object).map(ObjectLookup::Live).unwrap_or(ObjectLookup::Missing)
    }

    pub fn generation_for(&self, kind: ContractObjectKind, id: u64) -> Option<Generation> {
        self.objects
            .iter()
            .map(TableObject::table_ref)
            .filter(|object| object.kind == kind && object.id == id && !self.is_tombstoned(*object))
            .map(|object| object.generation)
            .max()
    }

    pub fn latest_ref(&self, kind: ContractObjectKind, id: u64) -> Option<ContractObjectRef> {
        self.generation_for(kind, id).map(|generation| ContractObjectRef::new(kind, id, generation))
    }

    pub fn live_refs(&self) -> Vec<ContractObjectRef> {
        self.objects
            .iter()
            .map(TableObject::table_ref)
            .filter(|object| !self.is_tombstoned(*object))
            .collect()
    }

    pub fn historical_refs(&self) -> Vec<ContractObjectRef> {
        self.objects.iter().map(TableObject::table_ref).collect()
    }

    pub fn roots(&self) -> Vec<String> {
        self.live_refs().into_iter().map(ContractObjectRef::summary).collect()
    }

    pub fn historical_roots(&self) -> Vec<String> {
        self.historical_refs().into_iter().map(ContractObjectRef::summary).collect()
    }

    pub fn visit_live_refs(&self, mut visitor: impl FnMut(ContractObjectRef)) {
        for object in self.live_refs() {
            visitor(object);
        }
    }

    pub fn visit_historical_refs(&self, mut visitor: impl FnMut(ContractObjectRef)) {
        for object in self.historical_refs() {
            visitor(object);
        }
    }

    pub fn is_tombstoned(&self, object: ContractObjectRef) -> bool {
        self.tombstones.contains(&object)
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
    use alloc::{string::ToString, vec};

    use super::*;

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
            table.push(TestObject { object: object_ref(ContractObjectKind::Task, 0, 1) }),
            Err(ObjectTableError::InvalidIdentity)
        );
        assert_eq!(
            table.push(TestObject { object: object_ref(ContractObjectKind::Task, 7, 0) }),
            Err(ObjectTableError::InvalidIdentity)
        );
        assert!(
            table.push(TestObject { object: object_ref(ContractObjectKind::Task, 7, 1) }).is_ok()
        );
        assert_eq!(
            table.push(TestObject { object: object_ref(ContractObjectKind::Task, 7, 1) }),
            Err(ObjectTableError::DuplicateIdentity)
        );
    }

    #[test]
    fn object_table_tracks_exact_generation_and_roots() {
        let mut table = ObjectTable::new();
        let old_generation = object_ref(ContractObjectKind::Store, 4, 1);
        let new_generation = object_ref(ContractObjectKind::Store, 4, 2);
        assert!(table.push(TestObject { object: old_generation }).is_ok());

        assert!(table.contains(old_generation));
        assert!(!table.contains(new_generation));
        assert_eq!(table.next_id(), 5);
        assert_eq!(table.roots(), vec!["store:4@1".to_string()]);
    }

    #[test]
    fn object_table_allocates_ids_and_tracks_latest_live_generation() {
        let mut table = ObjectTable::new();
        assert_eq!(table.allocate_id(), 1);
        assert_eq!(table.allocate_id(), 2);
        assert_eq!(table.next_id(), 3);

        let first = object_ref(ContractObjectKind::Task, 7, 1);
        let second = object_ref(ContractObjectKind::Task, 7, 2);
        assert!(table.push(TestObject { object: first }).is_ok());
        assert!(table.push(TestObject { object: second }).is_ok());

        assert_eq!(table.generation_for(ContractObjectKind::Task, 7), Some(2));
        assert_eq!(table.latest_ref(ContractObjectKind::Task, 7), Some(second));
        assert_eq!(table.historical_roots(), vec!["task:7@1".to_string(), "task:7@2".to_string()]);
        assert_eq!(table.roots(), vec!["task:7@1".to_string(), "task:7@2".to_string()]);
    }

    #[test]
    fn object_table_tombstones_exact_generations_without_hiding_history() {
        let mut table = ObjectTable::new();
        let old_generation = object_ref(ContractObjectKind::Store, 4, 1);
        let new_generation = object_ref(ContractObjectKind::Store, 4, 2);
        assert!(table.push(TestObject { object: old_generation }).is_ok());
        assert!(table.push(TestObject { object: new_generation }).is_ok());

        assert_eq!(table.tombstone(old_generation), Ok(()));
        assert_eq!(table.tombstone(old_generation), Err(ObjectTableError::DuplicateTombstone));
        assert!(matches!(table.lookup(old_generation), ObjectLookup::Tombstoned));
        assert!(matches!(table.lookup(new_generation), ObjectLookup::Live(_)));
        assert!(!table.contains(old_generation));
        assert!(table.contains_historical(old_generation));
        assert!(table.get(old_generation).is_none());
        assert!(table.get_historical(old_generation).is_some());
        assert_eq!(table.generation_for(ContractObjectKind::Store, 4), Some(2));
        assert_eq!(table.roots(), vec!["store:4@2".to_string()]);
        assert_eq!(
            table.historical_roots(),
            vec!["store:4@1".to_string(), "store:4@2".to_string()]
        );
        assert_eq!(
            table.push(TestObject { object: old_generation }),
            Err(ObjectTableError::DuplicateIdentity)
        );
    }

    #[test]
    fn object_table_visits_live_and_historical_refs_separately() {
        let mut table = ObjectTable::new();
        let old_generation = object_ref(ContractObjectKind::Activation, 9, 1);
        let new_generation = object_ref(ContractObjectKind::Activation, 9, 2);
        assert!(table.push(TestObject { object: old_generation }).is_ok());
        assert!(table.push(TestObject { object: new_generation }).is_ok());
        assert_eq!(table.tombstone(old_generation), Ok(()));

        let mut live = Vec::new();
        table.visit_live_refs(|object| live.push(object.summary()));
        assert_eq!(live, vec!["activation:9@2".to_string()]);

        let mut historical = Vec::new();
        table.visit_historical_refs(|object| historical.push(object.summary()));
        assert_eq!(historical, vec!["activation:9@1".to_string(), "activation:9@2".to_string()]);
    }

    #[test]
    fn object_table_rejects_missing_tombstone_and_reused_tombstoned_generation() {
        let mut table = ObjectTable::new();
        let object = object_ref(ContractObjectKind::Task, 8, 1);
        assert_eq!(table.tombstone(object), Err(ObjectTableError::MissingIdentity));

        assert!(table.push(TestObject { object }).is_ok());
        assert_eq!(table.tombstone(object), Ok(()));
        let mut replay = ObjectTable::new();
        replay.tombstones.push(object);
        assert_eq!(replay.push(TestObject { object }), Err(ObjectTableError::TombstonedGeneration));
    }
}
