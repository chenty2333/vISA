use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

use contract_core::{
    CONTRACT_VERSION, Digest, EntityRef, Event, EventKind, Identity, JournalEntry, JournalPosition,
    LeaseEpoch, NodeIdentity,
};
use substrate_api::{
    ActivationBundle, JournalPort, JournalScope, LeasePort, LeaseRecord, ProviderErrorKind,
};
use substrate_host::{FaultObservation, FaultPoint};

use super::{NetworkProvider, ProviderLocator, ProviderLocatorError, ProviderServer, probe};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("visa-provider-rpc-{label}-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).expect("unique provider RPC test directory is created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn node(value: u128) -> NodeIdentity {
    NodeIdentity::new(id(value))
}

fn entity(value: u128) -> EntityRef {
    EntityRef::initial(id(value))
}

fn digest(value: u8) -> Digest {
    let mut bytes = [0_u8; 32];
    bytes[0] = value;
    Digest::from_bytes(bytes)
}

fn activated_entry(identity: u128, output: u8) -> JournalEntry {
    JournalEntry {
        version: CONTRACT_VERSION,
        position: JournalPosition(1),
        input_state: digest(0),
        output_state: digest(output),
        event: Event::new(id(identity), EventKind::Activated { lease_epoch: LeaseEpoch(1) }),
    }
}

fn scope(node_id: u128, component: u128) -> JournalScope {
    JournalScope { node: node(node_id), component: id(component) }
}

fn locator(socket: &Path, digit: char) -> ProviderLocator {
    ProviderLocator::new(socket, digit.to_string().repeat(64)).expect("test locator is canonical")
}

#[test]
fn locator_round_trips_raw_unix_path_bytes_and_rejects_noncanonical_input() {
    let raw_path =
        OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', b'v', b'i', b's', b'a', b'-', 0x80]);
    let locator = ProviderLocator::new(PathBuf::from(raw_path), "a".repeat(64))
        .expect("non-UTF-8 Unix path is encoded as bytes");
    assert!(locator.as_str().starts_with(ProviderLocator::PREFIX));
    assert_eq!(ProviderLocator::parse(locator.as_str()), Ok(locator.clone()));

    assert_eq!(
        ProviderLocator::parse(
            "visa-provider+unix-v1:2F746d70:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        Err(ProviderLocatorError::InvalidSocketPath)
    );
    assert_eq!(
        ProviderLocator::new("relative.sock", "a".repeat(64)),
        Err(ProviderLocatorError::InvalidSocketPath)
    );
    assert_eq!(
        ProviderLocator::new("/tmp/provider.sock", "A".repeat(64)),
        Err(ProviderLocatorError::InvalidDatabaseId)
    );
}

#[test]
fn rpc_preserves_fault_atomicity_shared_scope_and_restart_durability() {
    let directory = TestDirectory::new("restart");
    let database_root = directory.path.join("databases");
    fs::create_dir(&database_root).expect("database root is created");
    let socket = directory.path.join("provider.sock");
    let locator = locator(&socket, '1');
    let source_scope = scope(1, 10);
    let destination_scope = scope(2, 10);
    let resource = entity(20);
    let entry = activated_entry(30, 1);
    let bundle = ActivationBundle {
        entry: entry.clone(),
        initial_leases: vec![LeaseRecord {
            resource,
            owner: source_scope.node,
            epoch: LeaseEpoch(1),
        }],
    };

    let server =
        ProviderServer::start(&database_root, &socket).expect("provider server starts ready");
    probe(locator.as_str()).expect("protocol ping succeeds without opening a database");
    assert_eq!(
        fs::read_dir(&database_root).expect("database root is readable").count(),
        0,
        "ping must not create a provider database"
    );

    let mut source =
        NetworkProvider::connect(locator.as_str(), source_scope).expect("source RPC session opens");
    let destination = NetworkProvider::connect(locator.as_str(), destination_scope)
        .expect("destination RPC session opens");

    source
        .inject_failure_once(FaultPoint::BeforeActivationBundle)
        .expect("fault is armed over RPC");
    assert_eq!(
        source.commit_activation(&bundle).expect_err("pre-transaction fault is visible").kind,
        ProviderErrorKind::Unavailable
    );
    assert_eq!(source.entry(JournalPosition(1)), Ok(None));
    assert_eq!(destination.current_lease(resource), Ok(None));

    source
        .inject_failure_once(FaultPoint::AfterActivationBundle)
        .expect("lost-ACK fault is armed over RPC");
    assert_eq!(
        source.commit_activation(&bundle).expect_err("post-commit acknowledgement is lost").kind,
        ProviderErrorKind::OutcomeUnknown
    );
    assert_eq!(source.entry(JournalPosition(1)), Ok(Some(entry.clone())));
    assert_eq!(
        destination.current_lease(resource),
        Ok(Some(LeaseRecord { resource, owner: source_scope.node, epoch: LeaseEpoch(1) }))
    );
    assert_eq!(
        source.fault_observation(),
        Ok(Some(FaultObservation { point: FaultPoint::AfterActivationBundle, count: 2 }))
    );
    assert_eq!(
        destination.entry(JournalPosition(1)),
        Ok(None),
        "journal streams remain scope-local inside the shared transaction domain"
    );

    server.shutdown().expect("provider server shuts down");
    assert!(!socket.exists(), "shutdown unlinks the listening socket");
    assert_eq!(
        source
            .entry(JournalPosition(1))
            .expect_err("a session cannot outlive server shutdown")
            .kind,
        ProviderErrorKind::OutcomeUnknown
    );
    drop(source);
    drop(destination);

    let restarted =
        ProviderServer::start(&database_root, &socket).expect("provider server restarts");
    let mut source = NetworkProvider::connect(locator.as_str(), source_scope)
        .expect("source reconnects after server restart");
    let destination = NetworkProvider::connect(locator.as_str(), destination_scope)
        .expect("destination reconnects after server restart");
    assert_eq!(source.entry(JournalPosition(1)), Ok(Some(entry)));
    assert_eq!(
        destination.current_lease(resource),
        Ok(Some(LeaseRecord { resource, owner: source_scope.node, epoch: LeaseEpoch(1) }))
    );
    source.commit_activation(&bundle).expect("exact retry after restart is idempotent");
    drop(source);
    drop(destination);
    restarted.shutdown().expect("restarted server shuts down");
}

#[test]
fn concurrent_sessions_serialize_conflicting_activation_transactions() {
    let directory = TestDirectory::new("concurrency");
    let database_root = directory.path.join("databases");
    fs::create_dir(&database_root).expect("database root is created");
    let socket = directory.path.join("provider.sock");
    let locator = locator(&socket, '2');
    let journal_scope = scope(100, 101);
    let left_resource = entity(102);
    let right_resource = entity(103);
    let left_entry = activated_entry(104, 1);
    let right_entry = activated_entry(105, 2);
    let left_bundle = ActivationBundle {
        entry: left_entry.clone(),
        initial_leases: vec![LeaseRecord {
            resource: left_resource,
            owner: journal_scope.node,
            epoch: LeaseEpoch(1),
        }],
    };
    let right_bundle = ActivationBundle {
        entry: right_entry.clone(),
        initial_leases: vec![LeaseRecord {
            resource: right_resource,
            owner: journal_scope.node,
            epoch: LeaseEpoch(1),
        }],
    };

    let server =
        ProviderServer::start(&database_root, &socket).expect("provider server starts ready");
    let mut left =
        NetworkProvider::connect(locator.as_str(), journal_scope).expect("left session opens");
    let mut right =
        NetworkProvider::connect(locator.as_str(), journal_scope).expect("right session opens");
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);
    let left_thread = thread::spawn(move || {
        left_barrier.wait();
        left.commit_activation(&left_bundle)
    });
    let right_thread = thread::spawn(move || {
        right_barrier.wait();
        right.commit_activation(&right_bundle)
    });
    barrier.wait();
    let left_result = left_thread.join().expect("left session does not panic");
    let right_result = right_thread.join().expect("right session does not panic");
    let outcomes = [left_result, right_result];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter_map(|result| result.as_ref().err())
            .filter(|error| error.kind == ProviderErrorKind::Conflict)
            .count(),
        1
    );

    let observer =
        NetworkProvider::connect(locator.as_str(), journal_scope).expect("observer session opens");
    let committed = observer
        .entry(JournalPosition(1))
        .expect("committed journal is readable")
        .expect("one activation committed");
    if committed == left_entry {
        assert!(observer.current_lease(left_resource).unwrap().is_some());
        assert_eq!(observer.current_lease(right_resource), Ok(None));
    } else {
        assert_eq!(committed, right_entry);
        assert!(observer.current_lease(right_resource).unwrap().is_some());
        assert_eq!(observer.current_lease(left_resource), Ok(None));
    }
    drop(observer);
    server.shutdown().expect("provider server shuts down");
}
