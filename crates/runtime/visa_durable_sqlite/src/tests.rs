use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use rusqlite::Connection;
use tempfile::{TempDir, tempdir};

use super::*;

struct Fixture {
    _root: TempDir,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempdir().expect("temporary root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private temporary root");
        Self { database: root.path().join("state.sqlite"), _root: root }
    }

    fn lock_path(&self) -> PathBuf {
        let mut path = self.database.as_os_str().to_os_string();
        path.push(".lock");
        path.into()
    }
}

#[test]
fn lock_is_private_single_writer_and_nofollow() {
    let fixture = Fixture::new();
    let lock = StoreLock::acquire(fixture.lock_path()).expect("acquire first lock");
    assert_eq!(
        fs::metadata(lock.path()).expect("lock metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(StoreLock::acquire(lock.path()), Err(DurableStoreError::Busy)));
    drop(lock);
    let reacquired = StoreLock::acquire(fixture.lock_path()).expect("reacquire lock");
    drop(reacquired);

    let symlink = fixture.database.with_extension("link.lock");
    std::os::unix::fs::symlink(fixture.lock_path(), &symlink).expect("lock symlink");
    assert!(matches!(
        StoreLock::acquire(&symlink),
        Err(DurableStoreError::Insecure | DurableStoreError::Io(_))
    ));
}

#[test]
fn database_guard_requires_private_regular_sqlite_file() {
    let fixture = Fixture::new();
    let guard = DatabaseGuard::create_new(&fixture.database).expect("create database");
    assert_eq!(
        fs::metadata(&fixture.database).expect("database metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(guard.verify_sqlite_header(), Err(DurableStoreError::NotSqlite)));

    let connection = Connection::open(&fixture.database).expect("open SQLite");
    connection
        .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE marker(value TEXT);")
        .expect("initialize SQLite");
    checkpoint_truncate(&connection).expect("checkpoint SQLite");
    drop(connection);
    ensure_sqlite_sidecars_absent(&fixture.database).expect("sidecars gone after close");
    guard.verify_sqlite_header().expect("SQLite header");
    guard.sync().expect("sync database");
    drop(guard);

    let reopened = DatabaseGuard::open_existing(&fixture.database).expect("reopen database");
    assert_eq!(reopened.path(), fixture.database.as_path());
}

#[test]
fn publication_is_noreplace_and_cleanup_is_inode_bound() {
    let fixture = Fixture::new();
    let temporary = initialization_path(&fixture.database, [7_u8; 16]);
    let guard = DatabaseGuard::create_new(&temporary).expect("create temporary");
    let connection = Connection::open(&temporary).expect("open temporary SQLite");
    connection
        .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE marker(value INTEGER);")
        .expect("initialize temporary SQLite");
    checkpoint_truncate(&connection).expect("checkpoint temporary SQLite");
    drop(connection);
    guard.publish_noreplace(&fixture.database).expect("publish final database");
    assert!(fixture.database.exists());
    assert!(!temporary.exists());
    drop(guard);

    let competing_temporary = initialization_path(&fixture.database, [9_u8; 16]);
    let competing_guard =
        DatabaseGuard::create_new(&competing_temporary).expect("create competing temp");
    let competing_connection =
        Connection::open(&competing_temporary).expect("open competing SQLite");
    competing_connection
        .execute_batch("CREATE TABLE marker(value INTEGER);")
        .expect("initialize competing SQLite");
    drop(competing_connection);
    assert!(matches!(
        competing_guard.publish_noreplace(&fixture.database),
        Err(DurableStoreError::AlreadyExists)
    ));
    competing_guard.cleanup_owned();
    drop(competing_guard);

    let second_temporary = initialization_path(&fixture.database, [8_u8; 16]);
    let second_guard = DatabaseGuard::create_new(&second_temporary).expect("create second temp");
    fs::write(&second_temporary, b"partial").expect("replace temporary contents");
    let replacement = second_temporary.with_extension("replacement");
    fs::rename(&second_temporary, &replacement).expect("rename temporary away");
    fs::write(&second_temporary, b"attacker path").expect("create replacement path");
    second_guard.cleanup_owned();
    assert_eq!(fs::read(&second_temporary).expect("retain swapped path"), b"attacker path");
    drop(second_guard);
}

#[test]
fn preexisting_sidecar_is_never_consumed() {
    let fixture = Fixture::new();
    let sidecar = sqlite_sidecar_path(&fixture.database, "-wal");
    fs::write(&sidecar, b"keep me").expect("create sidecar");
    assert!(matches!(
        DatabaseGuard::create_new(&fixture.database),
        Err(DurableStoreError::SidecarExists)
    ));
    assert_eq!(fs::read(&sidecar).expect("retain sidecar"), b"keep me");
}
