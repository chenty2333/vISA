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

#[test]
fn generic_publication_accepts_arbitrary_bytes_and_ignores_sqlite_sidecars() {
    let fixture = Fixture::new();
    let final_path = fixture.database.with_extension("manifest");
    let sidecar = sqlite_sidecar_path(&final_path, "-wal");
    fs::write(&sidecar, b"sidecar remains independent").expect("create sidecar-like path");
    let payload = b"not an SQLite database\0with arbitrary bytes";
    let nonce = [0x11_u8; 16];
    let temporary = initialization_path(&final_path, nonce);

    publish_private_noreplace(&final_path, payload, nonce).expect("publish generic bytes");

    assert_eq!(fs::read(&final_path).expect("read published bytes"), payload);
    assert_eq!(
        fs::read(&sidecar).expect("retain sidecar-like path"),
        b"sidecar remains independent"
    );
    assert_eq!(
        fs::metadata(&final_path).expect("published metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(!temporary.exists(), "temporary file must not remain visible");
}

#[test]
fn generic_publication_is_noreplace_and_preserves_competing_paths() {
    let fixture = Fixture::new();
    let final_path = fixture.database.with_extension("manifest");
    fs::write(&final_path, b"original").expect("create existing final");
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600))
        .expect("restrict existing final");

    let conflict_nonce = [0x22_u8; 16];
    let conflict_temporary = initialization_path(&final_path, conflict_nonce);
    assert!(matches!(
        publish_private_noreplace(&final_path, b"replacement", conflict_nonce),
        Err(DurableStoreError::AlreadyExists)
    ));
    assert_eq!(fs::read(&final_path).expect("retain existing final"), b"original");
    assert!(!conflict_temporary.exists(), "owned temporary must be cleaned after conflict");

    let occupied_nonce = [0x33_u8; 16];
    let occupied_temporary = initialization_path(&final_path, occupied_nonce);
    fs::write(&occupied_temporary, b"preexisting temporary").expect("occupy temporary path");
    fs::set_permissions(&occupied_temporary, fs::Permissions::from_mode(0o600))
        .expect("restrict occupied temporary");
    assert!(matches!(
        publish_private_noreplace(&final_path, b"replacement", occupied_nonce),
        Err(DurableStoreError::AlreadyExists)
    ));
    assert_eq!(
        fs::read(&occupied_temporary).expect("preserve preexisting temporary"),
        b"preexisting temporary"
    );

    let target = fixture.database.with_extension("target");
    fs::write(&target, b"symlink target").expect("create symlink target");
    let symlink_final = fixture.database.with_extension("symlink-manifest");
    std::os::unix::fs::symlink(&target, &symlink_final).expect("create symlink final");
    let symlink_nonce = [0x44_u8; 16];
    let symlink_temporary = initialization_path(&symlink_final, symlink_nonce);
    assert!(matches!(
        publish_private_noreplace(&symlink_final, b"must not replace", symlink_nonce),
        Err(DurableStoreError::AlreadyExists)
    ));
    assert!(
        fs::symlink_metadata(&symlink_final)
            .expect("retain final symlink")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&target).expect("retain symlink target"), b"symlink target");
    assert!(!symlink_temporary.exists(), "temporary must be cleaned after symlink conflict");
}
