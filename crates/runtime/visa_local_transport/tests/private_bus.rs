#![cfg(target_os = "linux")]

use std::{env, fs, process::Command};

use sha2::{Digest as _, Sha256};
use visa_local_transport::{LocalPeerVerifier, PeerVerificationError};
use zbus::fdo::{RequestNameFlags, RequestNameReply};

const INNER_ENV: &str = "VISA_LOCAL_TRANSPORT_PRIVATE_BUS_INNER";
const PEER_NAME: &str = "io.github.chenty2333.vISA.TransportTest1";

#[test]
fn private_bus_verifies_named_peer_and_rejects_substitution() {
    if env::var_os(INNER_ENV).is_none() {
        let status = Command::new("dbus-run-session")
            .arg("--")
            .arg(env::current_exe().expect("current integration-test executable"))
            .arg("--exact")
            .arg("private_bus_verifies_named_peer_and_rejects_substitution")
            .arg("--nocapture")
            .env(INNER_ENV, "1")
            .status()
            .expect("start isolated D-Bus session");
        assert!(status.success(), "nested private-bus test failed: {status}");
        return;
    }

    zbus::block_on(async {
        let owner = zbus::Connection::session().await.expect("owner connection");
        let reply = owner
            .request_name_with_flags(PEER_NAME, RequestNameFlags::DoNotQueue.into())
            .await
            .expect("acquire peer name");
        assert!(matches!(reply, RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner));

        let verifier_connection = zbus::Connection::session().await.expect("verifier connection");
        let verifier = LocalPeerVerifier::new(&verifier_connection);
        let owner_unique = owner.unique_name().expect("owner unique name");
        let digest: [u8; 32] = Sha256::digest(
            fs::read(env::current_exe().expect("current test executable path"))
                .expect("read current test executable"),
        )
        .into();

        let peer = verifier
            .verify_named_peer(PEER_NAME, owner_unique, digest)
            .await
            .expect("verify named peer");
        assert_eq!(peer.pid(), std::process::id());
        assert_eq!(peer.executable_sha256(), digest);
        peer.require_live().expect("verified process remains live");

        assert!(matches!(
            verifier.verify_named_peer(PEER_NAME, owner_unique, [0x9a; 32]).await,
            Err(PeerVerificationError::ExecutableDigestMismatch)
        ));

        let substitute = zbus::Connection::session().await.expect("substitute connection");
        assert!(matches!(
            verifier
                .verify_named_peer(
                    PEER_NAME,
                    substitute.unique_name().expect("substitute unique name"),
                    digest,
                )
                .await,
            Err(PeerVerificationError::NameOwnerMismatch)
        ));
    });
}
