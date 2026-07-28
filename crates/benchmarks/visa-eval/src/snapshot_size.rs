//! (c) How large the portable snapshot is, field by field.
//!
//! One export of the four-resource cell is measured with `canonical_bytes`
//! applied to the whole body and to each field that can grow. The extension
//! tiers are obtained by re-encoding the same body with the extension list
//! narrowed, which gives the marginal encoded cost of the regular-file and
//! logical-request profiles in situ. That is a different construction from
//! running three separate cells, and is used because the composite fixture
//! publishes a profile that requires both extensions: a timer/key-value-only
//! cell would not accept this component at all.

use std::{fs, path::Path};

use contract_core::{Extension, Identity, SnapshotBody, SnapshotEnvelope, canonical_bytes};
use visa_profile::{FileDurability, LOGICAL_REQUEST_EXTENSION_ID, REGULAR_FILE_EXTENSION_ID};

use crate::{
    EvalOptions, LONG_TIMER_NANOS, activate_source, adapter_error, case_id, counterbalanced_values,
    create_fixture, derive,
    output::{Sample, SampleSink},
    phases::drain_request,
    runtime_error, snapshot_evidence, spawn_peer,
};

pub const MEASURE: &str = "snapshot-size";

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    for run in 0..options.runs {
        for effects in counterbalanced_values(&options.effects_before_handoff, run) {
            let root = options.run_root(MEASURE, run).join(format!("effects-{effects}"));
            one_export(&root, run, effects, sink)?;
        }
    }
    Ok(())
}

fn one_export(
    root: &Path,
    run: u32,
    effects_before_handoff: u64,
    sink: &mut SampleSink,
) -> Result<(), String> {
    let case = case_id(&format!("snapshot-{effects_before_handoff}"), run);
    let peer = spawn_peer()?;
    let fixture = create_fixture(root, &case, &peer)?;
    let cell = activate_source(fixture, &case)?;
    let mut adapter = cell.adapter;
    let ids = cell.ids;

    for index in 0..effects_before_handoff {
        adapter
            .kv_put(&format!("{case}-pre-{index}"), &index.to_be_bytes())
            .map_err(adapter_error)?;
    }
    adapter.timer_arm(LONG_TIMER_NANOS).map_err(adapter_error)?;
    adapter.file_append("append-src", b"!", FileDurability::Data).map_err(adapter_error)?;
    drain_request(&mut adapter)?;

    adapter
        .coordinator_mut()
        .begin_quiesce(derive(&case, "source-begin-quiesce"), ids.source_handoff_authority)
        .map_err(runtime_error)?;
    let safe_point = adapter.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = adapter.freeze().map_err(adapter_error)?;
    adapter
        .coordinator_mut()
        .commit_safe_point(derive(&case, "source-freeze"), portable.as_bytes().to_vec(), safe_point)
        .map_err(runtime_error)?;
    let evidence = snapshot_evidence(&case, adapter.coordinator())?;
    let (_, envelope) = adapter
        .coordinator_mut()
        .export_snapshot(derive(&case, "source-export"), ids.handoff, ids.snapshot, evidence)
        .map_err(runtime_error)?;

    record_sizes(sink, run, effects_before_handoff, &envelope)?;
    let bundle_bytes = write_bundle(root, &envelope, portable.as_bytes())?;
    sink.record(sample(run, effects_before_handoff, "bundle-directory-total").bytes(bundle_bytes))?;

    drop(adapter);
    drop(peer);
    Ok(())
}

fn record_sizes(
    sink: &mut SampleSink,
    run: u32,
    effects_before_handoff: u64,
    envelope: &SnapshotEnvelope,
) -> Result<(), String> {
    let body = &envelope.body;
    let whole_envelope = encoded_len("envelope", envelope)?;
    let whole_body = encoded_len("body", body)?;
    let claims = encoded_len("claims", &body.claims)?;
    let authorities = encoded_len("authorities", &body.authorities)?;
    let operations = encoded_len("operations", &body.operations)?;
    let extensions = encoded_len("extensions", &body.extensions)?;
    let envelope_json = serde_json::to_vec(envelope)
        .map_err(|error| format!("cannot JSON-encode envelope: {error}"))?
        .len() as u64;

    // Tiers. Each is the same body re-encoded with a narrower extension list,
    // so the difference is exactly what that extension costs on the wire.
    let timer_kv_only = encoded_len("timer/key-value tier", &narrowed(body, &[]))?;
    let plus_file = encoded_len("file tier", &narrowed(body, &[REGULAR_FILE_EXTENSION_ID]))?;
    let plus_request = encoded_len(
        "request tier",
        &narrowed(body, &[REGULAR_FILE_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_ID]),
    )?;

    let mut sizes = vec![
        ("envelope-canonical", whole_envelope),
        ("envelope-json", envelope_json),
        ("body-canonical", whole_body),
        ("portable-state", body.portable_state.len() as u64),
        ("claims-canonical", claims),
        ("authorities-canonical", authorities),
        ("operations-canonical", operations),
        ("extensions-canonical", extensions),
        ("tier-timer-kv", timer_kv_only),
        ("tier-plus-file", plus_file),
        ("tier-plus-request", plus_request),
        ("delta-file-extension", plus_file.saturating_sub(timer_kv_only)),
        ("delta-request-extension", plus_request.saturating_sub(plus_file)),
        ("count-operation-records", body.operations.len() as u64),
        ("count-authority-grants", body.authorities.len() as u64),
    ];
    for extension in &body.extensions {
        let label = if extension.id == REGULAR_FILE_EXTENSION_ID {
            "extension-payload-regular-file"
        } else if extension.id == LOGICAL_REQUEST_EXTENSION_ID {
            "extension-payload-logical-request"
        } else {
            "extension-payload-other"
        };
        sizes.push((label, extension.payload.len() as u64));
    }

    // `count-*` phases carry a record count rather than a byte size; the
    // sample schema has one numeric slot, and the phase name says which.
    for (phase, bytes) in sizes {
        sink.record(sample(run, effects_before_handoff, phase).bytes(bytes))?;
    }
    Ok(())
}

fn encoded_len<T: serde::Serialize>(label: &str, value: &T) -> Result<u64, String> {
    canonical_bytes(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|error| format!("cannot encode {label}: {error:?}"))
}

/// The same body with only the named extensions retained, in the order the
/// fixture publishes them.
fn narrowed(body: &SnapshotBody, keep: &[Identity]) -> SnapshotBody {
    let mut narrowed = body.clone();
    narrowed.extensions = body
        .extensions
        .iter()
        .filter(|extension| keep.contains(&extension.id))
        .cloned()
        .collect::<Vec<Extension>>();
    narrowed
}

/// Write the bundle a destination would actually receive and return its total
/// size on disk. This is the transfer cost, as distinct from the encoded field
/// sizes above.
fn write_bundle(root: &Path, envelope: &SnapshotEnvelope, portable: &[u8]) -> Result<u64, String> {
    let bundle = root.join("bundle");
    fs::create_dir_all(&bundle)
        .map_err(|error| format!("cannot create {}: {error}", bundle.display()))?;
    let canonical =
        canonical_bytes(envelope).map_err(|error| format!("cannot encode envelope: {error:?}"))?;
    let json = serde_json::to_vec_pretty(envelope)
        .map_err(|error| format!("cannot JSON-encode envelope: {error}"))?;
    for (name, bytes) in [
        ("snapshot.postcard", canonical.as_slice()),
        ("snapshot.json", json.as_slice()),
        ("portable-state.bin", portable),
    ] {
        let path = bundle.join(name);
        fs::write(&path, bytes)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    }
    directory_bytes(&bundle)
}

/// Total size of the regular files under `directory`.
pub fn directory_bytes(directory: &Path) -> Result<u64, String> {
    let mut total = 0;
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("cannot stat {}: {error}", entry.path().display()))?;
        if metadata.is_dir() {
            total += directory_bytes(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}

fn sample(run: u32, effects_before_handoff: u64, phase: &str) -> Sample {
    Sample::new(MEASURE, "composite-cell", phase)
        .config("effects_before_handoff", effects_before_handoff)
        .at(run, 0)
}
