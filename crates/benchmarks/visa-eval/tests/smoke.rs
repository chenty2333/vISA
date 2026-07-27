//! Second-scale proof that each measure still drives the real spine.
//!
//! These are not measurements. Every parameter is the smallest value that
//! still exercises the path, because the workspace test tier runs them on
//! every change and a real measurement run takes minutes.

use std::path::{Path, PathBuf};

use visa_eval::{
    EvalOptions, Measure,
    output::{SampleSink, percentile},
    phases, restart, snapshot_size, steady_state,
};

/// One temporary directory per test, removed when the test finishes.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "visa-eval-smoke-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is before the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("cannot create scratch directory");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn smoke_options(root: &Path) -> EvalOptions {
    EvalOptions {
        out: root.to_path_buf(),
        iters: 2,
        warmup: 1,
        runs: 1,
        effects_before_handoff: vec![2],
        digest_operations: vec![2],
    }
}

#[test]
fn steady_state_records_both_arms() {
    let scratch = Scratch::new("steady");
    let options = smoke_options(scratch.path());
    let mut sink = SampleSink::open(scratch.path()).expect("cannot open sink");
    steady_state::run(&options, &mut sink).expect("steady-state smoke failed");
    sink.flush().expect("cannot flush");

    let samples = read_samples(scratch.path());
    let arms = arms_for(&samples, steady_state::MEASURE);
    assert!(arms.contains(&"coordinator".to_owned()), "missing coordinator arm: {arms:?}");
    assert!(arms.contains(&"sqlite-baseline".to_owned()), "missing baseline arm: {arms:?}");
    // Every recorded effect executed durably rather than replaying, so no
    // sample may be implausibly close to zero.
    for sample in &samples {
        if sample["arm"] == "coordinator" {
            let value = sample["value_ns"].as_u64().expect("coordinator sample has no duration");
            assert!(value > 0, "coordinator effect took no measurable time");
        }
    }
}

#[test]
fn handoff_phases_covers_every_segment() {
    let scratch = Scratch::new("phases");
    let options = smoke_options(scratch.path());
    let mut sink = SampleSink::open(scratch.path()).expect("cannot open sink");
    phases::run(&options, &mut sink).expect("handoff-phases smoke failed");
    sink.flush().expect("cannot flush");

    let samples = read_samples(scratch.path());
    let phases_seen = phases_for(&samples, phases::MEASURE);
    for expected in [
        "quiesce-begin",
        "quiesce-prepare-safe-point",
        "quiesce-freeze",
        "quiesce-commit-safe-point",
        "export-snapshot",
        "validate-snapshot",
        "rebind-coordinator-restore",
        "reauthorize-prepare-destination",
        "commit-handoff",
        "rebind-adapter-instantiate",
        "rebind-adapter-restore",
        "resume-destination",
        "handoff-total",
    ] {
        assert!(phases_seen.contains(&expected.to_owned()), "missing phase {expected}");
    }
}

#[test]
fn snapshot_size_decomposes_the_body() {
    let scratch = Scratch::new("snapshot");
    let options = smoke_options(scratch.path());
    let mut sink = SampleSink::open(scratch.path()).expect("cannot open sink");
    snapshot_size::run(&options, &mut sink).expect("snapshot-size smoke failed");
    sink.flush().expect("cannot flush");

    let samples = read_samples(scratch.path());
    let sized = |phase: &str| -> u64 {
        samples
            .iter()
            .find(|sample| sample["phase"] == phase)
            .and_then(|sample| sample["bytes"].as_u64())
            .unwrap_or_else(|| panic!("no size sample for {phase}"))
    };
    // Narrowing the extension list can only shrink the body, and the whole
    // envelope can never be smaller than the body it wraps.
    assert!(sized("tier-timer-kv") <= sized("tier-plus-file"));
    assert!(sized("tier-plus-file") <= sized("tier-plus-request"));
    assert_eq!(sized("tier-plus-request"), sized("body-canonical"));
    assert!(sized("body-canonical") <= sized("envelope-canonical"));
}

#[test]
fn restart_baseline_runs_both_arms() {
    let scratch = Scratch::new("restart");
    let options = smoke_options(scratch.path());
    let mut sink = SampleSink::open(scratch.path()).expect("cannot open sink");
    restart::run(&options, &mut sink).expect("restart-baseline smoke failed");
    sink.flush().expect("cannot flush");

    let samples = read_samples(scratch.path());
    let arms = arms_for(&samples, restart::MEASURE);
    assert!(arms.contains(&"coordinator-replay".to_owned()), "missing replay arm: {arms:?}");
    assert!(arms.contains(&"raw-sqlite".to_owned()), "missing raw arm: {arms:?}");
    assert!(!restart::LOSSY_NOTES.is_empty(), "the lossy baseline must document what it drops");
}

#[test]
fn percentiles_use_nearest_rank() {
    let values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    assert_eq!(percentile(&values, 50.0), 50);
    assert_eq!(percentile(&values, 95.0), 100);
    assert_eq!(percentile(&[], 50.0), 0);
    assert_eq!(percentile(&[7], 95.0), 7);
}

#[test]
fn every_measure_has_a_label() {
    let labels = Measure::all()
        .iter()
        .map(|measure| measure.label())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(labels.len(), Measure::all().len());
}

fn read_samples(root: &Path) -> Vec<serde_json::Value> {
    let path = root.join("samples.jsonl");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("sample is not valid JSON"))
        .inspect(|sample: &serde_json::Value| {
            assert_eq!(sample["schema"], "visa-eval-sample-v1");
        })
        .collect()
}

fn arms_for(samples: &[serde_json::Value], measure: &str) -> Vec<String> {
    samples
        .iter()
        .filter(|sample| sample["measure"] == measure)
        .filter_map(|sample| sample["arm"].as_str().map(str::to_owned))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn phases_for(samples: &[serde_json::Value], measure: &str) -> Vec<String> {
    samples
        .iter()
        .filter(|sample| sample["measure"] == measure)
        .filter_map(|sample| sample["phase"].as_str().map(str::to_owned))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
