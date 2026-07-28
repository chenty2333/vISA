//! Sample records, the JSONL sink, and the environment receipt.
//!
//! Every measurement leaves the harness as one line of `samples.jsonl`. The
//! terminal summary is computed from the same values that were written, so a
//! reported percentile can always be recomputed from the retained file.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{Value, json};

pub const SAMPLE_SCHEMA: &str = "visa-eval-sample-v1";
pub const META_SCHEMA: &str = "visa-eval-meta-v2";
pub const SAMPLES_FILE: &str = "samples.jsonl";
pub const META_FILE: &str = "meta.json";
pub const COMPLETION_FILE: &str = "completion.json";
pub const COMPLETION_SCHEMA: &str = "visa-eval-completion-v1";
pub(crate) const BUILD_GIT_COMMIT: &str = env!("VISA_EVAL_BUILD_GIT_COMMIT");
const BUILD_GIT_DIRTY: &str = env!("VISA_EVAL_BUILD_GIT_DIRTY");
const BUILD_RUSTC_VERSION: &str = env!("VISA_EVAL_BUILD_RUSTC_VERSION");
const BUILD_TARGET: &str = env!("VISA_EVAL_BUILD_TARGET");
const BUILD_PROFILE: &str = env!("VISA_EVAL_BUILD_PROFILE");
const BUILD_OPT_LEVEL: &str = env!("VISA_EVAL_BUILD_OPT_LEVEL");
const BUILD_CARGO_LOCK_SHA256: &str = env!("VISA_EVAL_BUILD_CARGO_LOCK_SHA256");

type ValuesByRun = BTreeMap<u32, Vec<u64>>;

/// One measurement. `value_ns` carries a duration, `bytes` carries a size;
/// a size-only sample leaves `value_ns` null and vice versa.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub schema: &'static str,
    pub measure: String,
    pub arm: String,
    pub phase: String,
    pub config: BTreeMap<String, Value>,
    pub run: u32,
    pub iter: u64,
    pub value_ns: Option<u64>,
    pub bytes: Option<u64>,
}

impl Sample {
    pub fn new(measure: &str, arm: &str, phase: &str) -> Self {
        Self {
            schema: SAMPLE_SCHEMA,
            measure: measure.to_owned(),
            arm: arm.to_owned(),
            phase: phase.to_owned(),
            config: BTreeMap::new(),
            run: 0,
            iter: 0,
            value_ns: None,
            bytes: None,
        }
    }

    #[must_use]
    pub fn config(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.config.insert(key.to_owned(), value.into());
        self
    }

    #[must_use]
    pub const fn at(mut self, run: u32, iter: u64) -> Self {
        self.run = run;
        self.iter = iter;
        self
    }

    #[must_use]
    pub const fn nanos(mut self, value_ns: u64) -> Self {
        self.value_ns = Some(value_ns);
        self
    }

    #[must_use]
    pub const fn bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Grouping label for the terminal summary. It mirrors the grouping the
    /// summarize script applies to the same file.
    fn group(&self) -> String {
        let config = self
            .config
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}/{}/{}/{}", self.measure, self.arm, self.phase, config)
    }
}

/// Appending JSONL sink that also accumulates values for the terminal recap.
pub struct SampleSink {
    writer: BufWriter<File>,
    path: PathBuf,
    durations: BTreeMap<String, ValuesByRun>,
    sizes: BTreeMap<String, ValuesByRun>,
    written: u64,
}

impl SampleSink {
    pub fn open(directory: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
        let path = directory.join(SAMPLES_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
            path,
            durations: BTreeMap::new(),
            sizes: BTreeMap::new(),
            written: 0,
        })
    }

    pub fn record(&mut self, sample: Sample) -> Result<(), String> {
        let line = serde_json::to_string(&sample)
            .map_err(|error| format!("cannot encode sample: {error}"))?;
        writeln!(self.writer, "{line}")
            .map_err(|error| format!("cannot write {}: {error}", self.path.display()))?;
        let group = sample.group();
        if let Some(value) = sample.value_ns {
            self.durations
                .entry(group.clone())
                .or_default()
                .entry(sample.run)
                .or_default()
                .push(value);
        }
        if let Some(bytes) = sample.bytes {
            self.sizes.entry(group).or_default().entry(sample.run).or_default().push(bytes);
        }
        self.written += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.writer
            .flush()
            .map_err(|error| format!("cannot flush {}: {error}", self.path.display()))
    }

    pub const fn written(&self) -> u64 {
        self.written
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Terminal recap over independent run medians, durations then sizes.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        for (label, by_run) in &self.durations {
            lines.push(report_group(label, by_run, "ns"));
        }
        for (label, by_run) in &self.sizes {
            lines.push(report_group(label, by_run, "bytes"));
        }
        lines.join("\n")
    }
}

fn report_group(label: &str, by_run: &ValuesByRun, unit: &str) -> String {
    let samples = by_run.values().map(Vec::len).sum::<usize>();
    let mut medians = by_run
        .values()
        .map(|values| {
            let mut sorted = values.clone();
            sorted.sort_unstable();
            percentile(&sorted, 50.0)
        })
        .collect::<Vec<_>>();
    medians.sort_unstable();
    format!(
        "  {label}  runs={} samples={} run-p50={} run-p95={} ({unit})",
        medians.len(),
        samples,
        percentile(&medians, 50.0),
        percentile(&medians, 95.0),
    )
}

/// Nearest-rank percentile over an already sorted slice. The summarize script
/// uses the same definition so the two never disagree.
#[must_use]
pub fn percentile(sorted: &[u64], percent: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (percent / 100.0 * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

/// Environment receipt written next to the samples.
pub fn write_meta(directory: &Path, parameters: Value) -> Result<PathBuf, String> {
    let filesystem = filesystem_for(directory);
    let workspace = workspace_root();
    let runtime_commit = git_output(&workspace, &["rev-parse", "HEAD"]);
    let runtime_dirty =
        git_output(&workspace, &["status", "--porcelain", "--untracked-files=normal"])
            .map(|status| !status.is_empty());
    let meta = json!({
        "schema": META_SCHEMA,
        "git_commit": BUILD_GIT_COMMIT,
        "git_dirty": BUILD_GIT_DIRTY == "true",
        "rustc_version": BUILD_RUSTC_VERSION,
        "cargo_lock_sha256": BUILD_CARGO_LOCK_SHA256,
        "binary_sha256": std::env::current_exe().ok().as_deref().and_then(sha256_file),
        "runtime_source_checkout": {
            "workspace_root": workspace.display().to_string(),
            "git_commit": runtime_commit,
            "git_dirty": runtime_dirty,
            "cargo_lock_sha256": sha256_file(&workspace.join("Cargo.lock")),
        },
        "build_profile": BUILD_PROFILE,
        "opt_level": BUILD_OPT_LEVEL,
        "kernel": command_output("uname", &["-s", "-r", "-v", "-m"]),
        "cpu": cpu_receipt(),
        "memory_total_kib": memory_total_kib(),
        "process_cpu_affinity": process_status_value("Cpus_allowed_list"),
        "cpu_governor": read_trimmed("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "target_triple": BUILD_TARGET,
        "output_directory": directory.display().to_string(),
        "filesystem": filesystem,
        "parameters": parameters,
    });
    let path = directory.join(META_FILE);
    let encoded =
        serde_json::to_vec_pretty(&meta).map_err(|error| format!("cannot encode meta: {error}"))?;
    std::fs::write(&path, encoded)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(path)
}

/// Digest-bound commit marker for a complete measurement artifact. Failed
/// invocations may retain diagnostics, but never receive this marker.
pub fn write_completion(directory: &Path, sample_count: u64) -> Result<PathBuf, String> {
    let samples = directory.join(SAMPLES_FILE);
    let meta = directory.join(META_FILE);
    sync_regular_file(&samples, "completed samples")?;
    sync_regular_file(&meta, "completed metadata")?;
    let document = json!({
        "schema": COMPLETION_SCHEMA,
        "git_commit": BUILD_GIT_COMMIT,
        "sample_count": sample_count,
        "samples_sha256": sha256_file(&samples).ok_or("cannot hash completed samples")?,
        "meta_sha256": sha256_file(&meta).ok_or("cannot hash completed metadata")?,
        "finished_at_unix_ms": u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch")?
                .as_millis()
        )
        .map_err(|_| "completion timestamp exceeds u64")?,
    });
    let encoded = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("cannot encode completion receipt: {error}"))?;
    let path = directory.join(COMPLETION_FILE);
    let temporary = directory.join(".completion.json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, &path)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {}: {error}", directory.display()))?;
    Ok(path)
}

fn sync_regular_file(path: &Path, label: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("cannot sync {label} {}: {error}", path.display()))
}

/// Refuse conditions that would make a paper-facing run ambiguous or merge
/// samples from different invocations. Normal smoke runs retain the convenient
/// append behaviour used by existing tests.
pub fn ensure_measurement_preconditions(
    directory: &Path,
    paper_grade: bool,
    runs: u32,
    iters: u64,
    warmup: u64,
) -> Result<(), String> {
    if !paper_grade {
        return Ok(());
    }
    if runs < 10 {
        return Err("--paper-grade requires at least 10 independent runs".to_owned());
    }
    if iters == 0 {
        return Err("--paper-grade requires at least one measured iteration per run".to_owned());
    }
    if warmup == 0 {
        return Err("--paper-grade requires at least one discarded warmup iteration".to_owned());
    }
    if cfg!(debug_assertions) || BUILD_PROFILE != "release" || BUILD_OPT_LEVEL == "0" {
        return Err("--paper-grade requires a --release build".to_owned());
    }
    if BUILD_GIT_DIRTY != "false" {
        return Err("--paper-grade requires a binary built from a clean worktree".to_owned());
    }
    if !valid_sha(BUILD_GIT_COMMIT) {
        return Err("--paper-grade binary does not embed a full Git SHA".to_owned());
    }
    let workspace = workspace_root();
    let commit = git_output(&workspace, &["rev-parse", "HEAD"])
        .ok_or("--paper-grade requires a Git worktree with a resolved HEAD")?;
    if !valid_sha(&commit) {
        return Err("--paper-grade could not resolve a full 40-character Git SHA".to_owned());
    }
    if commit != BUILD_GIT_COMMIT {
        return Err(format!(
            "--paper-grade source checkout {commit} differs from binary build {BUILD_GIT_COMMIT}"
        ));
    }
    let status = git_output(&workspace, &["status", "--porcelain", "--untracked-files=normal"])
        .ok_or("--paper-grade could not inspect the Git worktree")?;
    if !status.is_empty() {
        return Err("--paper-grade requires a clean exact-SHA worktree".to_owned());
    }
    if sha256_file(&workspace.join("Cargo.lock")).as_deref() != Some(BUILD_CARGO_LOCK_SHA256) {
        return Err("--paper-grade Cargo.lock differs from the binary build receipt".to_owned());
    }
    if is_memory_backed_path(directory) {
        return Err("--paper-grade refuses a memory-backed output filesystem".to_owned());
    }
    if directory.exists() {
        let mut entries = std::fs::read_dir(directory)
            .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "--paper-grade refuses non-empty output directory {}",
                directory.display()
            ));
        }
    }
    Ok(())
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."))
}

/// Mount point and filesystem type backing `directory`, from `/proc/mounts`.
/// A memory-backed filesystem makes every fsync measurement meaningless, so
/// the caller warns on it rather than silently publishing the numbers.
#[must_use]
pub fn filesystem_for(directory: &Path) -> Value {
    let Some(resolved) = existing_ancestor(directory) else {
        return Value::Null;
    };
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return Value::Null;
    };
    let mut best: Option<(PathBuf, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let Some(point) = fields.next() else { continue };
        let Some(kind) = fields.next() else { continue };
        let point = PathBuf::from(unescape_mount(point));
        if !resolved.starts_with(&point) {
            continue;
        }
        let longer = best
            .as_ref()
            .is_none_or(|(current, _)| point.components().count() > current.components().count());
        if longer {
            best = Some((point, kind.to_owned()));
        }
    }
    match best {
        Some((point, kind)) => json!({
            "mount_point": point.display().to_string(),
            "type": kind,
            "memory_backed": is_memory_backed(&kind),
        }),
        None => Value::Null,
    }
}

#[must_use]
pub fn is_memory_backed(filesystem_type: &str) -> bool {
    matches!(filesystem_type, "tmpfs" | "ramfs" | "devtmpfs")
}

/// True when the directory lives on a memory-backed filesystem.
#[must_use]
pub fn is_memory_backed_path(directory: &Path) -> bool {
    filesystem_for(directory).get("memory_backed").and_then(Value::as_bool).unwrap_or(false)
}

fn existing_ancestor(directory: &Path) -> Option<PathBuf> {
    let absolute = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(directory)
    };
    for candidate in absolute.ancestors() {
        if let Ok(resolved) = std::fs::canonicalize(candidate) {
            return Some(resolved);
        }
    }
    None
}

/// `/proc/mounts` escapes space, tab, newline, and backslash as octal.
fn unescape_mount(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(index) = rest.find('\\') {
        out.push_str(&rest[..index]);
        let escape = rest.get(index + 1..index + 4);
        match escape.and_then(|digits| u8::from_str_radix(digits, 8).ok()) {
            Some(byte) => {
                out.push(char::from(byte));
                rest = &rest[index + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[index + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn cpu_receipt() -> Value {
    let logical_cpus = std::thread::available_parallelism().ok().map(std::num::NonZero::get);
    let model = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|contents| {
        contents.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "model name").then(|| value.trim().to_owned())
        })
    });
    json!({"model": model, "logical_cpus_available": logical_cpus})
}

fn memory_total_kib() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = contents.lines().find(|line| line.starts_with("MemTotal:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn process_status_value(key: &str) -> Option<String> {
    let contents = std::fs::read_to_string("/proc/self/status").ok()?;
    contents.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate == key).then(|| value.trim().to_owned())
    })
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|value| value.trim().to_owned())
}

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}

fn git_output(workspace: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(workspace).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_grade_rejects_zero_iterations_before_source_checks() {
        let error = ensure_measurement_preconditions(Path::new("unused"), true, 10, 0, 1)
            .expect_err("zero iterations must fail");
        assert!(error.contains("measured iteration"));
    }

    #[test]
    fn paper_grade_rejects_zero_warmup_before_source_checks() {
        let error = ensure_measurement_preconditions(Path::new("unused"), true, 10, 1, 0)
            .expect_err("zero warmup must fail");
        assert!(error.contains("warmup"));
    }

    #[test]
    fn terminal_summary_uses_one_median_per_run() {
        let root = std::env::temp_dir().join(format!(
            "visa-eval-output-summary-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut sink = SampleSink::open(&root).unwrap();
        for (run, values) in [(0, [1, 100]), (1, [10, 20])] {
            for (iter, value) in values.into_iter().enumerate() {
                sink.record(Sample::new("m", "a", "p").at(run, iter as u64).nanos(value)).unwrap();
            }
        }

        let report = sink.report();
        assert!(report.contains("runs=2 samples=4 run-p50=1 run-p95=10"));
        drop(sink);
        std::fs::remove_dir_all(root).unwrap();
    }
}
