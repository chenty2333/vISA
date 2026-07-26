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
};

use serde::Serialize;
use serde_json::{Value, json};

pub const SAMPLE_SCHEMA: &str = "visa-eval-sample-v1";
pub const META_SCHEMA: &str = "visa-eval-meta-v1";
pub const SAMPLES_FILE: &str = "samples.jsonl";
pub const META_FILE: &str = "meta.json";

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
    durations: BTreeMap<String, Vec<u64>>,
    sizes: BTreeMap<String, Vec<u64>>,
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
            self.durations.entry(group.clone()).or_default().push(value);
        }
        if let Some(bytes) = sample.bytes {
            self.sizes.entry(group).or_default().push(bytes);
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

    /// Terminal recap: p50/p95/count per group, durations then sizes.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        for (label, values) in &self.durations {
            let mut sorted = values.clone();
            sorted.sort_unstable();
            lines.push(format!(
                "  {label}  n={} p50={} p95={} (ns)",
                sorted.len(),
                percentile(&sorted, 50.0),
                percentile(&sorted, 95.0),
            ));
        }
        for (label, values) in &self.sizes {
            let mut sorted = values.clone();
            sorted.sort_unstable();
            lines.push(format!(
                "  {label}  n={} p50={} p95={} (bytes)",
                sorted.len(),
                percentile(&sorted, 50.0),
                percentile(&sorted, 95.0),
            ));
        }
        lines.join("\n")
    }
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
    let meta = json!({
        "schema": META_SCHEMA,
        "git_commit": command_output("git", &["rev-parse", "HEAD"]),
        "git_dirty": command_output("git", &["status", "--porcelain"])
            .map(|status| !status.is_empty()),
        "rustc_version": command_output("rustc", &["--version"]),
        "hostname": hostname(),
        "target_triple": std::env::consts::ARCH.to_owned() + "-" + std::env::consts::OS,
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

fn hostname() -> Value {
    match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(name) => Value::String(name.trim().to_owned()),
        Err(_) => command_output("hostname", &[]).map_or(Value::Null, Value::String),
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
