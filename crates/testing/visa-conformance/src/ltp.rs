use std::{
    collections::BTreeMap,
    fs, io,
    path::{Component, Path, PathBuf},
};

use crate::{
    catalog::linux_ltp_catalog,
    hash::sha256_hex,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, LtpCaseResult,
        LtpSubset, LtpVisaPlanEntry, Outcome, REPORT_SCHEMA_VERSION, TestResult, TestSpec,
    },
};

pub const LTP_VISA_TRACE_SCHEMA_VERSION: &str = "visa-ltp-execution-trace-v0.1";
pub const LTP_FULL_SUITE_ID: &str = "visa-linux-ltp-personality-compatibility";
pub const LTP_VISA_SUBSET_SUITE_ID: &str = "visa-linux-ltp-visa-backed-subset";

pub fn parse_ltp_results(text: &str) -> Vec<LtpCaseResult> {
    text.lines().filter_map(parse_ltp_result_line).collect()
}

pub fn parse_ltp_result_line(line: &str) -> Option<LtpCaseResult> {
    let clean_line = strip_ansi_csi(line);
    let trimmed = clean_line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut case_id = trimmed.split_whitespace().next()?.trim_end_matches(':').to_string();
    let (raw_status, outcome) = trimmed.split_whitespace().find_map(|token| {
        normalize_ltp_status(token).map(|outcome| (token.to_string(), outcome))
    })?;
    if matches!(case_id.as_str(), "PASS" | "FAIL" | "TPASS" | "TFAIL" | "SKIP" | "CONF") {
        case_id = "unknown".to_string();
    }
    Some(LtpCaseResult { case_id, outcome, raw_status, detail: trimmed.to_string() })
}

pub fn ltp_subset_result(
    spec: &TestSpec,
    cases: &[LtpCaseResult],
    observed_boundary: Boundary,
    observed_profile: Option<String>,
) -> TestResult {
    let passed = cases.iter().filter(|case| case.outcome == Outcome::Pass).count();
    let failed = cases.iter().filter(|case| case.outcome == Outcome::Fail).count();
    let skipped = cases.iter().filter(|case| case.outcome == Outcome::Skip).count();
    let outcome = if failed > 0 {
        Outcome::Fail
    } else if passed > 0 {
        Outcome::Pass
    } else if skipped > 0 {
        Outcome::Skip
    } else {
        Outcome::NotRun
    };
    let mut metrics = BTreeMap::new();
    metrics.insert("ltp_cases_passed".to_string(), passed as f64);
    metrics.insert("ltp_cases_failed".to_string(), failed as f64);
    metrics.insert("ltp_cases_skipped".to_string(), skipped as f64);
    TestResult {
        spec_id: spec.id.clone(),
        outcome,
        observed_boundary,
        observed_profile,
        evidence: format!(
            "LTP subset {} parsed {} cases: {passed} passed, {failed} failed, {skipped} skipped",
            spec.id,
            cases.len()
        ),
        remaining_uncertainty: "LTP compatibility does not prove vISA semantic completeness, substrate profile conformance, or real target substrate execution unless separately claimed with matching evidence".to_string(),
        metrics,
        evidence_artifacts: Vec::new(),
    }
}

pub fn ltp_report_from_subset_logs<'a>(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    logs: impl IntoIterator<Item = (LtpSubset, &'a str)>,
) -> ConformanceReport {
    let logs = logs.into_iter().collect::<BTreeMap<_, _>>();
    let results = linux_ltp_catalog()
        .into_iter()
        .map(|spec| {
            let subset = LtpSubset::from_spec_id(&spec.id).expect("linux_ltp_catalog id mismatch");
            let observed_profile =
                observed_profile_override.clone().or_else(|| spec.required_profile.clone());
            match logs.get(&subset) {
                Some(text) => {
                    let cases = parse_ltp_results(text);
                    ltp_subset_result(&spec, &cases, observed_boundary, observed_profile)
                }
                None => TestResult {
                    spec_id: spec.id,
                    outcome: Outcome::NotRun,
                    observed_boundary,
                    observed_profile,
                    evidence: "LTP subset log was not provided".to_string(),
                    remaining_uncertainty:
                        "subset was not executed or the runner did not collect its log".to_string(),
                    metrics: BTreeMap::new(),
                    evidence_artifacts: Vec::new(),
                },
            }
        })
        .collect();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: LTP_FULL_SUITE_ID.to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results,
    }
}

pub fn ltp_report_from_log_dir(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    log_dir: impl AsRef<Path>,
) -> io::Result<ConformanceReport> {
    ltp_report_from_log_dir_with_scope(
        target,
        generated_by,
        LTP_FULL_SUITE_ID,
        observed_boundary,
        observed_profile_override,
        log_dir,
        false,
    )
}

pub fn ltp_visa_subset_report_from_log_dir(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    log_dir: impl AsRef<Path>,
) -> io::Result<ConformanceReport> {
    ltp_report_from_log_dir_with_scope(
        target,
        generated_by,
        LTP_VISA_SUBSET_SUITE_ID,
        observed_boundary,
        observed_profile_override,
        log_dir,
        true,
    )
}

fn ltp_report_from_log_dir_with_scope(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    suite_id: &str,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    log_dir: impl AsRef<Path>,
    present_logs_only: bool,
) -> io::Result<ConformanceReport> {
    let log_dir = log_dir.as_ref();
    let mut logs = Vec::new();
    for subset in LtpSubset::ALL {
        if let Some((text, artifacts)) = read_subset_log_bundle(log_dir, subset)? {
            logs.push((subset, text, artifacts));
        }
    }

    let mut report = if present_logs_only {
        ltp_subset_report_from_present_logs(
            target,
            generated_by,
            suite_id,
            observed_boundary,
            observed_profile_override,
            logs.iter().map(|(subset, text, _artifacts)| (*subset, text.as_str())),
        )
    } else {
        let mut report = ltp_report_from_subset_logs(
            target,
            generated_by,
            observed_boundary,
            observed_profile_override,
            logs.iter().map(|(subset, text, _artifacts)| (*subset, text.as_str())),
        );
        report.suite_id = suite_id.to_string();
        report
    };
    for result in &mut report.results {
        if let Some((_subset, _text, artifacts)) =
            logs.iter().find(|(subset, _text, _artifacts)| subset.spec_id() == result.spec_id)
        {
            result.evidence_artifacts.extend(artifacts.iter().cloned());
        }
    }
    Ok(report)
}

pub fn ltp_subset_report_from_present_logs<'a>(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    suite_id: &str,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    logs: impl IntoIterator<Item = (LtpSubset, &'a str)>,
) -> ConformanceReport {
    let logs = logs.into_iter().collect::<BTreeMap<_, _>>();
    let results = linux_ltp_catalog()
        .into_iter()
        .filter_map(|spec| {
            let subset = LtpSubset::from_spec_id(&spec.id).expect("linux_ltp_catalog id mismatch");
            let text = logs.get(&subset)?;
            let observed_profile =
                observed_profile_override.clone().or_else(|| spec.required_profile.clone());
            let cases = parse_ltp_results(text);
            Some(ltp_subset_result(&spec, &cases, observed_boundary, observed_profile))
        })
        .collect();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: suite_id.to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results,
    }
}

fn read_subset_log_bundle(
    log_dir: &Path,
    subset: LtpSubset,
) -> io::Result<Option<(String, Vec<EvidenceArtifact>)>> {
    let raw_names = matching_log_names(log_dir, subset, ".log", true)?;
    if raw_names.is_empty() {
        return Ok(None);
    }

    let mut text = String::new();
    let mut artifacts = Vec::new();
    for raw_name in raw_names {
        let bytes = fs::read(log_dir.join(&raw_name))?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&bytes));
        artifacts.push(EvidenceArtifact {
            kind: EvidenceArtifactKind::LtpRawLog,
            uri: raw_name,
            sha256: sha256_hex(&bytes),
            description: format!("raw LTP result log for {}", subset.spec_id()),
        });
    }

    for trace_name in matching_log_names(log_dir, subset, ".visa-trace.jsonl", false)? {
        let bytes = fs::read(log_dir.join(&trace_name))?;
        artifacts.push(EvidenceArtifact {
            kind: EvidenceArtifactKind::LinuxPersonalityTrace,
            uri: trace_name,
            sha256: sha256_hex(&bytes),
            description: format!("vISA Linux personality execution trace for {}", subset.spec_id()),
        });
    }

    Ok(Some((text, artifacts)))
}

fn matching_log_names(
    log_dir: &Path,
    subset: LtpSubset,
    suffix: &str,
    exclude_serial: bool,
) -> io::Result<Vec<String>> {
    let spec_id = subset.spec_id();
    let exact = format!("{spec_id}{suffix}");
    let prefix = format!("{spec_id}.");
    let mut names = Vec::new();

    match fs::read(&log_dir.join(&exact)) {
        Ok(_) => names.push(exact.clone()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(names),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == exact || !name.starts_with(&prefix) || !name.ends_with(suffix) {
            continue;
        }
        if exclude_serial && (name.ends_with(".serial.log") || name.ends_with(".host-runltp.log")) {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

pub fn default_visa_ltp_plan(
    output_dir: impl AsRef<Path>,
    binary_root: impl AsRef<Path>,
) -> Vec<LtpVisaPlanEntry> {
    let output_dir = output_dir.as_ref();
    let binary_root = binary_root.as_ref();
    [
        (LtpSubset::FsBasic, "open01"),
        (LtpSubset::MmMapping, "mmap01"),
        (LtpSubset::MmMapping, "brk01"),
        (LtpSubset::SyscallsCore, "getpid01"),
        (LtpSubset::SyscallsCore, "uname01"),
        (LtpSubset::SyscallsCore, "getuid01"),
        (LtpSubset::SyscallsCore, "gettid01"),
        (LtpSubset::SyscallsCore, "read01"),
        (LtpSubset::SyscallsCore, "write01"),
        (LtpSubset::SchedTimers, "clock_gettime01"),
        (LtpSubset::SchedTimers, "nanosleep01"),
        (LtpSubset::NetSocket, "socket01"),
    ]
    .into_iter()
    .map(|(subset, case_id)| visa_ltp_plan_entry(output_dir, binary_root, subset, case_id))
    .collect()
}

pub fn visa_ltp_manifest_plan(
    output_dir: impl AsRef<Path>,
    binary_root: impl AsRef<Path>,
    manifest_text: &str,
) -> Result<Vec<LtpVisaPlanEntry>, String> {
    let output_dir = output_dir.as_ref();
    let binary_root = binary_root.as_ref();
    let mut entries = Vec::new();
    for (line_idx, raw_line) in manifest_text.lines().enumerate() {
        let line_number = line_idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 3 {
            return Err(format!(
                "line {line_number}: expected spec_id, case_id, and relative binary path"
            ));
        }
        let spec_id = fields[0].trim();
        let case_id = fields[1].trim();
        let relative_binary = fields[2].trim();
        let subset = LtpSubset::from_spec_id(spec_id)
            .ok_or_else(|| format!("line {line_number}: unknown LTP spec id {spec_id}"))?;
        validate_ltp_case_id(case_id, line_number)?;
        let relative_binary = validate_ltp_relative_path(relative_binary, line_number)?;
        entries.push(visa_ltp_plan_entry_with_binary(
            output_dir,
            binary_root,
            subset,
            case_id,
            &relative_binary,
        ));
    }
    if entries.is_empty() {
        return Err("manifest did not contain any vISA LTP entries".to_string());
    }
    Ok(entries)
}

fn visa_ltp_plan_entry(
    output_dir: &Path,
    binary_root: &Path,
    subset: LtpSubset,
    case_id: &str,
) -> LtpVisaPlanEntry {
    visa_ltp_plan_entry_with_binary(output_dir, binary_root, subset, case_id, Path::new(case_id))
}

fn visa_ltp_plan_entry_with_binary(
    output_dir: &Path,
    binary_root: &Path,
    subset: LtpSubset,
    case_id: &str,
    relative_binary: &Path,
) -> LtpVisaPlanEntry {
    let spec_id = subset.spec_id().to_string();
    let binary_path = binary_root.join(relative_binary);
    let logs_dir = output_dir.join("logs");
    LtpVisaPlanEntry {
        spec_id,
        subset,
        case_id: case_id.to_string(),
        binary_path: path_string(binary_path),
        output_log: path_string(logs_dir.join(format!("{}.{}.log", subset.spec_id(), case_id))),
        trace_log: path_string(logs_dir.join(format!(
            "{}.{}.visa-trace.jsonl",
            subset.spec_id(),
            case_id
        ))),
        serial_log: path_string(logs_dir.join(format!(
            "{}.{}.serial.log",
            subset.spec_id(),
            case_id
        ))),
    }
}

fn validate_ltp_case_id(case_id: &str, line_number: usize) -> Result<(), String> {
    if case_id.is_empty() {
        return Err(format!("line {line_number}: case id is empty"));
    }
    if !case_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(format!(
            "line {line_number}: case id {case_id:?} is not safe for log file names"
        ));
    }
    Ok(())
}

fn validate_ltp_relative_path(path: &str, line_number: usize) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err(format!("line {line_number}: binary path is empty"));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(format!("line {line_number}: binary path must be relative"));
    }
    if !path.components().all(|component| matches!(component, Component::Normal(_))) {
        return Err(format!(
            "line {line_number}: binary path must not contain '.', '..', prefixes, or roots"
        ));
    }
    Ok(path.to_path_buf())
}

fn path_string(path: PathBuf) -> String {
    path.display().to_string()
}

pub fn ltp_raw_log_from_serial(case_id: &str, serial_text: &str, runner_status: i32) -> String {
    let mut out = String::new();
    for line in serial_text.lines() {
        let clean_line = strip_ansi_csi(line);
        if parse_ltp_result_line(&clean_line).is_some() {
            out.push_str(clean_line.trim());
            out.push('\n');
        }
    }
    if !out.is_empty() {
        return out;
    }

    if runner_status == 0 && serial_text.contains("visa: demo completed") {
        format!("{case_id} 1 TPASS : vISA Linux personality execution completed\n")
    } else {
        let detail = serial_text
            .lines()
            .find(|line| {
                line.contains("visa: user ELF exited") || line.contains("visa: demo failed")
            })
            .unwrap_or("vISA Linux personality execution did not report success");
        format!("{case_id} 1 TFAIL : {detail}\n")
    }
}

pub fn ltp_visa_trace_from_serial(
    spec_id: &str,
    case_id: &str,
    binary_path: &str,
    raw_log_uri: &str,
    serial_log_uri: &str,
    serial_text: &str,
    runner_status: i32,
) -> serde_json::Value {
    let entered_visa_execution = serial_text.contains("== ring3 real ELF demo ==")
        || serial_text.contains("entering ring3 ELF demo")
        || serial_text.contains("visa: user ELF exited")
        || serial_text.contains("visa: demo completed");
    let hostcall_count = serial_text.matches("HostcallEntered").count() as u64;
    let linux_syscall_mentions = serial_text.matches("linux_syscall").count() as u64;
    let service_mentions = serial_text.matches("_service").count() as u64
        + serial_text.matches("vfs_service").count() as u64
        + serial_text.matches("futex_service").count() as u64
        + serial_text.matches("epoll_service").count() as u64;
    let service_dispatch_count = service_mentions.max(hostcall_count);
    let exit_status = parse_exit_status(serial_text).unwrap_or(runner_status);
    serde_json::json!({
        "schema_version": LTP_VISA_TRACE_SCHEMA_VERSION,
        "spec_id": spec_id,
        "case_id": case_id,
        "test_binary": binary_path,
        "runner": "visa-linux-personality",
        "entered_visa_execution": entered_visa_execution,
        "linux_personality_dispatch": linux_syscall_mentions > 0 || hostcall_count > 0,
        "syscalls_observed": hostcall_count.max(linux_syscall_mentions),
        "service_syscalls_observed": service_dispatch_count,
        "exit_status": exit_status,
        "runner_status": runner_status,
        "raw_log_uri": raw_log_uri,
        "serial_log_uri": serial_log_uri,
    })
}

fn parse_exit_status(serial_text: &str) -> Option<i32> {
    if serial_text.contains("visa: demo completed") {
        return Some(0);
    }
    let marker = "visa: user ELF exited with status ";
    serial_text.lines().find_map(|line| {
        let status = line.split_once(marker)?.1.trim();
        status.split_whitespace().next()?.parse().ok()
    })
}

fn normalize_ltp_status(token: &str) -> Option<Outcome> {
    let status = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()).to_ascii_uppercase();
    match status.as_str() {
        "PASS" | "TPASS" => Some(Outcome::Pass),
        "FAIL" | "TFAIL" | "BROK" | "TBROK" => Some(Outcome::Fail),
        "CONF" | "TCONF" | "NA" | "SKIP" | "TSKIP" => Some(Outcome::Skip),
        _ => None,
    }
}

fn strip_ansi_csi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}
