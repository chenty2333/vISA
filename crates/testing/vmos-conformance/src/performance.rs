use std::{collections::BTreeMap, fs, path::Path};

use crate::{
    catalog::performance_catalog,
    hash::sha256_hex,
    types::{
        Boundary, ConformanceReport, EvidenceArtifact, EvidenceArtifactKind, Outcome,
        REPORT_SCHEMA_VERSION, TestResult, TestSpec,
    },
};

pub fn required_performance_metrics(spec_id: &str) -> &'static [&'static str] {
    match spec_id {
        "bench.hostcall.latency" => &["latency_ns"],
        "bench.activation.start" => &["latency_ns"],
        "bench.block.network" => &["block_iops", "network_packets_per_sec"],
        "bench.snapshot.restore" => &["latency_ns"],
        "bench.scheduler.preemption" => &["latency_ns"],
        "bench.simd.context" => &["latency_ns"],
        "bench.simd.speedup" => &["latency_ns"],
        "bench.display.framebuffer" => &["latency_ns"],
        _ => &[],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerformancePlanEntry {
    pub spec_id: String,
    pub benchmark_id: String,
    pub metric: String,
    pub estimate_path: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum CriterionMetricTransform {
    MeanNs,
    OpsPerSecond { ops_per_iter: f64 },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CriterionMetricSource {
    pub(crate) spec_id: &'static str,
    pub(crate) benchmark_id: &'static str,
    pub(crate) metric: &'static str,
    pub(crate) transform: CriterionMetricTransform,
}

pub(crate) const CRITERION_METRIC_SOURCES: &[CriterionMetricSource] = &[
    CriterionMetricSource {
        spec_id: "bench.hostcall.latency",
        benchmark_id: "hostcall_dispatch_latency",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.activation.start",
        benchmark_id: "artifact_load_activation_start",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.block.network",
        benchmark_id: "block_request_submit_mutation_64",
        metric: "block_iops",
        transform: CriterionMetricTransform::OpsPerSecond { ops_per_iter: 64.0 },
    },
    CriterionMetricSource {
        spec_id: "bench.block.network",
        benchmark_id: "network_adapter_record_mutation",
        metric: "network_packets_per_sec",
        transform: CriterionMetricTransform::OpsPerSecond { ops_per_iter: 1.0 },
    },
    CriterionMetricSource {
        spec_id: "bench.snapshot.restore",
        benchmark_id: "portable_snapshot_restore_latency",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.scheduler.preemption",
        benchmark_id: "preemption_latency_mutation",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.simd.context",
        benchmark_id: "simd_vector_state_record_mutation",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.simd.speedup",
        benchmark_id: "simd_speedup_mutation",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
    CriterionMetricSource {
        spec_id: "bench.display.framebuffer",
        benchmark_id: "display_record_mutation",
        metric: "latency_ns",
        transform: CriterionMetricTransform::MeanNs,
    },
];

pub fn criterion_performance_plan_entries(
    criterion_root: impl AsRef<Path>,
) -> Vec<PerformancePlanEntry> {
    let criterion_root = criterion_root.as_ref();
    CRITERION_METRIC_SOURCES
        .iter()
        .map(|source| PerformancePlanEntry {
            spec_id: source.spec_id.to_string(),
            benchmark_id: source.benchmark_id.to_string(),
            metric: source.metric.to_string(),
            estimate_path: criterion_estimate_path(criterion_root, source.benchmark_id)
                .display()
                .to_string(),
        })
        .collect()
}

pub fn criterion_performance_report_from_estimates_dir(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    criterion_root: impl AsRef<Path>,
) -> ConformanceReport {
    criterion_performance_report_from_estimates_dir_with_boundary(
        target,
        generated_by,
        Some(observed_boundary),
        observed_profile_override,
        criterion_root,
    )
}

pub fn criterion_performance_report_from_estimates_dir_with_boundary(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary_override: Option<Boundary>,
    observed_profile_override: Option<String>,
    criterion_root: impl AsRef<Path>,
) -> ConformanceReport {
    let criterion_root = criterion_root.as_ref();
    let results = performance_catalog()
        .into_iter()
        .map(|spec| {
            criterion_performance_result_for_spec(
                &spec,
                observed_boundary_override.unwrap_or(spec.minimum_boundary),
                observed_profile_override.clone().or_else(|| spec.required_profile.clone()),
                criterion_root,
            )
        })
        .collect();

    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-performance-benchmark".to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results,
    }
}

fn criterion_performance_result_for_spec(
    spec: &TestSpec,
    observed_boundary: Boundary,
    observed_profile: Option<String>,
    criterion_root: &Path,
) -> TestResult {
    let sources = criterion_sources_for_spec(&spec.id);
    let mut metrics = BTreeMap::new();
    let mut evidence_artifacts = Vec::new();
    let mut missing = Vec::new();
    let mut invalid = Vec::new();

    for source in &sources {
        match read_criterion_estimate(criterion_root, source.benchmark_id) {
            Ok(estimate) => {
                let value = match source.transform {
                    CriterionMetricTransform::MeanNs => estimate.mean_ns,
                    CriterionMetricTransform::OpsPerSecond { ops_per_iter } => {
                        ops_per_iter * 1_000_000_000.0 / estimate.mean_ns
                    }
                };
                if value.is_finite() && value >= 0.0 {
                    metrics.insert(source.metric.to_string(), value);
                    evidence_artifacts.push(estimate.artifact);
                } else {
                    invalid.push(source.benchmark_id);
                }
            }
            Err(CriterionEstimateError::Missing) => missing.push(source.benchmark_id),
            Err(CriterionEstimateError::Invalid(_)) => invalid.push(source.benchmark_id),
        }
    }

    let outcome = if invalid.is_empty() && missing.is_empty() {
        Outcome::Pass
    } else if metrics.is_empty() && invalid.is_empty() {
        Outcome::NotRun
    } else {
        Outcome::Fail
    };

    let evidence = match outcome {
        Outcome::Pass => {
            format!("Criterion estimates collected for {}", sources_for_display(&sources))
        }
        Outcome::Fail => format!(
            "Criterion estimates were incomplete for {}: missing=[{}] invalid=[{}]",
            spec.id,
            missing.join(","),
            invalid.join(",")
        ),
        Outcome::NotRun => {
            format!("Criterion estimates were not found for {}", sources_for_display(&sources))
        }
        Outcome::Skip => "Criterion benchmark was skipped".to_string(),
    };
    let remaining_uncertainty = match outcome {
        Outcome::Pass => {
            "Criterion estimates measure host-side benchmark runs; compare across targets only when runner environment and evidence boundary are recorded".to_string()
        }
        Outcome::Fail => {
            "benchmark report is partial or contains invalid Criterion estimates".to_string()
        }
        Outcome::NotRun => {
            "benchmark was not executed or Criterion output was not preserved".to_string()
        }
        Outcome::Skip => "benchmark skipped by runner configuration".to_string(),
    };

    TestResult {
        spec_id: spec.id.clone(),
        outcome,
        observed_boundary,
        observed_profile,
        evidence,
        remaining_uncertainty,
        metrics,
        evidence_artifacts,
    }
}

fn criterion_sources_for_spec(spec_id: &str) -> Vec<CriterionMetricSource> {
    CRITERION_METRIC_SOURCES.iter().copied().filter(|source| source.spec_id == spec_id).collect()
}

fn sources_for_display(sources: &[CriterionMetricSource]) -> String {
    sources.iter().map(|source| source.benchmark_id).collect::<Vec<_>>().join(",")
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CriterionEstimateError {
    Missing,
    Invalid(String),
}

struct CriterionEstimate {
    mean_ns: f64,
    artifact: EvidenceArtifact,
}

fn read_criterion_estimate(
    criterion_root: &Path,
    benchmark_id: &str,
) -> Result<CriterionEstimate, CriterionEstimateError> {
    let path = criterion_estimate_path(criterion_root, benchmark_id);
    let bytes = fs::read(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CriterionEstimateError::Missing
        } else {
            CriterionEstimateError::Invalid(format!("{}: {}", path.display(), error))
        }
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| CriterionEstimateError::Invalid(error.to_string()))?;
    let mean_ns = value
        .get("mean")
        .and_then(|mean| mean.get("point_estimate"))
        .and_then(serde_json::Value::as_f64)
        .filter(|mean_ns| mean_ns.is_finite() && *mean_ns > 0.0)
        .ok_or_else(|| {
            CriterionEstimateError::Invalid("missing mean.point_estimate".to_string())
        })?;
    Ok(CriterionEstimate {
        mean_ns,
        artifact: EvidenceArtifact {
            kind: EvidenceArtifactKind::BenchmarkRawOutput,
            uri: path.display().to_string(),
            sha256: sha256_hex(&bytes),
            description: format!("Criterion estimates for {benchmark_id}"),
        },
    })
}

fn criterion_estimate_path(criterion_root: &Path, benchmark_id: &str) -> std::path::PathBuf {
    criterion_root.join(benchmark_id).join("base").join("estimates.json")
}
