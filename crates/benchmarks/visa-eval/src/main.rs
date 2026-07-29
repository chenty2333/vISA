//! Command-line driver for the continuity performance harness.
//!
//! The argument parser is written by hand: this crate is measurement code and
//! adding a parser dependency would put a version of it into the workspace
//! lock for no benefit.

use std::{path::PathBuf, process::ExitCode};

use serde_json::json;
use visa_eval::{
    EvalOptions, Measure, behavior, digest_spike, evidence,
    output::{
        SampleSink, ensure_measurement_preconditions, is_memory_backed_path, write_completion,
        write_meta,
    },
    phases, restart, snapshot_size, steady_state,
};

const USAGE: &str = "\
usage: visa-eval <subcommand> [options]

subcommands:
  steady-state       one durable effect against a same-SQLite baseline
  handoff-phases     per-phase timing of one composite handoff
  snapshot-size      portable snapshot size, field by field
  restart-baseline   journal replay against a lossy read-the-last-value restart
  digest-cost        full-state replay cost versus an independent Merkle prototype
  evidence-overhead  raw-observation oracle and production outer-gate cost
  behavior-defects   independent feature-gated behavior-injection driver
  all                every production measurement above, in that order
  paper              production measurements plus evidence-overhead

options:
  --out <dir>                    output directory (default target/visa-eval)
  --iters <n>                    iterations per run for steady-state
  --warmup <n>                   discarded iterations before the first sample
  --runs <n>                     independent runs per measure
  --effects-before-handoff <n>[,<n>...]
                                 effect counts used as the independent variable
  --digest-operations <n>[,<n>...]
                                 operation counts used by digest-cost
  --evidence-root <dir>          accepted Stage 3A cross-runtime artifact root
  --paper-grade                  require clean SHA, release build, >=10 runs, and fresh output
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("visa-eval failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let Some(subcommand) = arguments.next() else {
        eprint!("{USAGE}");
        return Err("missing subcommand".to_owned());
    };
    if matches!(subcommand.as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(());
    }
    let measures = measures_for(&subcommand)?;
    let options = parse_options(arguments)?;

    if subcommand == "behavior-defects" {
        std::fs::create_dir_all(&options.out)
            .map_err(|error| format!("cannot create {}: {error}", options.out.display()))?;
        behavior::run(&options)?;
        return Ok(());
    }

    let evidence_input = measures
        .contains(&Measure::EvidenceOverhead)
        .then(|| evidence::preflight(&options))
        .transpose()?;
    ensure_measurement_preconditions(
        &options.out,
        options.paper_grade,
        options.runs,
        options.iters,
        options.warmup,
    )?;
    std::fs::create_dir_all(&options.out)
        .map_err(|error| format!("cannot create {}: {error}", options.out.display()))?;
    if is_memory_backed_path(&options.out) {
        eprintln!(
            "warning: {} is on a memory-backed filesystem; fsync costs are not real \
             and the durability numbers below must not be published as disk figures",
            options.out.display()
        );
    }

    let meta = write_meta(
        &options.out,
        json!({
            "subcommand": subcommand,
            "measures": measures.iter().map(|measure| measure.label()).collect::<Vec<_>>(),
            "iters": options.iters,
            "warmup": options.warmup,
            "runs": options.runs,
            "effects_before_handoff": options.effects_before_handoff,
            "digest_operations": options.digest_operations,
            "evidence_root": options.evidence_root,
            "evidence_input": evidence_input,
            "paper_grade": options.paper_grade,
            "ordering": {
                "effect_configurations": "counterbalanced six-permutation catalog across runs",
                "steady_state": "key-value arm fixed first; timer and SQLite baselines alternate by run",
                "evidence": "declared-digest control, independent raw oracle, and production outer-gate arms counterbalanced by run and iteration",
            },
        }),
    )?;

    let mut sink = SampleSink::open(&options.out)?;
    for measure in &measures {
        println!("running {} ...", measure.label());
        match measure {
            Measure::SteadyState => steady_state::run(&options, &mut sink)?,
            Measure::HandoffPhases => phases::run(&options, &mut sink)?,
            Measure::SnapshotSize => snapshot_size::run(&options, &mut sink)?,
            Measure::RestartBaseline => restart::run(&options, &mut sink)?,
            Measure::DigestCost => digest_spike::run(&options, &mut sink)?,
            Measure::EvidenceOverhead => evidence::run(&options, &mut sink)?,
        }
        sink.flush()?;
    }
    sink.flush()?;
    let completion =
        options.paper_grade.then(|| write_completion(&options.out, sink.written())).transpose()?;

    println!("\nsamples: {} ({})", sink.written(), sink.path().display());
    println!("meta:    {}", meta.display());
    if let Some(completion) = completion {
        println!("complete: {}", completion.display());
    }
    println!("\n{}", sink.report());
    Ok(())
}

fn measures_for(subcommand: &str) -> Result<Vec<Measure>, String> {
    match subcommand {
        "steady-state" => Ok(vec![Measure::SteadyState]),
        "handoff-phases" => Ok(vec![Measure::HandoffPhases]),
        "snapshot-size" => Ok(vec![Measure::SnapshotSize]),
        "restart-baseline" => Ok(vec![Measure::RestartBaseline]),
        "digest-cost" => Ok(vec![Measure::DigestCost]),
        "evidence-overhead" => Ok(vec![Measure::EvidenceOverhead]),
        "all" => Ok(Measure::all().to_vec()),
        "paper" => Ok(vec![
            Measure::SteadyState,
            Measure::HandoffPhases,
            Measure::SnapshotSize,
            Measure::RestartBaseline,
            Measure::EvidenceOverhead,
        ]),
        "behavior-defects" => Ok(Vec::new()),
        other => {
            eprint!("{USAGE}");
            Err(format!("unknown subcommand {other}"))
        }
    }
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<EvalOptions, String> {
    let mut options = EvalOptions::default();
    let mut arguments = arguments;
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--out" => options.out = PathBuf::from(next_value(&mut arguments, &flag)?),
            "--iters" => options.iters = parse_number(&next_value(&mut arguments, &flag)?, &flag)?,
            "--warmup" => {
                options.warmup = parse_number(&next_value(&mut arguments, &flag)?, &flag)?;
            }
            "--runs" => {
                let runs = parse_number(&next_value(&mut arguments, &flag)?, &flag)?;
                options.runs =
                    u32::try_from(runs).map_err(|_| format!("{flag} value is out of range"))?;
            }
            "--effects-before-handoff" => {
                let raw = next_value(&mut arguments, &flag)?;
                options.effects_before_handoff = raw
                    .split(',')
                    .map(|part| parse_number(part.trim(), &flag))
                    .collect::<Result<Vec<_>, _>>()?;
                if options.effects_before_handoff.is_empty() {
                    return Err(format!("{flag} needs at least one count"));
                }
            }
            "--digest-operations" => {
                let raw = next_value(&mut arguments, &flag)?;
                options.digest_operations = raw
                    .split(',')
                    .map(|part| parse_number(part.trim(), &flag))
                    .collect::<Result<Vec<_>, _>>()?;
                if options.digest_operations.is_empty() || options.digest_operations.contains(&0) {
                    return Err(format!("{flag} needs positive operation counts"));
                }
            }
            "--evidence-root" => {
                options.evidence_root = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "--paper-grade" => options.paper_grade = true,
            other => {
                eprint!("{USAGE}");
                return Err(format!("unknown option {other}"));
            }
        }
    }
    if options.runs == 0 {
        return Err("--runs must be at least 1".to_owned());
    }
    Ok(options)
}

fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments.next().ok_or_else(|| format!("{flag} expects a value"))
}

fn parse_number(raw: &str, flag: &str) -> Result<u64, String> {
    raw.parse::<u64>().map_err(|_| format!("{flag} expects a non-negative integer, got {raw}"))
}
