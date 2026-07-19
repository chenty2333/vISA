use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use visa_ownershipd::{ExitClass, run_from_digest_pinned_config};

const USAGE: &str =
    "usage: visa-ownershipd --bootstrap ABSOLUTE_PATH --bootstrap-sha256 LOWERCASE_SHA256";

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    bootstrap: PathBuf,
    bootstrap_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseOutcome {
    Help,
    Version,
}

fn main() -> ExitCode {
    match parse_arguments(std::env::args_os()) {
        Ok(arguments) => {
            match run_from_digest_pinned_config(arguments.bootstrap, &arguments.bootstrap_sha256) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("visa-ownershipd: {error}");
                    ExitCode::from(error.exit_class().code())
                }
            }
        }
        Err(Ok(ParseOutcome::Help)) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(Ok(ParseOutcome::Version)) => {
            println!("visa-ownershipd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Err(Err(message)) => {
            eprintln!("visa-ownershipd: {message}\n{USAGE}");
            ExitCode::from(ExitClass::Usage.code())
        }
    }
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, Result<ParseOutcome, &'static str>> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut bootstrap = None;
    let mut bootstrap_sha256 = None;

    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--bootstrap") if bootstrap.is_none() => {
                bootstrap = Some(PathBuf::from(
                    arguments.next().ok_or(Err("--bootstrap requires one path"))?,
                ));
            }
            Some("--bootstrap-sha256") if bootstrap_sha256.is_none() => {
                let value =
                    arguments.next().ok_or(Err("--bootstrap-sha256 requires one digest"))?;
                bootstrap_sha256 =
                    Some(value.into_string().map_err(|_| Err("bootstrap SHA-256 must be UTF-8"))?);
            }
            Some("--help" | "-h") if bootstrap.is_none() && bootstrap_sha256.is_none() => {
                if arguments.next().is_none() {
                    return Err(Ok(ParseOutcome::Help));
                }
                return Err(Err("--help does not accept other arguments"));
            }
            Some("--version") if bootstrap.is_none() && bootstrap_sha256.is_none() => {
                if arguments.next().is_none() {
                    return Err(Ok(ParseOutcome::Version));
                }
                return Err(Err("--version does not accept other arguments"));
            }
            Some("--bootstrap" | "--bootstrap-sha256") => {
                return Err(Err("each option must be provided exactly once"));
            }
            _ => return Err(Err("unknown or non-UTF-8 option")),
        }
    }

    let bootstrap = bootstrap.ok_or(Err("missing --bootstrap"))?;
    if !bootstrap.is_absolute() {
        return Err(Err("--bootstrap must be an absolute path"));
    }
    let bootstrap_sha256 = bootstrap_sha256.ok_or(Err("missing --bootstrap-sha256"))?;
    Ok(Arguments { bootstrap, bootstrap_sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args<'a>(values: &'a [&'a str]) -> impl Iterator<Item = OsString> + 'a {
        values.iter().map(OsString::from)
    }

    #[test]
    fn accepts_only_the_two_exact_launch_inputs() {
        let parsed = parse_arguments(args(&[
            "visa-ownershipd",
            "--bootstrap-sha256",
            &"a".repeat(64),
            "--bootstrap",
            "/run/user/1000/visa/ownershipd.json",
        ]))
        .expect("parse arguments");
        assert_eq!(
            parsed,
            Arguments {
                bootstrap: PathBuf::from("/run/user/1000/visa/ownershipd.json"),
                bootstrap_sha256: "a".repeat(64),
            }
        );
    }

    #[test]
    fn rejects_relative_missing_repeated_and_unknown_inputs() {
        assert!(parse_arguments(args(&["visa-ownershipd"])).is_err());
        assert!(
            parse_arguments(args(&[
                "visa-ownershipd",
                "--bootstrap",
                "relative.json",
                "--bootstrap-sha256",
                &"a".repeat(64),
            ]))
            .is_err()
        );
        assert!(
            parse_arguments(args(&[
                "visa-ownershipd",
                "--bootstrap",
                "/one",
                "--bootstrap",
                "/two",
                "--bootstrap-sha256",
                &"a".repeat(64),
            ]))
            .is_err()
        );
        assert!(parse_arguments(args(&["visa-ownershipd", "--ambient-env-config"])).is_err());
    }
}
