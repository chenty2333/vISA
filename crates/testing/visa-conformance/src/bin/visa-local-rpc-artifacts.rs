use std::{env, path::PathBuf, process::ExitCode};

use visa_conformance::local_rpc::{
    LOCAL_RPC_INDEX_PATH, verify_checked_in_golden_corpora, verify_checked_in_local_rpc_index,
    verify_checked_in_owned_schemas, write_golden_corpora, write_local_rpc_index,
    write_owned_schemas,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("visa-local-rpc-artifacts: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut write = false;
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.pop();

    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--write" => write = true,
            "--check" => write = false,
            "--root" => {
                root = PathBuf::from(arguments.next().ok_or("--root requires a path")?);
            }
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }

    if write {
        for artifact in write_owned_schemas(&root)? {
            println!("{}  {}  {}", artifact.sha256, artifact.artifact_id, artifact.path);
        }
        for corpus in write_golden_corpora(&root)? {
            println!("{}  {}  {}", corpus.sha256, corpus.corpus_id, corpus.path);
        }
        let index = write_local_rpc_index(&root)?;
        println!("{}  visa.local-rpc-artifact-index.v1  {}", index.sha256, LOCAL_RPC_INDEX_PATH);
    } else {
        verify_checked_in_owned_schemas(&root)?;
        verify_checked_in_golden_corpora(&root)?;
        verify_checked_in_local_rpc_index(&root)?;
        println!("local RPC owned-schema and golden-corpus artifacts are canonical and current");
    }
    Ok(())
}
