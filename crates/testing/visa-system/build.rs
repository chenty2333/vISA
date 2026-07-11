use std::{env, error::Error, fs, path::PathBuf};

use wit_component::ComponentEncoder;

mod build_provenance;

fn main() -> Result<(), Box<dyn Error>> {
    let guest_module = PathBuf::from(
        env::var_os("CARGO_CDYLIB_FILE_HANDOFF_COMPONENT_handoff_component")
            .expect("missing handoff-component artifact dependency"),
    );
    let module = fs::read(&guest_module)?;
    let component = ComponentEncoder::default().module(&module)?.validate(true).encode()?;

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR"))
        .join("handoff-component.component.wasm");
    fs::write(output, component)?;

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing manifest"));
    let workspace_root = manifest_dir
        .ancestors()
        .nth(3)
        .ok_or("visa-system is not nested under the workspace root")?;
    let provenance = build_provenance::collect(workspace_root)?;
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR"));
    fs::write(out_dir.join("build-source-manifest.json"), &provenance.source_manifest_json)?;
    fs::write(out_dir.join("build-toolchain.txt"), &provenance.toolchain_raw)?;

    println!("cargo:rerun-if-env-changed=CARGO_CDYLIB_FILE_HANDOFF_COMPONENT_handoff_component");
    println!("cargo:rerun-if-changed=../../../wit/cooperative-handoff/world.wit");
    // Individual paths make ordinary edits precise. Directory roots ensure a
    // newly added provenance input also invalidates this build script.
    for source_root in build_provenance::SOURCE_ROOTS {
        let source_root = workspace_root.join(source_root);
        if source_root.is_dir() {
            println!("cargo:rerun-if-changed={}", source_root.display());
        }
    }
    for source in provenance.source_paths {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    println!("cargo:rustc-env=VISA_BUILD_SOURCE_SHA256={}", provenance.source_digest);
    println!("cargo:rustc-env=VISA_BUILD_TOOLCHAIN_SHA256={}", provenance.toolchain_digest);
    Ok(())
}
