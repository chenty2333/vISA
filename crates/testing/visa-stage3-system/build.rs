use std::{env, error::Error, fs, path::PathBuf};

use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn Error>> {
    componentize(
        "CARGO_CDYLIB_FILE_STAGE3_FILE_COMPONENT_stage3_file_component",
        "stage3-file-component.component.wasm",
    )?;
    componentize(
        "CARGO_CDYLIB_FILE_STAGE3_REQUEST_COMPONENT_stage3_request_component",
        "stage3-request-component.component.wasm",
    )?;
    println!(
        "cargo:rerun-if-env-changed=CARGO_CDYLIB_FILE_STAGE3_FILE_COMPONENT_stage3_file_component"
    );
    println!(
        "cargo:rerun-if-env-changed=CARGO_CDYLIB_FILE_STAGE3_REQUEST_COMPONENT_stage3_request_component"
    );
    println!("cargo:rerun-if-changed=../../../wit/regular-file-continuity/world.wit");
    println!("cargo:rerun-if-changed=../../../wit/logical-request-continuity/world.wit");
    Ok(())
}

fn componentize(variable: &str, output_name: &str) -> Result<(), Box<dyn Error>> {
    let guest = PathBuf::from(env::var_os(variable).ok_or("missing guest artifact dependency")?);
    let module = fs::read(guest)?;
    let component = ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join(output_name);
    fs::write(output, component)?;
    Ok(())
}
