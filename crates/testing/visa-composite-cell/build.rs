use std::{env, error::Error, fs, path::PathBuf};

use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn Error>> {
    let guest = PathBuf::from(
        env::var_os("CARGO_CDYLIB_FILE_COMPOSITE_COMPONENT_composite_component")
            .ok_or("missing guest artifact dependency")?,
    );
    let module = fs::read(guest)?;
    let component = ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?)
        .join("composite-component.component.wasm");
    fs::write(output, component)?;
    println!(
        "cargo:rerun-if-env-changed=CARGO_CDYLIB_FILE_COMPOSITE_COMPONENT_composite_component"
    );
    println!("cargo:rerun-if-changed=../../../wit/composite-continuity/world.wit");
    Ok(())
}
