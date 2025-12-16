use std::process::Command;
use std::path::Path;

fn main() {
    let circuits_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("circuits");
    
    println!("cargo:rerun-if-changed={}", circuits_dir.display());
    
    // Compile Noir circuits if nargo is available
    if which_nargo().is_some() {
        println!("cargo:warning=Compiling Noir circuits...");
        
        let status = Command::new("nargo")
            .arg("compile")
            .current_dir(&circuits_dir)
            .status();
        
        match status {
            Ok(s) if s.success() => {
                println!("cargo:warning=Noir circuits compiled successfully");
            }
            Ok(s) => {
                println!("cargo:warning=nargo compile failed with status: {}", s);
            }
            Err(e) => {
                println!("cargo:warning=Failed to run nargo: {}", e);
            }
        }
    } else {
        println!("cargo:warning=nargo not found, skipping circuit compilation");
    }
}

fn which_nargo() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .filter_map(|dir| {
                    let full_path = dir.join("nargo");
                    if full_path.is_file() {
                        Some(full_path)
                    } else {
                        None
                    }
                })
                .next()
        })
}
