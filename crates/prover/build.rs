use std::process::Command;
use std::path::Path;
use std::fs;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let circuits_bin_dir = workspace_root.join("circuits-bin").join("transfer");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);
    
    println!("cargo:rerun-if-changed={}", circuits_bin_dir.display());
    println!("cargo:rerun-if-changed={}", circuits_bin_dir.join("src").join("main.nr").display());
    println!("cargo:rerun-if-changed={}", circuits_bin_dir.join("Nargo.toml").display());
    
    if which_nargo().is_none() {
        println!("cargo:warning=nargo not found, skipping circuit compilation");
        return;
    }
    
    println!("cargo:warning=Compiling transfer circuit...");
    
    let status = Command::new("nargo")
        .arg("compile")
        .current_dir(&circuits_bin_dir)
        .status();
    
    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=Transfer circuit compiled successfully");
        }
        Ok(s) => {
            println!("cargo:warning=nargo compile failed with status: {}", s);
            return;
        }
        Err(e) => {
            println!("cargo:warning=Failed to run nargo: {}", e);
            return;
        }
    }
    
    let artifact_src = circuits_bin_dir.join("target").join("transfer.json");
    let artifact_dst = out_path.join("transfer.json");
    
    if artifact_src.exists() {
        if let Err(e) = fs::copy(&artifact_src, &artifact_dst) {
            println!("cargo:warning=Failed to copy ACIR artifact: {}", e);
            return;
        }
        println!("cargo:warning=Copied ACIR artifact to {}", artifact_dst.display());
        println!("cargo:rustc-env=TRANSFER_CIRCUIT_PATH={}", artifact_dst.display());
    } else {
        println!("cargo:warning=ACIR artifact not found at {}", artifact_src.display());
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
