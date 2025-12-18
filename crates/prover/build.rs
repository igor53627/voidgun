use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let circuits_bin_dir = workspace_root.join("circuits-bin");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // Watch both circuit directories
    let transfer_dir = circuits_bin_dir.join("transfer");
    let withdrawal_dir = circuits_bin_dir.join("withdrawal");

    println!("cargo:rerun-if-changed={}", transfer_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        transfer_dir.join("src").join("main.nr").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        transfer_dir.join("Nargo.toml").display()
    );
    println!("cargo:rerun-if-changed={}", withdrawal_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        withdrawal_dir.join("src").join("main.nr").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        withdrawal_dir.join("Nargo.toml").display()
    );

    if which_nargo().is_none() {
        println!("cargo:warning=nargo not found, skipping circuit compilation");
        set_dummy_circuit_paths();
        return;
    }

    // Compile transfer circuit
    println!("cargo:warning=Compiling transfer circuit...");
    let transfer_ok = compile_circuit(&transfer_dir, "transfer", out_path);

    // Compile withdrawal circuit if it exists
    let withdrawal_ok = if withdrawal_dir.exists() {
        println!("cargo:warning=Compiling withdrawal circuit...");
        compile_circuit(&withdrawal_dir, "withdrawal", out_path)
    } else {
        println!("cargo:warning=Withdrawal circuit not found, skipping");
        false
    };

    if !transfer_ok {
        println!("cargo:rustc-env=TRANSFER_CIRCUIT_PATH=/dev/null");
    }
    if !withdrawal_ok {
        println!("cargo:rustc-env=WITHDRAWAL_CIRCUIT_PATH=/dev/null");
    }
}

fn compile_circuit(circuit_dir: &Path, name: &str, out_path: &Path) -> bool {
    let status = Command::new("nargo")
        .arg("compile")
        .current_dir(circuit_dir)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning={} circuit compiled successfully", name);
        }
        Ok(s) => {
            println!(
                "cargo:warning=nargo compile failed for {} with status: {}",
                name, s
            );
            return false;
        }
        Err(e) => {
            println!("cargo:warning=Failed to run nargo for {}: {}", name, e);
            return false;
        }
    }

    let artifact_src = circuit_dir.join("target").join(format!("{}.json", name));
    let artifact_dst = out_path.join(format!("{}.json", name));

    if artifact_src.exists() {
        if let Err(e) = fs::copy(&artifact_src, &artifact_dst) {
            println!("cargo:warning=Failed to copy {} ACIR artifact: {}", name, e);
            return false;
        }
        println!(
            "cargo:warning=Copied {} ACIR artifact to {}",
            name,
            artifact_dst.display()
        );
        let env_var = format!("{}_CIRCUIT_PATH", name.to_uppercase());
        println!("cargo:rustc-env={}={}", env_var, artifact_dst.display());
        true
    } else {
        println!(
            "cargo:warning={} ACIR artifact not found at {}",
            name,
            artifact_src.display()
        );
        false
    }
}

fn set_dummy_circuit_paths() {
    println!("cargo:rustc-env=TRANSFER_CIRCUIT_PATH=/dev/null");
    println!("cargo:rustc-env=WITHDRAWAL_CIRCUIT_PATH=/dev/null");
}

fn which_nargo() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
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
