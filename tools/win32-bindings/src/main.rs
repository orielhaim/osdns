//! Regenerates `src/platform/windows/ffi/bindings.rs`.
//!
//! Run from the repository root:
//! `cargo run --manifest-path tools/win32-bindings/Cargo.toml`

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("tools/win32-bindings lives two levels under the repo root");
    let out = repo_root.join("src/platform/windows/ffi/bindings.rs");
    let filter_path = manifest_dir.join("filters.txt");

    std::fs::create_dir_all(out.parent().expect("bindings parent")).expect("create ffi dir");

    let filters = std::fs::read_to_string(&filter_path).expect("read filters.txt");
    let mut args: Vec<String> = vec![
        "--out".into(),
        out.to_string_lossy().into_owned(),
        "--flat".into(),
        "--sys".into(),
    ];
    for line in filters.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        args.push("--filter".into());
        args.push(line.to_string());
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    println!("generating {} ({} filters)", out.display(), arg_refs.len() / 2 - 2);
    windows_bindgen::bindgen(&arg_refs);
    rustfmt(&out);
    println!("wrote {}", out.display());
}

fn rustfmt(path: &Path) {
    let status = Command::new("rustfmt")
        .arg("--edition")
        .arg("2024")
        .arg(path)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: rustfmt exited with {status}"),
        Err(error) => eprintln!("warning: could not run rustfmt: {error}"),
    }
}
