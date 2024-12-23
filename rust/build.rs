// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::process::{Command, Stdio};

use lib_flutter_rust_bridge_codegen::codegen;
use lib_flutter_rust_bridge_codegen::codegen::Config;

fn main() {
    println!("cargo:rerun-if-changed=src/api");

    if !is_dart_installed() {
        panic!("Warning: dart not installed.");
    }

    if !is_flutter_installed() {
        panic!("Warning: flutter not installed.");
    }

    // Execute code generator with auto-detected config
    codegen::generate(
        Config::from_config_file("../flutter_rust_bridge.yaml")
            .unwrap()
            .unwrap(),
        Default::default(),
    )
    .unwrap();
}

fn is_dart_installed() -> bool {
    let output = Command::new("dart")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(output, Ok(status) if status.success())
}

fn is_flutter_installed() -> bool {
    let output = Command::new("flutter")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(output, Ok(status) if status.success())
}
