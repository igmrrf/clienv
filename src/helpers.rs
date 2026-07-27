use anyhow::{Context, Result};
use log::{info, warn};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
};

fn find_matches(content: &str, pattern: &str, mut writer: impl std::io::Write) {
    for line in content.lines() {
        if line.contains(pattern) {
            let _ = writeln!(writer, "{}", line);
        }
    }
}

#[allow(dead_code)]
pub fn log() -> Result<(), Box<dyn Error>> {
    info!("Starting up");
    warn!("oops, nothing implemented!");

    let stdout = io::stdout();
    let mut handle = io::BufWriter::new(stdout);
    writeln!(handle, "foo: {}", 42)?;
    Ok(())
}

pub fn search_file(path: &PathBuf, pattern: &str) {
    match std::fs::read_to_string(path)
        .with_context(|| format!("could not read file `{}`", path.display()))
    {
        Ok(content) => find_matches(&content, pattern, &mut std::io::stdout()),
        Err(e) => {
            eprintln!("Error searching file: {:#}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[path = "helpers_test.rs"]
mod helpers_test;
