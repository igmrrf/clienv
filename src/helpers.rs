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
            writeln!(writer, "{}", line).unwrap();
        }
    }
}

pub fn log() -> Result<(), Box<dyn Error>> {
    // env_logger::init();
    info!("Starting up");
    warn!("oops, nothing implemented!");
    // Assuming you have a file as src/bin/output-log.rs, on unix based systems
    // run `env RUST_LOG=info cargo run --bin output-log`

    let stdout = io::stdout(); // get the global stdout entity
    let mut handle = io::BufWriter::new(stdout); // optional: wrap that handle in a buffer
    writeln!(handle, "foo: {}", 42)?; // add `?` if you care about errors here
    Ok(())
}

pub fn search_file(path: &PathBuf, pattern: &str) {
    // pub fn search_file(path: PathBuf, pattern: &str) -> Result<()> {
    // let content =
    //     read_to_string(path).with_context(|| format!("could  not read file `{}`", path.display()));
    // match content {
    //     Ok(content) => helpers::find_matches(&content, name, &mut std::io::stdout()),
    //
    //     Err(e) => eprintln!("Erro getting current directory: {} ", e),
    // }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("could  not read file `{}`", &path.display()))
        .unwrap();
    find_matches(&content, pattern, &mut std::io::stdout());
    // Ok(())
}
