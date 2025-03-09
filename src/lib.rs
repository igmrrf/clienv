use anyhow::Result;
use log::{info, warn};
use std::io::{self, Write};

// TODO: add error handling
pub fn find_matches(content: &str, pattern: &str,  mut writer: impl std::io::Write){
    for line in content.lines(){
        if line.contains(pattern){
            writeln!(writer, "{}", line);
        }
    }
}

pub fn log()-> Result<(), Box<dyn std::error::Error>>{
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

pub fn answer()->i32{
    42
}

