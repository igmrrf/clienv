use clap::Parser;
use anyhow::{Context, Result};
use std::io::{self, Write};
mod lib;

// / Search for a pattern in a file and display the lines that contain it
#[derive(Parser)]
struct Cli {
    /// The pattern to look for
    pattern: String,
    /// The path to the file to read
    path: std::path::PathBuf,
}


fn main() -> Result<()> {
    let args = Cli::parse();

    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("could  not read file `{}`", args.path.display()))?;
    lib::find_matches(&content, &args.pattern, &mut std::io::stdout());
    Ok(())
}


// fn progress(){
//     let pb = indicatif::ProgressBar::new(100);
//     for i in 0..100{
//         log();
//         pb.println(format!("[+] finished #{}", i));
//         pb.inc(1);
//     }
//
//     pb.finish_with_message("done");
// }
