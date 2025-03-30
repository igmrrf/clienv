use clap::{Parser, Subcommand};
use config::get_config;
use std::{env, path::PathBuf};
mod config;
mod helpers;
mod manager;
// target/debug/clienv log get mongo
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional name to operate on
    name: Option<String>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    path: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// does testing things
    Get {
        /// name to operate on
        name: String,
    },

    /// does testing things
    Search {
        /// name to operate on
        name: String,

        #[arg(short, long, value_name = "FILE")]
        path: PathBuf,
    },

    /// does testing things
    Set {
        /// name to operate on
        name: String,
        /// value to operate on
        value: String,
    },
}

pub fn get_env_variable(key: &str) {
    let conf = get_config();
    match manager::get_env_variable(key, &conf.encryption_key) {
        Some(value) => println!("{}: {}", key, value),
        None => println!("environment variable not found"),
    }
}

pub fn set_env_variable(key: &str, value: &str) {
    let conf = get_config();
    manager::set_env_variable(key, value, &conf.encryption_key);
    println!("environment variable set successfully")
}

fn main() {
    let cli = Cli::parse();
    println!("{:?}", cli);

    // You can check the value provided by positional arguments, or option arguments
    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {name}");
    }

    if let Some(config_path) = cli.config.as_deref() {
        println!("Value for config: {}", config_path.display());
    }

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Some(Commands::Set { name, value }) => {
            println!("setting {} to {}", name, value);

            set_env_variable(name, value);
            if name == "mongo" {
                println!("Printing getting mongo ...");
            } else {
                println!("printing unknown ...");
            }
        }

        Some(Commands::Get { name }) => {
            get_env_variable(name);
            println!("{}", name);
        }

        Some(Commands::Search { name, path }) => {
            let cur_path = match env::current_dir() {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Erro getting current directory: {} ", e);
                    PathBuf::from("/")
                }
            };
            // get env files and find contents and show accordingly;

            println!("Current working directory: {}", cur_path.display());

            println!("Search for {}, within {}", name, path.display());
            helpers::search_file(path, name)
        }
        None => {
            let cur_path = match env::current_dir() {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Erro getting current directory: {} ", e);
                    PathBuf::from("/")
                }
            };
            println!("Current working directory: {}", cur_path.display());
        }
    }
}
