use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;

mod bip39_words;
mod config;
mod env_file;
mod helpers;
mod manager;
mod network_config;
mod project_config;
mod secrets;
mod wallet;

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod manager_test;

#[derive(Parser, Debug)]
#[command(
    name = "bsec",
    version,
    about = "Decentralized, secure secret management and environment variable CLI tool",
    long_about = "bsec is a CLI tool for secure environment variable management, schema validation, format conversion, and ephemeral secret sharing."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new wallet or import an existing one
    Init {
        /// Optional User ID or machine identifier
        user_id: Option<String>,

        /// Import wallet from mnemonic phrase
        #[arg(long)]
        import_mnemonic: Option<String>,

        /// Add password protection to wallet
        #[arg(long)]
        password: Option<String>,

        /// Overwrite existing wallet if it exists
        #[arg(short, long)]
        overwrite: bool,
    },

    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        sub: WalletCommands,
    },

    /// Configure network and storage settings
    Config {
        /// Set blockchain network (ethereum, polygon, goerli, mumbai)
        #[arg(long)]
        network: Option<String>,

        /// Set custom RPC endpoint URL
        #[arg(long)]
        rpc: Option<String>,

        /// Set IPFS gateway URL
        #[arg(long)]
        ipfs_gateway: Option<String>,

        /// Set IPFS pinning service
        #[arg(long)]
        ipfs_pinning: Option<String>,

        /// Show current configuration
        #[arg(long)]
        show: bool,
    },

    /// Share a secret securely
    Share {
        /// Positional secret text content
        secret: Option<String>,

        /// Secret text content to share
        #[arg(long)]
        content: Option<String>,

        /// Path to text file containing the secret
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Time-to-live (e.g. 1m, 2h, 1d, 7d)
        #[arg(short, long, default_value = "24h")]
        ttl: String,

        /// Maximum number of reads before auto-destruction
        #[arg(short = 'm', long = "max-reads", default_value = "1")]
        max_reads: u32,

        /// Recipient wallet address or user ID
        #[arg(short = 'u', long = "to")]
        to: Option<String>,

        /// Password to unlock wallet if required
        #[arg(short, long)]
        password: Option<String>,
    },

    /// View a shared secret
    View {
        /// Secret ID to view
        secret_id: String,

        /// Save decrypted content to output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Password to unlock wallet if required
        #[arg(short, long)]
        password: Option<String>,
    },

    /// List active or expired secrets
    List {
        /// Filter by specific recipient/user address
        #[arg(short, long)]
        user: Option<String>,

        /// List all secrets across users
        #[arg(short = 'a', long)]
        all_users: bool,

        /// List all secrets
        #[arg(long)]
        all: bool,

        /// List expired secrets only
        #[arg(long)]
        expired: bool,

        /// List active secrets only
        #[arg(long)]
        active: bool,

        /// Password to unlock wallet if required
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Revoke access to a shared secret
    Revoke {
        /// Secret ID to revoke
        secret_id: String,

        /// Password to unlock wallet if required
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Hide shared secret(s)
    Hide {
        /// Secret ID to hide
        secret_id: Option<String>,

        /// Hide secrets for a specific user
        #[arg(short, long)]
        user: Option<String>,

        /// Hide all secrets
        #[arg(long)]
        all: bool,

        /// Password to unlock wallet if required
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Convert between environment file formats (JSON, YAML, .env)
    Convert {
        /// Input file path
        input_file: Option<PathBuf>,

        /// Output file path
        output_file: Option<PathBuf>,

        /// Input file option
        #[arg(long)]
        file: Option<PathBuf>,

        /// Output file option
        #[arg(long)]
        out: Option<PathBuf>,

        /// Output format (env, json, yaml)
        #[arg(long, default_value = "env")]
        format: String,

        /// Environment variable prefix
        #[arg(long)]
        prefix: Option<String>,

        /// Environment variable suffix
        #[arg(long)]
        suffix: Option<String>,

        /// Embed as JavaScript object properties with specified prefix
        #[arg(long)]
        embed: Option<String>,
    },

    /// Validate environment files against a schema file
    Validate {
        /// Path to .env file
        #[arg(short, long, default_value = ".env.local")]
        env: PathBuf,

        /// Path to schema file
        #[arg(short, long, default_value = ".env.schema")]
        schema: PathBuf,
    },

    /// Generate templates or samples from environment files
    Generate {
        /// Input .env file path
        #[arg(short, long, default_value = ".env")]
        env: PathBuf,

        /// Output template file path
        #[arg(short, long, default_value = ".env.template")]
        out: PathBuf,
    },

    /// Encrypt environment files (.env)
    Encrypt {
        /// Input .env file to encrypt
        file: PathBuf,

        /// Output encrypted file path
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Decrypt encrypted environment files (.env.enc)
    Decrypt {
        /// Input encrypted file to decrypt
        file: PathBuf,

        /// Output decrypted file path
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Run a command with injected environment variables or shared secret
    Run {
        /// Path to environment file (.env, .env.local, .json, .env.enc)
        #[arg(short, long)]
        env: Option<PathBuf>,

        /// Shared Secret ID to inject
        #[arg(short, long)]
        secret: Option<String>,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Display value of specific environment variable
    Log {
        /// Environment variable key name
        env_name: String,

        /// Target file path
        #[arg(short, long, default_value = ".env.local")]
        file: PathBuf,
    },

    /// Legacy / simple get command
    Get {
        /// Key name to retrieve
        name: String,
    },

    /// Legacy / simple set command
    Set {
        /// Key name to set
        name: String,
        /// Value to assign
        value: String,
    },

    /// Search for pattern in a file
    Search {
        /// Pattern to search for
        name: String,

        /// Path to file
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCommands {
    /// Display wallet information
    Info {
        /// Password if wallet is encrypted
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn print_banner() {
    println!("╔═══════════════════════════════════════╗");
    println!("║                                       ║");
    println!("║                 BSEC                  ║");
    println!("║  Blockchain-based Secret Management   ║");
    println!("║                                       ║");
    println!("╚═══════════════════════════════════════╝");
}

fn get_password_or_prompt(provided: Option<String>, prompt_msg: &str) -> Option<String> {
    if provided.is_some() {
        provided
    } else if std::io::stdin().is_terminal() {
        eprint!("{}", prompt_msg);
        rpassword::read_password().ok().filter(|p| !p.is_empty())
    } else {
        None
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init {
            user_id,
            import_mnemonic,
            password,
            overwrite,
        }) => {
            print_banner();
            let pwd = get_password_or_prompt(password, "Set wallet encryption password (optional): ");
            match wallet::init_wallet(import_mnemonic, pwd, user_id, overwrite) {
                Ok(info) => {
                    println!("Wallet initialized successfully!");
                    println!("Address: {}", info.address);
                    println!("Public Key: {}", info.public_key);
                    println!("\nIMPORTANT: Please write down your mnemonic phrase and keep it safe:");
                    println!("{}", info.mnemonic);
                }
                Err(e) => eprintln!("Error initializing wallet: {}", e),
            }
        }

        Some(Commands::Wallet {
            sub: WalletCommands::Info { password },
        }) => {
            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(info) => {
                    println!("Wallet Information:");
                    println!("-------------------");
                    println!("Address: {}", info.address);
                    println!("Public Key: {}", info.public_key);
                    if let Some(ref uid) = info.user_id {
                        println!("User ID: {}", uid);
                    }
                    println!("Created: {}", info.created_at);
                    println!("Last Accessed: {}", info.last_accessed);
                }
                Err(e) => eprintln!("Error getting wallet info: {}", e),
            }
        }

        Some(Commands::Config {
            network,
            rpc,
            ipfs_gateway,
            ipfs_pinning,
            show,
        }) => {
            if show {
                let conf = network_config::load_network_config();
                println!("Current Configuration:");
                println!("-------------------");
                println!("Network: {}", conf.network);
                println!("Chain ID: {}", conf.chain_id);
                println!("RPC URL: {}", conf.rpc_url);
                println!("IPFS Gateway: {}", conf.ipfs.gateway);
                println!(
                    "IPFS Pinning Service: {}",
                    conf.ipfs.pinning_service.as_deref().unwrap_or("None")
                );
            } else {
                match network_config::update_network_config(network, rpc, ipfs_gateway, ipfs_pinning) {
                    Ok(conf) => println!("Configuration updated: Network = {}", conf.network),
                    Err(e) => eprintln!("Error updating config: {}", e),
                }
            }
        }

        Some(Commands::Share {
            secret,
            content,
            file,
            ttl,
            max_reads,
            to,
            password,
        }) => {
            let secret_content = if let Some(c) = content {
                c
            } else if let Some(ref path) = file {
                match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                        return;
                    }
                }
            } else if let Some(s) = secret {
                s
            } else {
                eprintln!("Error: Content to share is required. Use --content, --file, or positional secret text.");
                return;
            };

            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            let recipient = to.unwrap_or_else(|| "public".to_string());
            let sender = match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(w) => w.address.clone(),
                Err(e) => {
                    eprintln!("Error getting wallet info: {e}");
                    return;
                }
            };

            match secrets::share_secret(&secret_content, &ttl, max_reads, &recipient, &sender, pwd.as_deref()) {
                Ok(rec) => {
                    println!("Secret shared successfully!");
                    println!("Secret ID: {}", rec.id);
                    println!("Expires At: {}", rec.expires_at);
                    println!("Max Reads: {}", rec.max_reads);
                    println!("To view this secret, run: bsec view {}", rec.id);
                }
                Err(e) => eprintln!("Error sharing secret: {}", e),
            }
        }

        Some(Commands::View {
            secret_id,
            output,
            password,
        }) => {
            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            let user_addr = match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(w) => w.address.clone(),
                Err(e) => {
                    eprintln!("Error loading wallet: {e}");
                    return;
                }
            };

            match secrets::view_secret(&secret_id, &user_addr, pwd.as_deref()) {
                Ok(content) => {
                    if let Some(out_path) = output {
                        if let Err(e) = std::fs::write(&out_path, &content) {
                            eprintln!("Error writing output file: {}", e);
                        } else {
                            println!("Secret saved to: {}", out_path.display());
                        }
                    } else {
                        println!("Secret Content:");
                        println!("-------------------");
                        println!("{}", content);
                        println!("-------------------");
                    }
                }
                Err(e) => eprintln!("Error viewing secret: {}", e),
            }
        }

        Some(Commands::List {
            user,
            all_users,
            all,
            expired,
            active,
            password,
        }) => {
            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            let user_addr = match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(w) => w.address.clone(),
                Err(e) => {
                    eprintln!("Error loading wallet: {e}");
                    return;
                }
            };

            let list_all = all || all_users;
            match secrets::list_secrets(&user_addr, user.as_deref(), list_all, expired, active) {
                Ok(list) => {
                    if list.is_empty() {
                        println!("No matching secrets found.");
                    } else {
                        println!("Secrets:");
                        println!("-------------------");
                        for sec in list {
                            println!("ID: {}", sec.id);
                            println!("Sender: {}", sec.sender);
                            println!("Recipient: {}", sec.recipient);
                            println!("Created: {}", sec.created_at);
                            println!("Expires: {}", sec.expires_at);
                            println!("Reads: {}/{}", sec.read_count, sec.max_reads);
                            println!("-------------------");
                        }
                    }
                }
                Err(e) => eprintln!("Error listing secrets: {}", e),
            }
        }

        Some(Commands::Revoke { secret_id, password }) => {
            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            let user_addr = match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(w) => w.address.clone(),
                Err(e) => {
                    eprintln!("Error loading wallet: {e}");
                    return;
                }
            };

            match secrets::revoke_secret(&secret_id, &user_addr) {
                Ok(_) => println!("Secret '{}' has been revoked.", secret_id),
                Err(e) => eprintln!("Error revoking secret: {}", e),
            }
        }

        Some(Commands::Hide {
            secret_id,
            user,
            all,
            password,
        }) => {
            let pwd = get_password_or_prompt(password, "Enter wallet password (if encrypted): ");
            let user_addr = match wallet::get_wallet_info(pwd.as_deref()) {
                Ok(w) => w.address.clone(),
                Err(e) => {
                    eprintln!("Error loading wallet: {e}");
                    return;
                }
            };

            let target_id = if all { None } else { secret_id.as_deref() };
            match secrets::hide_secret(target_id, user.as_deref(), &user_addr) {
                Ok(count) => println!("Hidden {} secret(s).", count),
                Err(e) => eprintln!("Error hiding secret: {}", e),
            }
        }

        Some(Commands::Convert {
            input_file,
            output_file,
            file,
            out,
            format,
            prefix,
            suffix,
            embed,
        }) => {
            let in_path = file.or(input_file);
            let out_path = out.or(output_file);

            if in_path.is_none() || out_path.is_none() {
                eprintln!("Error: Both input and output files are required for convert command.");
                return;
            }

            let input_p = in_path.unwrap();
            let output_p = out_path.unwrap();

            match env_file::convert_env_file(
                &input_p,
                &output_p,
                &format,
                prefix.as_deref(),
                suffix.as_deref(),
                embed.as_deref(),
            ) {
                Ok(_) => println!("Converted '{}' to '{}'.", input_p.display(), output_p.display()),
                Err(e) => eprintln!("Error converting file: {}", e),
            }
        }

        Some(Commands::Validate { env, schema }) => {
            match env_file::validate_env_file(&schema, &env) {
                Ok(_) => println!("Validation complete."),
                Err(e) => eprintln!("Error validating env file: {}", e),
            }
        }

        Some(Commands::Generate { env, out }) => {
            match env_file::generate_template(&env, &out) {
                Ok(_) => println!("Template file '{}' created successfully.", out.display()),
                Err(e) => eprintln!("Error generating template: {}", e),
            }
        }

        Some(Commands::Encrypt { file, out }) => {
            match env_file::encrypt_env_file(&file, out.as_deref()) {
                Ok(target) => println!("Encrypted file saved to '{}'.", target.display()),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }

        Some(Commands::Decrypt { file, out }) => {
            match env_file::decrypt_env_file(&file, out.as_deref()) {
                Ok(target) => println!("Decrypted file saved to '{}'.", target.display()),
                Err(e) => eprintln!("Error decrypting file: {}", e),
            }
        }

        Some(Commands::Run { env, secret, command }) => {
            match env_file::run_with_envs(env.as_deref(), secret.as_deref(), &command) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("Error running command: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::Log { env_name, file }) => {
            if let Err(e) = env_file::log_env_var(&env_name, &file) {
                eprintln!("Error logging variable: {}", e);
            }
        }

        Some(Commands::Get { name }) => {
            let conf = config::get_config();
            match manager::get_env_variable(&name, &conf.encryption_key) {
                Some(value) => println!("{}: {}", name, value),
                None => println!("environment variable not found"),
            }
        }

        Some(Commands::Set { name, value }) => {
            let conf = config::get_config();
            manager::set_env_variable(&name, &value, &conf.encryption_key);
            println!("environment variable set successfully");
        }

        Some(Commands::Search { name, path }) => {
            helpers::search_file(&path, &name);
        }

        None => {
            print_banner();
            println!("Use --help to see available commands.");
        }
    }
}
