mod auth;
mod breaker;
mod broker;
mod cleanup;
mod config;
mod emergency;
mod github;
mod journal;
mod kube;
mod metrics;
mod mint;
mod operations;
mod passkeys;
mod release;
mod server;
mod telegram;
mod telegram_relay;
mod telemetry;

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use config::Config;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
    path::PathBuf,
    time::Duration,
};

#[derive(Parser)]
#[command(about = "Mint short-lived GitHub App installation tokens")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct MintOptions {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
    timeout: Duration,
}

#[derive(Subcommand)]
enum Command {
    Mint {
        key: String,
        #[command(flatten)]
        options: MintOptions,
    },
    Helper {
        #[arg(default_value = "get")]
        action: String,
        #[command(flatten)]
        options: MintOptions,
    },
    Serve(server::Options),
    TelegramEnroll {
        relay: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        token_file: PathBuf,
    },
    Validate {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        service: bool,
        #[arg(long, requires = "service")]
        against: Option<PathBuf>,
    },
    Version,
    CleanupStatus {
        #[arg(long)]
        state_file: PathBuf,
    },
    /// Quarantine cleanup records while Keymint is stopped.
    CleanupQuarantine {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        session_id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Passkeys {
        #[arg(long, global = true)]
        state_file: Option<PathBuf>,
        #[command(subcommand)]
        action: PasskeyCommand,
    },
}

#[derive(Subcommand)]
enum PasskeyCommand {
    List,
    /// Revoke a passkey while Keymint is stopped.
    Revoke {
        credential_id: String,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Mint { key, options } => {
            let config = Config::load(options.config.as_deref())?;
            let entry = config
                .keys
                .get(&key)
                .with_context(|| format!("mint: key {key:?} not found in config"))?;
            let token = mint::mint(entry, options.timeout).await?;
            println!("{}", token.token);
        }
        Command::Helper { action, options } if action == "get" => helper_get(options).await?,
        Command::Helper { .. } => {}
        Command::CleanupStatus { state_file } => {
            println!("{}", operations::cleanup_status(&state_file)?);
        }
        Command::CleanupQuarantine {
            state_file,
            session_id,
            ..
        } => {
            ensure!(
                session_id.as_deref().is_none_or(|id| !id.trim().is_empty()),
                "specify either --session-id or --all"
            );
            let count = operations::quarantine_cleanup(&state_file, session_id.as_deref())?;
            println!("Quarantined {count} cleanup record(s)");
        }
        Command::Passkeys { state_file, action } => {
            let state_file = state_file.context("a passkey state file is required")?;
            match action {
                PasskeyCommand::List => println!("{}", operations::list_passkeys(&state_file)?),
                PasskeyCommand::Revoke { credential_id } => {
                    operations::revoke_passkey(&state_file, &credential_id)?;
                    println!("Passkey revoked");
                }
            }
        }
        Command::Serve(options) => server::serve(options).await?,
        Command::TelegramEnroll {
            relay,
            url,
            token_file,
        } => {
            telegram::enroll(&url, &relay, &token_file).await?;
        }
        Command::Validate {
            config,
            service,
            against,
        } => {
            let config = Config::load(config.as_deref())?;
            if service {
                config.validate_service()?;
                if let Some(path) = against {
                    config.validate_reload_from(&Config::load(Some(&path))?)?;
                }
            }
            println!("Configuration is valid");
        }
        Command::Version => println!("{}", env!("KEYMINT_VERSION")),
    }
    Ok(())
}

async fn helper_get(options: MintOptions) -> Result<()> {
    let config = Config::load(options.config.as_deref())?;
    let mut attributes = BTreeMap::new();
    for line in io::stdin().lock().lines() {
        let line = line.context("credhelper: read input")?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once('=') {
            attributes.insert(name.to_owned(), value.to_owned());
        }
    }
    let value = |name| attributes.get(name).map(String::as_str).unwrap_or_default();
    let protocol = value("protocol");
    if !protocol.is_empty() && protocol != "https" {
        return Ok(());
    }
    let host = value("host");
    ensure!(
        !host.is_empty()
            && !host.contains(['/', '?', '#', '@', '\\'])
            && !host.chars().any(char::is_whitespace),
        "credhelper: missing host attribute from git"
    );
    let path = value("path");
    ensure!(
        !path.is_empty(),
        "credhelper: git did not send `path` for {host} — set credential.useHttpPath=true; see README"
    );
    if let Some(key) = config.key_for_https_remote(host, path) {
        let token = mint::mint(key, options.timeout)
            .await
            .context("credhelper: mint")?;
        println!("username=x-access-token\npassword={}", token.token);
    }
    Ok(())
}
