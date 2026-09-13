mod commands;
mod error;
mod keys;
mod output;

use std::{path::PathBuf, time::Duration};

use anchor_client::VerificationPolicy;
use clap::{Args, Parser, Subcommand};

use crate::error::CliError;

const DEFAULT_NODE: &str = "http://127.0.0.1:26657";

#[derive(Parser)]
#[command(name = "demo", version)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_NODE)]
    node: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Pubkey {
        path: PathBuf,
    },
    Inception {
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        threshold: Option<u16>,
        #[arg(long = "next-key", required = true)]
        next_keys: Vec<String>,
        #[arg(long)]
        next_threshold: Option<u16>,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    Query {
        id: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    History {
        id: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    Resolve {
        did: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    RotateControl {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long = "reveal-key", required = true)]
        reveal_keys: Vec<String>,
        #[arg(long)]
        reveal_threshold: Option<u16>,
        #[arg(long = "next-key", required = true)]
        next_keys: Vec<String>,
        #[arg(long)]
        next_threshold: Option<u16>,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    AuthorizeDevice {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        device_key: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    RevokeDevice {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        device_id: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    CommitCredential {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        credential: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    RevokeCredential {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        credential: String,
        #[command(flatten)]
        verification: VerificationArgs,
    },
    Deactivate {
        id: String,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[command(flatten)]
        verification: VerificationArgs,
    },
}

#[derive(Args)]
struct VerificationArgs {
    #[arg(long, value_name = "PATH")]
    genesis: PathBuf,
    #[arg(long, default_value_t = 300)]
    max_header_age_seconds: u64,
    #[arg(long, default_value_t = 10)]
    max_clock_drift_seconds: u64,
}

impl VerificationArgs {
    fn policy(&self) -> VerificationPolicy {
        VerificationPolicy {
            max_header_age: Duration::from_secs(self.max_header_age_seconds),
            max_clock_drift: Duration::from_secs(self.max_clock_drift_seconds),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    if let Err(error) = run(cli).await {
        output::error(&error.to_string());
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Keygen { path, force } => commands::keygen(&path, force),
        Command::Pubkey { path } => commands::pubkey(&path),
        Command::Inception {
            keys,
            threshold,
            next_keys,
            next_threshold,
            verification,
        } => {
            let policy = verification.policy();
            commands::inception(
                &cli.node,
                &verification.genesis,
                &policy,
                &keys,
                threshold,
                &next_keys,
                next_threshold,
            )
            .await
        }
        Command::Query { id, verification } => {
            let policy = verification.policy();
            commands::query(&cli.node, &verification.genesis, &policy, &id).await
        }
        Command::History { id, verification } => {
            let policy = verification.policy();
            commands::history(&cli.node, &verification.genesis, &policy, &id).await
        }
        Command::Resolve { did, verification } => {
            let policy = verification.policy();
            commands::resolve(&cli.node, &verification.genesis, &policy, &did).await
        }
        Command::RotateControl {
            id,
            keys,
            reveal_keys,
            reveal_threshold,
            next_keys,
            next_threshold,
            verification,
        } => {
            let policy = verification.policy();
            commands::rotate_control(
                &cli.node,
                &verification.genesis,
                &policy,
                &id,
                &keys,
                &reveal_keys,
                reveal_threshold,
                &next_keys,
                next_threshold,
            )
            .await
        }
        Command::AuthorizeDevice {
            id,
            keys,
            device_key,
            verification,
        } => {
            let policy = verification.policy();
            commands::authorize_device(
                &cli.node,
                &verification.genesis,
                &policy,
                &id,
                &keys,
                &device_key,
            )
            .await
        }
        Command::RevokeDevice {
            id,
            keys,
            device_id,
            verification,
        } => {
            let policy = verification.policy();
            commands::revoke_device(
                &cli.node,
                &verification.genesis,
                &policy,
                &id,
                &keys,
                &device_id,
            )
            .await
        }
        Command::CommitCredential {
            id,
            keys,
            credential,
            verification,
        } => {
            let policy = verification.policy();
            commands::commit_credential(
                &cli.node,
                &verification.genesis,
                &policy,
                &id,
                &keys,
                &credential,
            )
            .await
        }
        Command::RevokeCredential {
            id,
            keys,
            credential,
            verification,
        } => {
            let policy = verification.policy();
            commands::revoke_credential(
                &cli.node,
                &verification.genesis,
                &policy,
                &id,
                &keys,
                &credential,
            )
            .await
        }
        Command::Deactivate {
            id,
            keys,
            verification,
        } => {
            let policy = verification.policy();
            commands::deactivate(&cli.node, &verification.genesis, &policy, &id, &keys).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_policy_converts_seconds_to_durations() {
        let args = VerificationArgs {
            genesis: PathBuf::from("genesis.json"),
            max_header_age_seconds: 120,
            max_clock_drift_seconds: 5,
        };

        let policy = args.policy();

        assert_eq!(policy.max_header_age, Duration::from_secs(120));
        assert_eq!(policy.max_clock_drift, Duration::from_secs(5));
    }
}
