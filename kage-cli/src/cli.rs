use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kage")]
#[command(about = "Hardware-backed key management for age/SOPS")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize org and enroll device
    Init {
        #[arg(long)]
        org_id: String,
        #[arg(long)]
        env: Vec<String>,
        #[arg(long = "1p-vault")]
        vault: String,
        #[arg(long)]
        non_interactive: bool,
    },
    /// Output age secret key for SOPS integration
    AgeIdentities {
        #[arg(long)]
        env: String,
    },
    /// Refresh device keypair and re-wrap K_env
    RotateDeviceKey {
        #[arg(long)]
        env: String,
    },
}

