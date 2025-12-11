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
    /// Run a local self-test (encrypt/decrypt roundtrip) for an environment
    SelfTest {
        #[arg(long)]
        env: String,
    },
    /// Refresh device keypair and re-wrap K_env
    RotateDeviceKey {
        #[arg(long)]
        env: String,
    },
    /// Decrypt a SOPS file using the device key for the given environment
    SopsDecrypt {
        #[arg(long)]
        env: String,
        /// Path to the encrypted SOPS file
        #[arg(long)]
        file: String,
        /// Optional output path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
    /// Encrypt a file with SOPS using the device key for the given environment
    SopsEncrypt {
        #[arg(long)]
        env: String,
        /// Path to the plaintext file
        #[arg(long)]
        file: String,
        /// Optional output path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
        /// Optional age recipient; if omitted, derived from the device key
        #[arg(long)]
        recipient: Option<String>,
    },
}
