use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anchor_consensus::LedgerApplication;
use anchor_storage::LedgerStore;
use clap::Parser;
use tendermint_abci::ServerBuilder;

#[derive(Parser)]
#[command(name = "anchord", version)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    state: PathBuf,
    #[arg(long, value_name = "ADDR")]
    abci: SocketAddr,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let store = Arc::new(LedgerStore::open(&cli.state)?);
    let app = LedgerApplication::new(store);

    tracing::info!(abci = %cli.abci, state = %cli.state.display(), "starting anchord");

    let server = ServerBuilder::default().bind(cli.abci, app)?;
    server.listen()?;

    Ok(())
}
