#[macro_use]
extern crate diesel;
#[macro_use]
extern crate anyhow;

use std::str::FromStr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::{filter, prelude::*};

mod api;
mod cmd;
mod config;
mod errors;
mod helpers;
mod keys;
mod schema;
mod storage;
mod structs;
#[cfg(test)]
mod test;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the configuration template
    Configfile {},
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conf = config::Configuration::get(&cli.config)?;

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Configfile {} => cmd::configfile::run(&conf),
        }
        return Ok(());
    }

    let filter = filter::Targets::new().with_targets(vec![(
        "simple_join_server",
        Level::from_str(&conf.logging.level).unwrap(),
    )]);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    storage::setup(&conf).await?;
    api::setup(&conf).await?;

    Ok(())
}
