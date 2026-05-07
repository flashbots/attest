use anyhow::{Result, bail};
use clap::Parser;

#[derive(Parser)]
pub(crate) struct Args {}

pub(crate) fn run(_args: Args) -> Result<()> {
    bail!("`attest dump` is not yet implemented");
}
