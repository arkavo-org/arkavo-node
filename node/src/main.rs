//! Substrate Node Template CLI library.
#![warn(missing_docs)]
// Allow large error types from Substrate CLI - this is a Substrate convention
#![allow(clippy::result_large_err)]

mod benchmarking;
mod chain_spec;
mod cli;
mod command;
mod rpc;
mod service;

fn main() -> sc_cli::Result<()> {
    command::run().map_err(|e| *e)
}
