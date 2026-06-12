mod client;
mod tools;

use clap::Parser;
use rmcp::{ServiceExt, transport::stdio};
use tools::GhidraServer;
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about = "Ghidra MCP bridge")]
struct Args {
    #[arg(long, env = "GHIDRA_SERVER", default_value = "http://127.0.0.1:8080/")]
    ghidra_server: Url,

    #[arg(long, env = "GHIDRA_TIMEOUT_SECS", default_value_t = 60)]
    timeout_secs: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ghidra_mcp=info,warn".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let args = Args::parse();
    tracing::info!(url = %args.ghidra_server, "starting ghidra-mcp");

    let server = GhidraServer::new(args.ghidra_server, args.timeout_secs)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
