mod client;
mod instance;
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

    #[arg(long, env = "GHIDRA_TOKEN", hide_env_values = true)]
    ghidra_token: Option<String>,

    #[arg(
        long,
        env = "GHIDRA_MCP_ALLOW_MULTIPLE",
        default_value_t = false,
        help = "Allow multiple bridges for the same binary (default: replace older instances)."
    )]
    allow_multiple: bool,

    #[arg(
        long,
        env = "GHIDRA_MCP_DETACH",
        default_value_t = false,
        help = "Do not exit when the parent MCP client dies (default: exit — no orphan bridges)."
    )]
    detach: bool,
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

    instance::prepare(args.allow_multiple, args.detach);

    tracing::info!(
        url = %args.ghidra_server,
        allow_multiple = args.allow_multiple,
        detach = args.detach,
        "starting ghidra-mcp"
    );

    let server = GhidraServer::new(
        args.ghidra_server,
        args.timeout_secs,
        args.ghidra_token.as_deref(),
    )?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
