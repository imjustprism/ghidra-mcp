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

    #[arg(long, env = "GHIDRA_TIMEOUT_SECS", default_value_t = 180)]
    timeout_secs: u64,

    #[arg(long, env = "GHIDRA_TOKEN", hide_env_values = true)]
    ghidra_token: Option<String>,

    #[arg(
        long,
        env = "GHIDRA_MCP_REPLACE_SIBLINGS",
        default_value_t = false,
        help = "Kill other live ghidra-mcp processes on start. Default only reaps orphans (dead parent)."
    )]
    replace_siblings: bool,

    #[arg(
        long,
        env = "GHIDRA_MCP_DETACH",
        default_value_t = false,
        help = "Do not exit when the parent MCP host dies."
    )]
    detach: bool,

    #[arg(
        long,
        env = "GHIDRA_MCP_ALLOW_MULTIPLE",
        default_value_t = true,
        hide = true
    )]
    allow_multiple: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
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
    let replace = args.replace_siblings || !args.allow_multiple;
    instance::prepare(replace, args.detach);

    tracing::info!(
        url = %args.ghidra_server,
        replace_siblings = replace,
        detach = args.detach,
        timeout_secs = args.timeout_secs,
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
