use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use snitchgate::{
    broker::{Broker, seed_demo},
    config::{self, Config},
    ipc::{self, Command},
    model::{Action, Duration},
    protocol, server,
    store::Store,
    tui,
};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(
    version,
    about = "A terminal control room and bounded decision broker for OpenSnitch"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Classify live GUI events read-only, with a bounded budget and no firewall decisions.
    Observe(snitchgate::observe::Options),
    /// Run Slack approvals over Socket Mode (dry-run feedback unless --live).
    Approvals(snitchgate::slack::Options),
    /// Benchmark the production explanation prompt against synthetic local fixtures.
    Benchmark(snitchgate::benchmark::Args),
    /// Run isolated service sockets; does not change OpenSnitch settings.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Also accept the legacy daemon on a Linux abstract Unix socket (root/owner only).
        #[arg(long)]
        abstract_name: Option<String>,
        /// Disable configured automation; require a human decision for every request.
        #[arg(long)]
        manual: bool,
    },
    /// Attach to a running service.
    Tui {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Explore the TUI with in-memory fixtures, without network or firewall access.
    Demo,
    /// Print a service snapshot as JSON.
    Status {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Settle a pending request by its full ID.
    Decide {
        id: String,
        #[arg(value_enum)]
        action: Action,
        #[arg(long, value_enum, default_value = "once")]
        duration: Duration,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Write a durable proposal to a staging directory (never deploys it).
    Propose {
        id: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Validate configuration without contacting providers.
    CheckConfig { path: PathBuf },
    /// Act as an OpenSnitch daemon against an explicitly supplied test socket.
    Mock {
        #[arg(long)]
        socket: PathBuf,
    },
}

fn control_socket(path: Option<PathBuf>) -> Result<PathBuf> {
    path.map(Ok)
        .unwrap_or_else(|| Ok(config::runtime_dir()?.join("control.sock")))
}

async fn serve(
    config: Config,
    runtime: PathBuf,
    state: PathBuf,
    abstract_name: Option<String>,
) -> Result<()> {
    ipc::private_dir(&runtime)?;
    ipc::private_dir(&state)?;
    let db = state.join("history.sqlite3");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&db)?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        file.metadata()?.mode() & 0o077 == 0,
        "history database must have mode 0600"
    );
    let broker = Broker::new(
        config.clone(),
        Store::open(&db, config.history_limit)?,
        false,
    )?;
    let grpc_path = runtime.join("opensnitch.sock");
    let control_path = runtime.join("control.sock");
    let grpc = ipc::bind(&grpc_path)?;
    let control = match ipc::bind(&control_path) {
        Ok(listener) => listener,
        Err(error) => {
            ipc::remove_socket(&grpc_path);
            return Err(error);
        }
    };
    eprintln!(
        "Snitchgate listening\n  OpenSnitch: {}\n  Control:    {}\n  Mode:       {}",
        grpc_path.display(),
        control_path.display(),
        broker.snapshot()?.mode
    );
    let mut grpc_task = tokio::spawn(server::serve(grpc, Arc::clone(&broker)));
    let mut ipc_task = tokio::spawn(ipc::serve(control, Arc::clone(&broker)));
    let abstract_broker = broker.clone();
    let mut abstract_task = tokio::spawn(async move {
        match abstract_name {
            Some(name) => server::serve_abstract(&name, abstract_broker).await,
            None => std::future::pending::<Result<()>>().await,
        }
    });
    let result: Result<()> = tokio::select! {
        result = &mut grpc_task => result.unwrap_or_else(|error| Err(error.into())),
        result = &mut ipc_task => result.unwrap_or_else(|error| Err(error.into())),
        result = &mut abstract_task => result.unwrap_or_else(|error| Err(error.into())),
        _ = shutdown_signal() => Ok(()),
    };
    broker.shutdown();
    // Give pending AskRule responses a chance to flush before closing transport.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    grpc_task.abort();
    ipc_task.abort();
    abstract_task.abort();
    ipc::remove_socket(&grpc_path);
    ipc::remove_socket(&control_path);
    result
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Observe(args) => snitchgate::observe::run(args).await,
        Commands::Approvals(args) => snitchgate::slack::run(args).await,
        Commands::Benchmark(args) => snitchgate::benchmark::run(args).await,
        Commands::Serve {
            config: path,
            runtime_dir,
            state_dir,
            abstract_name,
            manual,
        } => {
            let mut config = Config::load(path.as_deref())?;
            if manual {
                config.automation.clear();
            }
            let runtime = runtime_dir.map(Ok).unwrap_or_else(config::runtime_dir)?;
            let state = state_dir.map(Ok).unwrap_or_else(config::state_dir)?;
            serve(config, runtime, state, abstract_name).await
        }
        Commands::Tui { socket } => tui::run(tui::Source::Service(control_socket(socket)?)).await,
        Commands::Demo => {
            let config = Config {
                request_timeout_seconds: 100,
                ..Config::default()
            };
            let broker = Broker::new(config, Store::memory(100)?, true)?;
            seed_demo(&broker)?;
            let result = tui::run(tui::Source::Demo(broker.clone())).await;
            broker.shutdown();
            result
        }
        Commands::Status { socket } => {
            let response = ipc::request(&control_socket(socket)?, Command::Snapshot).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&response.snapshot.context("missing snapshot")?)?
            );
            Ok(())
        }
        Commands::Decide {
            id,
            action,
            duration,
            socket,
        } => {
            ipc::request(
                &control_socket(socket)?,
                Command::Decide {
                    id,
                    action,
                    duration,
                },
            )
            .await?;
            println!("{} / {} recorded", action.as_str(), duration.as_str());
            Ok(())
        }
        Commands::Propose {
            id,
            description,
            output_dir,
            socket,
        } => {
            ensure!(
                output_dir.is_dir(),
                "output directory must already exist; use a staging directory"
            );
            let proposal = ipc::request(
                &control_socket(socket)?,
                Command::Propose { id, description },
            )
            .await?
            .proposal
            .context("missing proposal")?;
            let name = proposal["name"].as_str().context("missing proposal name")?;
            ensure!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "invalid rule filename"
            );
            let path = output_dir.join(format!("{name}.json"));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            writeln!(file, "{}", serde_json::to_string_pretty(&proposal)?)?;
            println!(
                "Proposal written to {}. Review, validate, and deploy through your policy repository.",
                path.display()
            );
            Ok(())
        }
        Commands::CheckConfig { path } => {
            Config::load(Some(&path))?;
            println!("Configuration valid");
            Ok(())
        }
        Commands::Mock { socket } => {
            let mut client = server::connect(&socket).await?;
            client
                .subscribe(protocol::ClientConfig {
                    name: "snitchgate-mock".into(),
                    ..Default::default()
                })
                .await?;
            client
                .ping(protocol::PingRequest {
                    id: 42,
                    stats: None,
                })
                .await?;
            eprintln!("Mock request submitted. Decide it in the TUI or CLI.");
            let rule = client
                .ask_rule(protocol::Connection {
                    protocol: "tcp".into(),
                    dst_ip: "127.0.0.1".into(),
                    dst_port: 8000,
                    process_path: "/usr/bin/curl".into(),
                    process_id: std::process::id(),
                    user_id: 1000,
                    ..Default::default()
                })
                .await?
                .into_inner();
            println!("{} / {} ({})", rule.action, rule.duration, rule.name);
            Ok(())
        }
    }
}
