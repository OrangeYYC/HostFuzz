use ble::input::MetaInput;
use clap::{Arg, Command};
use simulator::{Simulator, SimulatorConfig};
use tracing_subscriber::EnvFilter;

fn main() {
    let cmd_args = Command::new("MetaSimulator APP")
        .arg(Arg::new("protocol").short('p').long("protocol").help("HCI protocol").required(true))
        .arg(Arg::new("transport").short('t').long("transport").help("HCI transport").required(true))
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .help("Log level: trace, debug, info, warn, error(default)"),
        )
        .get_matches();

    let default_log_level = String::from("error");
    let log_level = cmd_args.get_one::<String>("log").unwrap_or_else(|| &default_log_level);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse().unwrap()))
        .init();

    let protocol = cmd_args.get_one::<String>("protocol").unwrap().clone();
    let transport = cmd_args.get_one::<String>("transport").unwrap().clone();
    let config = SimulatorConfig {
        protocol,
        transport,
        timeout: u64::MAX,
        initial_timeout: u64::MAX,
        ..SimulatorConfig::default()
    };

    let simulator = Simulator::new(&config, true);
    let input = MetaInput::blank();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to start tokio engine");
    println!(
        "{:?}",
        rt.block_on(async { simulator.fuzz_once(None, None, &input).await })
    );
}
