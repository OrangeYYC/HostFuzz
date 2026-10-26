pub mod config;
pub mod executor;

fn main() {
    fuzzer::app::<executor::SrcExecutor>();
}
