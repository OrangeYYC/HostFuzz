pub mod executor;

fn main() {
    fuzzer::app::<executor::UsermodeExecutor>();
}
