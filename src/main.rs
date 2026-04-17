//! secretsh — secure subprocess secret injection.

use clap::Parser;

use secretsh::cli::{run, Cli};
use secretsh::harden::harden_process;

fn main() {
    harden_process();
    let cli = Cli::parse();
    let exit_code = match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("secretsh error: {e}");
            e.exit_code()
        }
    };
    std::process::exit(exit_code);
}
