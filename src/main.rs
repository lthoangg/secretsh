//! secretsh — secure subprocess secret injection.
//!
//! Entry point: parses CLI arguments, hardens the process, and dispatches to
//! the appropriate subcommand handler defined in [`secretsh::cli`].

use clap::Parser;

use secretsh::cli::{
    run_delete, run_export, run_import, run_import_env, run_init, run_list, run_run, run_set, Cli,
    Command,
};
use secretsh::harden::harden_process;

fn main() {
    // ── 1. Harden the process before any secrets are loaded ───────────────────
    //
    // Disables core dumps (RLIMIT_CORE = 0) so that a crash cannot leak
    // secret material to disk.  All hardening failures are non-fatal warnings.
    harden_process();

    // ── 2. Parse CLI arguments ────────────────────────────────────────────────
    let cli = Cli::parse();

    // ── 3. Dispatch to the appropriate subcommand handler ─────────────────────
    let exit_code = dispatch(cli);

    // ── 4. Exit with the correct code ─────────────────────────────────────────
    std::process::exit(exit_code);
}

/// Dispatch the parsed [`Cli`] to the correct handler and return the process
/// exit code.
///
/// Subcommand handlers return `Result<(), SecretshError>` (or
/// `Result<i32, SecretshError>` for `run`).  Errors are printed to stderr and
/// mapped to the appropriate exit code via [`SecretshError::exit_code`].
fn dispatch(cli: Cli) -> i32 {
    match cli.command {
        // ── init ──────────────────────────────────────────────────────────────
        Command::Init(args) => match run_init(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── set ───────────────────────────────────────────────────────────────
        Command::Set(args) => match run_set(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── delete ────────────────────────────────────────────────────────────
        Command::Delete(args) => match run_delete(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── list ──────────────────────────────────────────────────────────────
        Command::List(args) => match run_list(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── run ───────────────────────────────────────────────────────────────
        //
        // `run_run` returns the child's exit code directly on success, or a
        // SecretshError on failure (e.g. vault open failed, tokenization error).
        Command::Run(args) => match run_run(&args) {
            Ok(child_exit_code) => child_exit_code,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── export ────────────────────────────────────────────────────────────
        Command::Export(args) => match run_export(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── import ────────────────────────────────────────────────────────────
        Command::Import(args) => match run_import(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },

        // ── import-env ───────────────────────────────────────────────────────
        Command::ImportEnv(args) => match run_import_env(&args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("secretsh error: {e}");
                e.exit_code()
            }
        },
    }
}
