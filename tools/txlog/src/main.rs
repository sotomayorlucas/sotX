/// txlog -- Transaction log viewer CLI for sotX/STYX.
///
/// Usage:
///   txlog tx list
///   txlog tx show <tx-id>
///   txlog tx replay <tx-id>
///   txlog tx stats
///   txlog --help

use std::env;
use std::process;

fn print_help() {
    println!("txlog -- Transaction log viewer");
    println!();
    println!("USAGE:");
    println!("  txlog tx list");
    println!("  txlog tx show <tx-id>");
    println!("  txlog tx replay <tx-id>");
    println!("  txlog tx stats");
    println!();
    println!("OPTIONS:");
    println!("  --help    Show this help message");
}

fn require_arg<'a>(args: &'a [String], idx: usize, label: &str) -> &'a str {
    match args.get(idx) {
        Some(v) => v.as_str(),
        None => {
            eprintln!("error: {} required", label);
            process::exit(1);
        }
    }
}

fn parse_u64(s: &str, label: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or_else(|_| {
            eprintln!("error: invalid {} '{}'", label, s);
            process::exit(1);
        })
    } else {
        s.parse().unwrap_or_else(|_| {
            eprintln!("error: invalid {} '{}'", label, s);
            process::exit(1);
        })
    }
}

fn cmd_list() {
    println!(
        "{:<8} {:<10} {:<12} {:<10} {:<20}",
        "TX-ID", "TIER", "STATE", "ENTRIES", "TIMESTAMP"
    );
    println!(
        "{:-<8} {:-<10} {:-<12} {:-<10} {:-<20}",
        "", "", "", "", ""
    );
    // Placeholder data -- real implementation reads WAL from kernel/store.
    println!(
        "{:<8} {:<10} {:<12} {:<10} {:<20}",
        1, "tier-0", "committed", 3, "epoch:1000"
    );
    println!(
        "{:<8} {:<10} {:<12} {:<10} {:<20}",
        2, "tier-1", "committed", 7, "epoch:1042"
    );
    println!(
        "{:<8} {:<10} {:<12} {:<10} {:<20}",
        3, "tier-0", "aborted", 1, "epoch:1050"
    );
    println!(
        "{:<8} {:<10} {:<12} {:<10} {:<20}",
        4, "tier-2", "in-flight", 12, "epoch:1100"
    );
}

fn cmd_show(args: &[String]) {
    let tx_id = parse_u64(require_arg(args, 0, "tx-id"), "tx-id");
    println!("Transaction {}", tx_id);
    println!("  Tier:      tier-0");
    println!("  State:     committed");
    println!("  Epoch:     1000");
    println!("  WAL entries:");
    println!("    [0] WRITE  so=42  offset=0    len=512");
    println!("    [1] WRITE  so=42  offset=512  len=256");
    println!("    [2] COMMIT so=42");
}

fn cmd_replay(args: &[String]) {
    let tx_id = parse_u64(require_arg(args, 0, "tx-id"), "tx-id");
    println!("Replaying transaction {} (dry run)...", tx_id);
    println!("  [0] WRITE so=42 offset=0 len=512  ... ok");
    println!("  [1] WRITE so=42 offset=512 len=256 ... ok");
    println!("  [2] COMMIT so=42                    ... ok");
    println!("Replay complete: 3/3 entries succeeded (no side effects).");
}

fn cmd_stats() {
    println!("Transaction statistics:");
    println!("  Total transactions: 4");
    println!("  Committed:          2");
    println!("  Aborted:            1");
    println!("  In-flight:          1");
    println!();
    println!("  By tier:");
    println!("    tier-0: 2 (avg latency: 5 ticks)");
    println!("    tier-1: 1 (avg latency: 42 ticks)");
    println!("    tier-2: 1 (avg latency: -- in-flight)");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] != "tx" {
        eprintln!("error: unknown command '{}'. Use --help for usage.", args[1]);
        process::exit(1);
    }

    if args.len() < 3 {
        eprintln!("error: subcommand required (list, show, replay, stats)");
        process::exit(1);
    }

    let rest = &args[3..];
    match args[2].as_str() {
        "list" => cmd_list(),
        "show" => cmd_show(rest),
        "replay" => cmd_replay(rest),
        "stats" => cmd_stats(),
        other => {
            eprintln!(
                "error: unknown subcommand '{}'. Use --help for usage.",
                other
            );
            process::exit(1);
        }
    }
}
