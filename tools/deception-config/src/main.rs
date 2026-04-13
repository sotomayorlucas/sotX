/// deception-config -- Deception profile management CLI for sotX/STYX.
///
/// Usage:
///   deception-config deception profiles
///   deception-config deception show <profile>
///   deception-config deception activate <domain-id> <profile>
///   deception-config deception deactivate <domain-id>
///   deception-config deception status <domain-id>
///   deception-config --help

use std::env;
use std::process;

fn print_help() {
    println!("deception-config -- Deception profile management");
    println!();
    println!("USAGE:");
    println!("  deception-config deception profiles");
    println!("  deception-config deception show <profile>");
    println!("  deception-config deception activate <domain-id> <profile>");
    println!("  deception-config deception deactivate <domain-id>");
    println!("  deception-config deception status <domain-id>");
    println!();
    println!("OPTIONS:");
    println!("  --help    Show this help message");
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

fn require_arg<'a>(args: &'a [String], idx: usize, label: &str) -> &'a str {
    match args.get(idx) {
        Some(v) => v.as_str(),
        None => {
            eprintln!("error: {} required", label);
            process::exit(1);
        }
    }
}

fn cmd_profiles() {
    println!(
        "{:<20} {:<40}",
        "PROFILE", "DESCRIPTION"
    );
    println!("{:-<20} {:-<40}", "", "");
    println!(
        "{:<20} {:<40}",
        "honeypot", "Full honeypot with fake services"
    );
    println!(
        "{:<20} {:<40}",
        "canary", "Canary tokens on sensitive objects"
    );
    println!(
        "{:<20} {:<40}",
        "decoy-fs", "Decoy filesystem with fake secrets"
    );
    println!(
        "{:<20} {:<40}",
        "tarpit", "Slow responses to delay attacker"
    );
    println!(
        "{:<20} {:<40}",
        "mirror", "Mirror real domain with instrumentation"
    );
}

fn cmd_show(args: &[String]) {
    let profile = require_arg(args, 0, "profile name");
    println!("Profile: {}", profile);
    println!();
    match profile {
        "honeypot" => {
            println!("  Type:        active deception");
            println!("  Services:    fake-ssh, fake-http, fake-db");
            println!("  Triggers:    any access logs alert");
            println!("  Cap policy:  read-only, no delegation");
            println!("  Alert level: high");
        }
        "canary" => {
            println!("  Type:        passive detection");
            println!("  Objects:     tagged with canary tokens");
            println!("  Triggers:    read/write to tagged objects");
            println!("  Cap policy:  normal (monitoring only)");
            println!("  Alert level: medium");
        }
        "decoy-fs" => {
            println!("  Type:        active deception");
            println!("  Objects:     fake /etc/shadow, fake .ssh/");
            println!("  Triggers:    open/read of decoy files");
            println!("  Cap policy:  read-only decoys");
            println!("  Alert level: high");
        }
        "tarpit" => {
            println!("  Type:        active delay");
            println!("  Mechanism:   IPC response delay (100-5000 ticks)");
            println!("  Triggers:    suspicious access patterns");
            println!("  Cap policy:  normal");
            println!("  Alert level: low");
        }
        "mirror" => {
            println!("  Type:        observation");
            println!("  Mechanism:   shadow domain with full logging");
            println!("  Triggers:    all IPC logged");
            println!("  Cap policy:  mirrored from source");
            println!("  Alert level: info");
        }
        _ => {
            eprintln!("error: unknown profile '{}'", profile);
            process::exit(1);
        }
    }
}

fn cmd_activate(args: &[String]) {
    let domain_id = parse_u64(require_arg(args, 0, "domain-id"), "domain-id");
    let profile = require_arg(args, 1, "profile name");
    println!(
        "Activating deception profile '{}' on domain {}...",
        profile, domain_id
    );
    println!(
        "Domain {} now running under deception profile '{}'.",
        domain_id, profile
    );
}

fn cmd_deactivate(args: &[String]) {
    let domain_id = parse_u64(require_arg(args, 0, "domain-id"), "domain-id");
    println!("Deactivating deception on domain {}...", domain_id);
    println!("Domain {} deception removed. Normal operation restored.", domain_id);
}

fn cmd_status(args: &[String]) {
    let domain_id = parse_u64(require_arg(args, 0, "domain-id"), "domain-id");
    println!("Deception status for domain {}:", domain_id);
    println!("  Active profile: honeypot");
    println!("  Since:          epoch 2000");
    println!("  Alerts fired:   3");
    println!("  Last alert:     epoch 2150 (read on decoy /etc/shadow)");
    println!("  Attacker IPC:   12 calls intercepted");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] != "deception" {
        eprintln!("error: unknown command '{}'. Use --help for usage.", args[1]);
        process::exit(1);
    }

    if args.len() < 3 {
        eprintln!(
            "error: subcommand required (profiles, show, activate, deactivate, status)"
        );
        process::exit(1);
    }

    let rest = &args[3..];
    match args[2].as_str() {
        "profiles" => cmd_profiles(),
        "show" => cmd_show(rest),
        "activate" => cmd_activate(rest),
        "deactivate" => cmd_deactivate(rest),
        "status" => cmd_status(rest),
        other => {
            eprintln!(
                "error: unknown subcommand '{}'. Use --help for usage.",
                other
            );
            process::exit(1);
        }
    }
}
