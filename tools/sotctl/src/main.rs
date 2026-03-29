/// sotctl -- Domain lifecycle management CLI for sotBSD/STYX.
///
/// Usage:
///   sotctl domain list
///   sotctl domain create --policy <file>
///   sotctl domain destroy <id>
///   sotctl domain info <id>
///   sotctl domain migrate-deception <id> --profile <name>
///   sotctl --help

use std::env;
use std::process;

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

fn print_help() {
    println!("sotctl -- Domain lifecycle management");
    println!();
    println!("USAGE:");
    println!("  sotctl domain list");
    println!("  sotctl domain create --policy <file>");
    println!("  sotctl domain destroy <id>");
    println!("  sotctl domain info <id>");
    println!("  sotctl domain migrate-deception <id> --profile <name>");
    println!();
    println!("OPTIONS:");
    println!("  --help    Show this help message");
}

fn cmd_domain_list() {
    println!("{:<6} {:<12} {:<8} {:<20}", "ID", "STATE", "CAPS", "POLICY");
    println!("{:-<6} {:-<12} {:-<8} {:-<20}", "", "", "", "");
    // In a real system this would query the kernel via IPC.
    println!("{:<6} {:<12} {:<8} {:<20}", 0, "running", 12, "default");
    println!("{:<6} {:<12} {:<8} {:<20}", 1, "running", 7, "restricted");
    println!("{:<6} {:<12} {:<8} {:<20}", 2, "suspended", 3, "deception-honeypot");
}

fn cmd_domain_create(args: &[String]) {
    let policy = match find_flag_value(args, "--policy") {
        Some(p) => p,
        None => {
            eprintln!("error: --policy <file> is required");
            process::exit(1);
        }
    };
    println!("Creating domain with policy file: {}", policy);
    // Would read and parse the policy, then issue a kernel syscall.
    println!("Domain created: id=3, policy={}", policy);
}

fn cmd_domain_destroy(args: &[String]) {
    let id = parse_u64(require_arg(args, 0, "domain id"), "domain id");
    println!("Destroying domain {}...", id);
    println!("Domain {} destroyed.", id);
}

fn cmd_domain_info(args: &[String]) {
    let id = parse_u64(require_arg(args, 0, "domain id"), "domain id");
    println!("Domain {}", id);
    println!("  State:       running");
    println!("  Capabilities: 12");
    println!("  Policy:      default");
    println!("  Created:     epoch 1000");
    println!("  Threads:     2");
    println!("  Memory:      64 pages");
    println!("  Deception:   none");
}

fn cmd_domain_migrate_deception(args: &[String]) {
    let id = parse_u64(require_arg(args, 0, "domain id"), "domain id");
    let profile = match find_flag_value(args, "--profile") {
        Some(p) => p,
        None => {
            eprintln!("error: --profile <name> is required");
            process::exit(1);
        }
    };
    println!("Migrating domain {} to deception profile '{}'...", id, profile);
    println!("Domain {} now running under deception profile '{}'.", id, profile);
}

/// Search `args` for `--flag value` and return the value.
fn find_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().cloned();
        }
    }
    None
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] != "domain" {
        eprintln!("error: unknown command '{}'. Use --help for usage.", args[1]);
        process::exit(1);
    }

    if args.len() < 3 {
        eprintln!("error: subcommand required (list, create, destroy, info, migrate-deception)");
        process::exit(1);
    }

    let rest = &args[3..];
    match args[2].as_str() {
        "list" => cmd_domain_list(),
        "create" => cmd_domain_create(rest),
        "destroy" => cmd_domain_destroy(rest),
        "info" => cmd_domain_info(rest),
        "migrate-deception" => cmd_domain_migrate_deception(rest),
        other => {
            eprintln!(
                "error: unknown subcommand '{}'. Use --help for usage.",
                other
            );
            process::exit(1);
        }
    }
}
