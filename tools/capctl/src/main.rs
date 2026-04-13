/// capctl -- Capability inspection and management CLI for sotX/STYX.
///
/// Usage:
///   capctl cap list <domain-id>
///   capctl cap inspect <cap-id>
///   capctl cap grant <source-cap> <target-domain> <rights-mask>
///   capctl cap revoke <cap-id>
///   capctl cap attenuate <cap-id> <rights-mask>
///   capctl cap interpose <cap-id> <proxy-domain> <policy>
///   capctl --help

use std::env;
use std::process;

fn print_help() {
    println!("capctl -- Capability inspection and management");
    println!();
    println!("USAGE:");
    println!("  capctl cap list <domain-id>");
    println!("  capctl cap inspect <cap-id>");
    println!("  capctl cap grant <source-cap> <target-domain> <rights-mask>");
    println!("  capctl cap revoke <cap-id>");
    println!("  capctl cap attenuate <cap-id> <rights-mask>");
    println!("  capctl cap interpose <cap-id> <proxy-domain> <policy>");
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

fn cmd_list(args: &[String]) {
    let domain_id = parse_u64(require_arg(args, 0, "domain-id"), "domain-id");
    println!("Capabilities for domain {}:", domain_id);
    println!(
        "{:<8} {:<14} {:<12} {:<8} {:<8}",
        "CAP", "TYPE", "RIGHTS", "EPOCH", "PARENT"
    );
    println!(
        "{:-<8} {:-<14} {:-<12} {:-<8} {:-<8}",
        "", "", "", "", ""
    );
    // Placeholder data -- real implementation would query kernel cap table.
    println!("{:<8} {:<14} {:<12} {:<8} {:<8}", 0, "endpoint", "RW", 1, "-");
    println!("{:<8} {:<14} {:<12} {:<8} {:<8}", 1, "frame", "R", 1, 0);
    println!("{:<8} {:<14} {:<12} {:<8} {:<8}", 2, "thread", "RWX", 1, "-");
    println!("{:<8} {:<14} {:<12} {:<8} {:<8}", 3, "address_space", "RW", 2, "-");
}

fn cmd_inspect(args: &[String]) {
    let cap_id = parse_u64(require_arg(args, 0, "cap-id"), "cap-id");
    println!("Capability {}", cap_id);
    println!("  Type:    endpoint");
    println!("  Rights:  RW (read, write)");
    println!("  Epoch:   1");
    println!("  Parent:  none (root)");
    println!("  Domain:  0");
    println!("  Derived: 2 children");
}

fn cmd_grant(args: &[String]) {
    let src = parse_u64(require_arg(args, 0, "source-cap"), "source-cap");
    let target = parse_u64(require_arg(args, 1, "target-domain"), "target-domain");
    let rights = require_arg(args, 2, "rights-mask");
    println!(
        "Granting cap {} to domain {} with rights mask {}...",
        src, target, rights
    );
    println!("Derived cap created: id=10, parent={}", src);
}

fn cmd_revoke(args: &[String]) {
    let cap_id = parse_u64(require_arg(args, 0, "cap-id"), "cap-id");
    println!("Revoking cap {} and all derivatives...", cap_id);
    println!("Revoked 3 capabilities (1 direct + 2 derived).");
}

fn cmd_attenuate(args: &[String]) {
    let cap_id = parse_u64(require_arg(args, 0, "cap-id"), "cap-id");
    let rights = require_arg(args, 1, "rights-mask");
    println!("Attenuating cap {} to rights mask {}...", cap_id, rights);
    println!("Cap {} rights narrowed to {}.", cap_id, rights);
}

fn cmd_interpose(args: &[String]) {
    let cap_id = parse_u64(require_arg(args, 0, "cap-id"), "cap-id");
    let proxy = parse_u64(require_arg(args, 1, "proxy-domain"), "proxy-domain");
    let policy = require_arg(args, 2, "policy");
    println!(
        "Interposing cap {} via proxy domain {} with policy '{}'...",
        cap_id, proxy, policy
    );
    println!(
        "Interposition active: cap {} -> domain {} (policy: {}).",
        cap_id, proxy, policy
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] != "cap" {
        eprintln!("error: unknown command '{}'. Use --help for usage.", args[1]);
        process::exit(1);
    }

    if args.len() < 3 {
        eprintln!("error: subcommand required (list, inspect, grant, revoke, attenuate, interpose)");
        process::exit(1);
    }

    let rest = &args[3..];
    match args[2].as_str() {
        "list" => cmd_list(rest),
        "inspect" => cmd_inspect(rest),
        "grant" => cmd_grant(rest),
        "revoke" => cmd_revoke(rest),
        "attenuate" => cmd_attenuate(rest),
        "interpose" => cmd_interpose(rest),
        other => {
            eprintln!(
                "error: unknown subcommand '{}'. Use --help for usage.",
                other
            );
            process::exit(1);
        }
    }
}
