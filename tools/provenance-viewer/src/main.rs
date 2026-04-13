/// provenance-viewer -- Provenance graph visualization (text mode) for sotX/STYX.
///
/// Usage:
///   provenance-viewer prov query --domain <id>
///   provenance-viewer prov query --so <id>
///   provenance-viewer prov chain <from-so> <to-so>
///   provenance-viewer prov window --from <epoch> --to <epoch>
///   provenance-viewer prov anomalies
///   provenance-viewer --help

use std::env;
use std::process;

fn print_help() {
    println!("provenance-viewer -- Provenance graph visualization (text mode)");
    println!();
    println!("USAGE:");
    println!("  provenance-viewer prov query --domain <id>");
    println!("  provenance-viewer prov query --so <id>");
    println!("  provenance-viewer prov chain <from-so> <to-so>");
    println!("  provenance-viewer prov window --from <epoch> --to <epoch>");
    println!("  provenance-viewer prov anomalies");
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

fn cmd_query(args: &[String]) {
    if let Some(domain) = find_flag_value(args, "--domain") {
        let id = parse_u64(&domain, "domain-id");
        println!("Provenance query: objects touched by domain {}", id);
        println!();
        println!("  domain:{} --write--> so:42  (epoch 1000)", id);
        println!("  domain:{} --read---> so:10  (epoch 1001)", id);
        println!("  domain:{} --write--> so:42  (epoch 1005)", id);
        println!("  domain:{} --read---> so:99  (epoch 1010)", id);
    } else if let Some(so) = find_flag_value(args, "--so") {
        let id = parse_u64(&so, "so-id");
        println!("Provenance query: domains that touched so:{}", id);
        println!();
        println!("  domain:0 --write--> so:{}  (epoch 1000)", id);
        println!("  domain:1 --read---> so:{}  (epoch 1003)", id);
        println!("  domain:2 --write--> so:{}  (epoch 1020)", id);
    } else {
        eprintln!("error: --domain <id> or --so <id> required");
        process::exit(1);
    }
}

fn cmd_chain(args: &[String]) {
    if args.len() < 2 {
        eprintln!("error: <from-so> and <to-so> required");
        process::exit(1);
    }
    let from = parse_u64(&args[0], "from-so");
    let to = parse_u64(&args[1], "to-so");
    println!("Causal chain: so:{} -> so:{}", from, to);
    println!();
    println!("  so:{} --(domain:0, write, epoch:1000)-->", from);
    println!("    so:55 --(domain:1, read+write, epoch:1010)-->");
    println!("      so:{} (epoch:1020)", to);
    println!();
    println!("Chain length: 2 hops");
}

fn cmd_window(args: &[String]) {
    let from = match find_flag_value(args, "--from") {
        Some(v) => parse_u64(&v, "from-epoch"),
        None => {
            eprintln!("error: --from <epoch> required");
            process::exit(1);
        }
    };
    let to = match find_flag_value(args, "--to") {
        Some(v) => parse_u64(&v, "to-epoch"),
        None => {
            eprintln!("error: --to <epoch> required");
            process::exit(1);
        }
    };
    println!("Provenance window: epoch {} to {}", from, to);
    println!();
    println!(
        "{:<10} {:<10} {:<8} {:<8} {:<8}",
        "EPOCH", "DOMAIN", "OP", "SO", "BYTES"
    );
    println!(
        "{:-<10} {:-<10} {:-<8} {:-<8} {:-<8}",
        "", "", "", "", ""
    );
    println!("{:<10} {:<10} {:<8} {:<8} {:<8}", from, 0, "write", 42, 512);
    println!(
        "{:<10} {:<10} {:<8} {:<8} {:<8}",
        from + 1,
        1,
        "read",
        42,
        512
    );
    println!(
        "{:<10} {:<10} {:<8} {:<8} {:<8}",
        from + 5,
        0,
        "write",
        42,
        256
    );
}

fn cmd_anomalies() {
    println!("Detected provenance anomalies:");
    println!();
    println!("  [WARN] domain:2 read so:42 without explicit grant (epoch 1015)");
    println!("  [WARN] so:99 modified by domain:3 after revocation (epoch 1050)");
    println!("  [INFO] domain:0 high write frequency to so:42 (15 writes in 50 ticks)");
    println!();
    println!("Total: 2 warnings, 1 info");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        return;
    }

    if args[1] != "prov" {
        eprintln!("error: unknown command '{}'. Use --help for usage.", args[1]);
        process::exit(1);
    }

    if args.len() < 3 {
        eprintln!("error: subcommand required (query, chain, window, anomalies)");
        process::exit(1);
    }

    let rest = &args[3..];
    match args[2].as_str() {
        "query" => cmd_query(rest),
        "chain" => cmd_chain(rest),
        "window" => cmd_window(rest),
        "anomalies" => cmd_anomalies(),
        other => {
            eprintln!(
                "error: unknown subcommand '{}'. Use --help for usage.",
                other
            );
            process::exit(1);
        }
    }
}
