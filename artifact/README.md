# sotFS Artifact Evaluation Package

Reproducible environment for all experiments in the sotFS paper.

## Quick Start

```bash
# Build the container
docker build -t sotfs-artifact artifact/

# Full evaluation (tests + all benchmarks + TLC)
docker run --rm -v $(pwd)/results:/results sotfs-artifact full

# Tests only (~30 seconds)
docker run --rm sotfs-artifact tests-only

# Benchmarks only (~10 minutes)
docker run --rm -v $(pwd)/results:/results sotfs-artifact bench-only
```

## What It Reproduces

| Table | Content | Benchmark | Time |
|-------|---------|-----------|------|
| 3 | Test suite summary (165+ tests) | `cargo test` | ~30s |
| 4 | DPO operation latency | `dpo_bench` | ~2min |
| 5 | WAL index speedup | `wal_bench` | ~1min |
| 6 | Monitor scaling (treewidth + curvature) | `monitor_bench` | ~3min |
| 7 | Real-world scale (1K-10K nodes) | `scale_bench` | ~3min |
| 8 | SquirrelFS comparison | `comparison_bench` | ~2min |

## Without Docker

```bash
# Prerequisites: Rust nightly, cargo
cd sotfs

# Run all tests
cargo test --workspace --exclude sotfs-fuse

# Run all benchmarks
cargo bench --workspace --exclude sotfs-fuse

# Run specific benchmark
cargo bench --bench dpo_bench
cargo bench --bench scale_bench
cargo bench --bench comparison_bench
```

## Output

- `results/` — Log files with raw timing data
- `target/criterion/` — Criterion HTML reports with statistical analysis
- Each benchmark produces mean/median/stddev via Criterion's default 100-sample protocol

## Nix Alternative

```nix
# flake.nix (if preferred over Docker)
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
      rust = pkgs.rust-bin.nightly."2026-04-01".default;
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [ rust pkgs.jdk21_headless ];
      };
    };
}
```

## Verification Coverage

The artifact demonstrates five verification layers:
1. **TLA+** — 14 specs, 20+ invariants (bounded model checking)
2. **Crash refinement** — 6 integration tests (redb ACID)
3. **Rust typestate** — 6 compile-time state machine enforcement
4. **Loom** — 3 exhaustive concurrency interleaving tests
5. **Coq** — 6 DPO rule proofs (unbounded, machine-checked)
