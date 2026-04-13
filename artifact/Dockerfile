# sotFS Artifact Evaluation — Reproducible Environment
#
# Builds the entire sotfs workspace, runs all tests (165+), runs all
# benchmarks, and generates the tables from the paper.
#
# Usage:
#   docker build -t sotfs-artifact artifact/
#   docker run --rm sotfs-artifact              # full evaluation
#   docker run --rm sotfs-artifact tests-only   # just tests
#   docker run --rm sotfs-artifact bench-only   # just benchmarks

FROM rust:1.85-bookworm

# Install TLC (TLA+ model checker) for Layer 1 verification
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    python3 \
    time \
    && rm -rf /var/lib/apt/lists/*

# Pin nightly toolchain (matches development environment)
RUN rustup toolchain install nightly-2026-04-01 \
    && rustup default nightly-2026-04-01

WORKDIR /sotfs

# Copy only Cargo files first for dependency caching
COPY sotfs/Cargo.toml sotfs/Cargo.lock* ./
COPY sotfs/sotfs-graph/Cargo.toml sotfs-graph/Cargo.toml
COPY sotfs/sotfs-ops/Cargo.toml sotfs-ops/Cargo.toml
COPY sotfs/sotfs-monitor/Cargo.toml sotfs-monitor/Cargo.toml
COPY sotfs/sotfs-tx/Cargo.toml sotfs-tx/Cargo.toml
COPY sotfs/sotfs-storage/Cargo.toml sotfs-storage/Cargo.toml

# Copy source
COPY sotfs/ .

# Copy formal specs for TLC verification
COPY formal/ /formal/

# Copy evaluation script
COPY artifact/run_evaluation.sh /run_evaluation.sh
RUN chmod +x /run_evaluation.sh

# Pre-build in release mode (benchmarks need --release)
RUN cargo build --workspace --exclude sotfs-fuse --release 2>&1 \
    || cargo build --workspace --exclude sotfs-fuse

# Pre-build test binaries
RUN cargo test --workspace --exclude sotfs-fuse --no-run 2>&1 || true

ENTRYPOINT ["/run_evaluation.sh"]
CMD ["full"]
