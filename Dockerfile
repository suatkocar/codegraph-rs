# ---------------------------------------------------------------------------
# CodeGraph Security Scan — GitHub Action Docker image
# Multi-stage build: compile from source, then copy to slim runtime image.
# ---------------------------------------------------------------------------

# Stage 1: Build CodeGraph from source
FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY rules/ rules/
COPY queries/ queries/
COPY assets/ assets/
COPY benches/ benches/

# Build release binary without embeddings (not needed for security scanning,
# avoids downloading the 90MB Jina model at runtime).
RUN cargo build --release --no-default-features \
    && strip /build/target/release/codegraph

# Stage 2: Slim runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    jq \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/codegraph /usr/local/bin/codegraph
# Rules are bundled into the binary via include_str!, but kept on disk for reference.
COPY --from=builder /build/rules/ /opt/codegraph/rules/
COPY scripts/gh-action-entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
