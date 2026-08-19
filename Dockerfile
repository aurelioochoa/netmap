FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY tests/ tests/
# The gui crate is a workspace member, so cargo needs its manifest to resolve
# the workspace even though this image never builds it (eframe would drag in
# the whole desktop graphics stack).
COPY gui/Cargo.toml gui/Cargo.toml
COPY gui/src/ gui/src/

RUN cargo build --release -p netmap

FROM builder AS test
RUN cargo test -p netmap -- --nocapture

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    traceroute \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/netmap /usr/local/bin/netmap

# Default log verbosity; override with `-e RUST_LOG=debug` or in compose.
ENV RUST_LOG=info

ENTRYPOINT ["netmap"]
CMD ["scan", "--help"]
