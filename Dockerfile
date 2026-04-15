FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY tests/ tests/

RUN cargo build --release

FROM builder AS test
RUN cargo test -- --nocapture

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    traceroute \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/netmap /usr/local/bin/netmap

ENTRYPOINT ["netmap"]
CMD ["scan", "--help"]
