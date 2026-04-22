.PHONY: build release check test clean fmt lint run install docker docker-run docker-down docker-clean docker-test

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

test:
	cargo test -- --nocapture

clean:
	cargo clean

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

TARGET ?= 192.168.2.0/24
RUST_LOG ?= info

run:
	RUST_LOG=$(RUST_LOG) cargo run -- scan $(TARGET) --no-tui --sudo

install: release
	sudo ln -sf $(CURDIR)/target/release/netmap /usr/local/bin/netmap
	@echo "Installed netmap to /usr/local/bin/netmap"

docker:
	docker compose build --no-cache

docker-run:
	docker compose up

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-clean:
	docker compose down --rmi local

docker-test:
	docker build --target test -t netmap-test .
