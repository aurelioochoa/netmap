.DEFAULT_GOAL := help

.PHONY: help build release check test clean fmt fmt-check lint verify run gui install install-gui \
        docker docker-run docker-down docker-logs docker-clean docker-test

TARGET   ?= 192.168.2.0/24
RUST_LOG ?= info

help:  ## Show this help menu
	@echo ""
	@echo "  netmap — discover and render network topology maps"
	@echo ""
	@echo "  usage: make <command>"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  variables: TARGET=$(TARGET)  RUST_LOG=$(RUST_LOG)"
	@echo "  example:   make run TARGET=10.0.0.0/24"
	@echo ""

build:  ## Debug build of the CLI and GUI
	cargo build --workspace

release:  ## Optimized release build
	cargo build --workspace --release

check:  ## Type-check without producing binaries
	cargo check --workspace --all-targets

test:  ## Run the full test suite
	cargo test --workspace

clean:  ## Remove build artifacts
	cargo clean

fmt:  ## Format the source tree
	cargo fmt --all

fmt-check:  ## Verify formatting without changing files
	cargo fmt --all -- --check

lint:  ## Run clippy, treating warnings as errors
	cargo clippy --workspace --all-targets -- -D warnings

verify: fmt-check lint test  ## Everything CI runs: format, lint, test

run:  ## Scan TARGET with the CLI (override: make run TARGET=10.0.0.0/24)
	RUST_LOG=$(RUST_LOG) cargo run -p netmap -- scan $(TARGET) --sudo

gui:  ## Launch the desktop GUI
	RUST_LOG=$(RUST_LOG) cargo run -p netmap-gui

install: release  ## Build and symlink the CLI into /usr/local/bin
	sudo ln -sf $(CURDIR)/target/release/netmap /usr/local/bin/netmap
	@echo "Installed netmap to /usr/local/bin/netmap"

install-gui: release  ## Build and symlink the GUI into /usr/local/bin
	sudo ln -sf $(CURDIR)/target/release/netmap-gui /usr/local/bin/netmap-gui
	@echo "Installed netmap-gui to /usr/local/bin/netmap-gui"

docker:  ## Build the Docker image from scratch
	docker compose build --no-cache

docker-run:  ## Run a scan inside Docker
	docker compose up

docker-down:  ## Stop the Docker stack
	docker compose down

docker-logs:  ## Follow Docker logs
	docker compose logs -f

docker-clean:  ## Stop the stack and remove the local image
	docker compose down --rmi local

docker-test:  ## Run the test suite inside Docker
	docker build --target test -t netmap-test .
