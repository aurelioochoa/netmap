PROJECT       := netmap
TAGLINE       := discover and render network topology maps
HELP_VARS      = TARGET=$(TARGET)  RUST_LOG=$(RUST_LOG)
HELP_EXAMPLE   = make run TARGET=10.0.0.0/24

# ─── Preamble ────────────────────────────────────────────────────────────────
# -e stops a recipe at the first failing command; -o pipefail stops a gate that
# pipes through a filter from reporting the filter's exit code instead of the
# command's — without it, a suite that fails into `tail` "passes".
SHELL         := /usr/bin/env bash
.SHELLFLAGS   := -eo pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS     += --no-print-directory

# ─── Colour ──────────────────────────────────────────────────────────────────
# MAKE_TERMOUT (GNU Make >= 4.1) is set only when stdout is a terminal, and is
# the only reliable test available here: `test -t 1` inside $(shell ...) always
# reports false, because make captures that command's stdout through a pipe.
# So `make help | less` and CI logs stay clean. NO_COLOR disables, FORCE_COLOR
# overrides both.
COLOR ?= $(if $(MAKE_TERMOUT),1,0)
ifdef NO_COLOR
  COLOR := 0
endif
ifdef FORCE_COLOR
  COLOR := 1
endif
ifeq ($(COLOR),1)
  # Real ESC bytes, so a plain `echo` renders them without needing -e.
  C_HEAD := $(shell printf '\033[1m')
  C_CMD  := $(shell printf '\033[36m')
  C_OK   := $(shell printf '\033[32m')
  C_WARN := $(shell printf '\033[33m')
  C_ERR  := $(shell printf '\033[31m')
  C_DIM  := $(shell printf '\033[2m')
  C_OFF  := $(shell printf '\033[0m')
endif

# Explains why a core verb does not apply here, then fails.
NA = @printf '  $(C_ERR)make $@$(C_OFF) does not apply to $(PROJECT).\n  $(C_DIM)%s$(C_OFF)\n\n' $(1) >&2; exit 2

# Width of the target-name column in help; widen it where names are long.
HELP_PAD ?= 18

# PROJECT, TAGLINE, HELP_VARS and HELP_EXAMPLE are interpolated into a
# single-quoted shell string below, so none of them may contain an apostrophe.
##@ General
.PHONY: help
help: ## List the available targets
	@printf '\n  $(C_HEAD)$(PROJECT)$(C_OFF) — $(TAGLINE)\n'
	@printf '  $(C_DIM)usage: make <target>$(C_OFF)\n'
	@awk 'BEGIN { FS = ":.*?## " } \
	  /^##@ / { printf "\n  $(C_HEAD)%s$(C_OFF)\n", substr($$0, 5); next } \
	  /^[a-zA-Z0-9_.-]+:.*?## / { printf "    $(C_CMD)%-$(HELP_PAD)s$(C_OFF) %s\n", $$1, $$2 }' \
	  $(MAKEFILE_LIST)
	@printf '\n  $(C_DIM)Variables:$(C_OFF) $(HELP_VARS)\n'
	@printf '  $(C_DIM)Example:$(C_OFF)   $(HELP_EXAMPLE)\n\n'

# ─── End of the shared block ─────────────────────────────────────────────────

CARGO ?= cargo

##@ Setup
.PHONY: setup
setup: ## First run on a fresh clone: fetch the dependencies
	$(CARGO) fetch

##@ Development
# There is no dev server here, so `dev` is the watch loop and `run` executes the
# CLI. cargo-watch is optional: a missing optional tool must not hard-fail.
.PHONY: dev
dev: ## Watch loop: re-check on every save (needs cargo-watch)
	@if command -v cargo-watch >/dev/null 2>&1; then \
		$(CARGO) watch -x check; \
	else \
		printf '  $(C_WARN)cargo-watch is not installed$(C_OFF) — running a single check instead.\n'; \
		printf '  $(C_DIM)install it with: cargo install cargo-watch$(C_OFF)\n\n'; \
		$(CARGO) check --workspace --all-targets; \
	fi

TARGET   ?= 192.168.2.0/24
RUST_LOG ?= info

build:  ## Debug build of the CLI and GUI
	cargo build --workspace

release:  ## Optimized release build
	cargo build --workspace --release

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

##@ Gates
# `check` is the fast gate the standard defines, so it now runs format, lint and
# tests — what this repo previously called `verify`. The old type-check-only
# recipe kept its behaviour under the name `typecheck`.
.PHONY: typecheck
typecheck: ## Type-check without producing binaries
	$(CARGO) check --workspace --all-targets

.PHONY: check
check: fmt-check lint test ## Fast gate: format, lint, tests

.PHONY: verify
verify: check release ## Full gate: check, then an optimised build
	@printf '\n  all gates passed\n'

##@ Cleaning
.PHONY: distclean
distclean: clean ## clean, plus any fetched registry sources
	rm -rf target
	@printf "  build tree removed; 'make setup' to refetch\n"
