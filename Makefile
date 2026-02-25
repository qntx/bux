# Makefile for qntx/bux — Distributable BoxLite VM Runtime
#
# Workspace members : bux-sys, bux, bux-cli

.PHONY: all
all: pre-commit

# Build the workspace in release mode
.PHONY: build
build:
	cargo build --release --all-features

# Quick compilation check without codegen
.PHONY: check
check:
	cargo check --all-features

# Run all workspace tests
.PHONY: test
test:
	cargo test --all-features

# Run benchmarks
.PHONY: bench
bench:
	cargo bench --all-features

# Run the CLI binary
.PHONY: run
run:
	cargo run --release --all-features

# Lint with Clippy (auto-fix)
.PHONY: clippy
clippy:
	cargo +nightly clippy --fix \
		--all-targets \
		--all-features \
		--allow-dirty \
		--allow-staged \
		-- -D warnings

# Format workspace code
.PHONY: fmt
fmt:
	cargo +nightly fmt

# Check formatting without modifying files
.PHONY: fmt-check
fmt-check:
	cargo +nightly fmt --check

# Generate and open documentation
.PHONY: doc
doc:
	cargo +nightly doc --all-features --no-deps --open

# Regenerate bux-sys/src/bindings.rs from remote libkrun.h (requires libclang)
# Pipeline: download libkrun.h → bindgen → src/bindings.rs
.PHONY: regenerate-bindings
regenerate-bindings:
	BUX_UPDATE_BINDINGS=1 cargo check -p bux-sys --features regenerate

# Update dependencies
.PHONY: update
update:
	cargo update

# Check for unused dependencies
.PHONY: udeps
udeps:
	cargo +nightly udeps --all-features

# Generate CHANGELOG.md using git-cliff
.PHONY: cliff
cliff:
	git cliff --output CHANGELOG.md

.PHONY: pre-commit
pre-commit:
	$(MAKE) fmt
	$(MAKE) clippy
	$(MAKE) test
	$(MAKE) build
	$(MAKE) cliff
