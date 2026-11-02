# hyphae — host build, tests and the ARM cross-check gate.

.PHONY: check test gate arm

check:
	cargo check --workspace

test:
	cargo test --workspace

# The full local gate: format, lints, tests, and the ARM type-check.
gate: test arm
	cargo fmt --all --check
	cargo clippy --workspace --all-targets

arm:
	cargo check --workspace --target aarch64-unknown-linux-gnu
	cargo check --workspace --target armv7-unknown-linux-gnueabihf
