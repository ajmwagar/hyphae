# ARM cross-check gate

First devices are ARM. A host-only `cargo check` is not enough.

## Commands

```sh
rustup target add aarch64-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf

cargo check --workspace --target aarch64-unknown-linux-gnu
cargo check --workspace --target armv7-unknown-linux-gnueabihf
```

These are the same weight as host `cargo check`. `cargo check` does not link a
final executable, so no cross linker or C toolchain is needed for the default
feature set.

## What is verified

- All default crates type-check for `aarch64-unknown-linux-gnu` and
  `armv7-unknown-linux-gnueabihf`.
- Pure-Rust dependencies (`toml`, `md5`, optional `libloading`,
  `pkg-config`) are target-buildable; C-dependent code is absent by default.
- No `usize == u64` assumption, no 64-bit-only atomics, no x86 intrinsics,
  no assumption that `u64` is a register.
- `codec-amr`'s RFC 4867 module and default (feature-off) surface type-check on
  both targets.

## What is not verified here

- **We cannot run tests on ARM locally.** The host is `aarch64-apple-darwin`;
  the Linux ARM targets are type-check only. Runtime behaviour, alignment,
  endianness of any FFI buffer, and actual SIM/modem integration require device
  or emulator testing.
- `codec-amr --features amr-wb` needs a target sysroot containing
  `libopencore-amrwb` and a cross `pkg-config`; it is not part of the default
  gate. See `codec-amr/README.md` for `PKG_CONFIG_ALLOW_CROSS=1`,
  `PKG_CONFIG_PATH`, and `OPENCODE_AMR_DIR`.
- `--features amr-wb-dlopen` type-checks only where `libloading` supports the
  target; runtime symbol loading is device-specific.
- No ARM performance, power, or latency claims are made.

## Reproducing on a Linux ARM board

```sh
# Native on the device
cargo check --workspace
cargo test -p sip -p aka -p ims -p carrier -p codec -p codec-amr -p transport -p conformance
```

That is a separate gate from the cross-check; record the board, kernel and
rustc version with the result.
