# codec-amr

AMR-WB behind the `codec::Codec` trait, plus a **pure-Rust RFC 4867** RTP
payload-format implementation.

## Default build

- No C dependency, no `unsafe` (crate-level `forbid(unsafe_code)` applies).
- `rtp` module: RFC 4867 octet-aligned parse/serialise, ToC/F/FT/Q/P handling,
  speech/SID/no-data/lost classification, multi-frame concatenation.
  Bandwidth-efficient mode is rejected explicitly (`UnsupportedMode`).
- `AmrWbCodec::new()` succeeds, but `encode`/`decode` return
  `CodecError::Unavailable`.

## `--features amr-wb`

Links the **system** `libopencore-amrwb` decoder via pkg-config. It provides
decode only; the library has no AMR-WB encoder, so `encode` returns
`CodecError::Unavailable`.

```sh
# Host build
cargo build -p codec-amr --features amr-wb

# Cross build: point pkg-config at the target sysroot
PKG_CONFIG_ALLOW_CROSS=1 \
PKG_CONFIG_SYSROOT_DIR=$SYSROOT \
PKG_CONFIG_PATH=$SYSROOT/usr/lib/pkgconfig \
cargo build -p codec-amr --target aarch64-unknown-linux-gnu --features amr-wb

# Or bypass pkg-config with an explicit prefix
OPENCODE_AMR_DIR=$SYSROOT/usr \
cargo build -p codec-amr --target armv7-unknown-linux-gnueabihf --features amr-wb
```

## `--features amr-wb-dlopen`

Uses `libloading` to resolve `D_IF_init`/`D_IF_decode`/`D_IF_exit` at runtime.
It does not link the library at build time, so it builds on hosts without
libopencore-amrwb. Trade-off: a runtime failure (`CodecUnavailable`) if the
target image lacks the shared object, and the loader path is platform-specific.
This backend does not compile on targets without `dlopen` support.

```sh
# Override the soname/path if it is not on the loader search path.
OPENCODE_AMRWB_LIB=/opt/homebrew/lib/libopencore-amrwb.0.dylib \
  cargo test -p codec-amr --features amr-wb-dlopen
```

## Legal

Read [`PATENTS.md`](PATENTS.md). The implementation is Apache-2.0; AMR-WB
patents are not granted. Features are off by default.
