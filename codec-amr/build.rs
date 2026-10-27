//! Locate libopencore-amrwb for the `amr-wb` feature.
//!
//! Order:
//! 1. `OPENCODE_AMR_DIR` (explicit sysroot: looks in `<dir>/lib`, `<dir>/lib64`)
//! 2. `pkg-config opencore-amrwb`
//!
//! Cross builds honour `PKG_CONFIG_ALLOW_CROSS=1` (pkg-config requires it) and
//! `PKG_CONFIG_PATH`/`PKG_CONFIG_SYSROOT_DIR`. A cross sysroot with a `.pc` file
//! is usually best supplied through `PKG_CONFIG_PATH`; otherwise set
//! `OPENCODE_AMR_DIR` to the target sysroot prefix.
//!
//! No C is compiled or vendored. The default feature set never invokes this
//! path.

fn main() {
    println!("cargo:rerun-if-env-changed=OPENCODE_AMR_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS");

    if std::env::var_os("CARGO_FEATURE_AMR_WB").is_none() {
        return;
    }

    if std::env::var_os("CARGO_FEATURE_AMR_WB_DLOPEN").is_some() {
        panic!("features `amr-wb` and `amr-wb-dlopen` are mutually exclusive");
    }

    if let Some(dir) = std::env::var_os("OPENCODE_AMR_DIR") {
        let dir = std::path::PathBuf::from(dir);
        let mut found = false;
        for lib in ["lib", "lib64"] {
            let candidate = dir.join(lib);
            if candidate.is_dir() {
                println!("cargo:rustc-link-search=native={}", candidate.display());
                found = true;
            }
        }
        if !found {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
        println!("cargo:rustc-link-lib=dylib=opencore-amrwb");
        // Runtime lookup on non-standard prefixes; harmless elsewhere.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        println!("cargo:rerun-if-env-changed=OPENCODE_AMR_DIR");
        return;
    }

    match pkg_config::Config::new()
        .cargo_metadata(true)
        .probe("opencore-amrwb")
    {
        Ok(lib) => {
            for path in lib.link_paths {
                println!("cargo:rustc-link-search=native={}", path.display());
            }
        }
        Err(e) => {
            panic!(
                "libopencore-amrwb not found via pkg-config ({e}).\n\
                 Install the system development package (e.g. libopencore-amr-dev),\n\
                 set PKG_CONFIG_PATH, or set OPENCODE_AMR_DIR to a sysroot prefix.\n\
                 For cross builds also set PKG_CONFIG_ALLOW_CROSS=1.\n\
                 Alternatively build with --features amr-wb-dlopen."
            );
        }
    }
}
