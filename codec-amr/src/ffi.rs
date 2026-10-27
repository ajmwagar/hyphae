//! The **only** module allowed to contain `unsafe`.
//!
//! Two mutually exclusive backends:
//! * `amr-wb` — statically link the system libopencore-amrwb (`D_IF_*`).
//! * `amr-wb-dlopen` — resolve the same C symbols with libloading at runtime.
//!
//! Boundary contract: [`Decoder::decode`] takes one complete RFC 4867
//! octet-aligned RTP payload (CMR + ToC + one frame), converts it to the
//! one-octet frame header that OpenCORE's `D_IF_decode` expects, and writes
//! exactly [`crate::FRAME_SAMPLES`] PCM samples. Multi-frame payloads are
//! rejected rather than silently dropping all but one frame.

use crate::rtp;
use codec::CodecError;
use std::os::raw::{c_int, c_void};

#[cfg(all(feature = "amr-wb", feature = "amr-wb-dlopen"))]
compile_error!("features `amr-wb` and `amr-wb-dlopen` are mutually exclusive");

/// One AMR-WB frame converted to OpenCORE's input layout.
fn decoder_frame(payload: &[u8]) -> Result<(Vec<u8>, bool), CodecError> {
    let parsed = rtp::Payload::parse(payload)
        .map_err(|_| CodecError::Backend("invalid RFC 4867 payload"))?;
    if parsed.frames.len() != 1 {
        return Err(CodecError::Backend(
            "multi-frame AMR payload needs a jitter buffer, not a one-frame decoder",
        ));
    }
    let frame = &parsed.frames[0];
    let lost = matches!(frame.kind(), rtp::FrameKind::Lost);
    let mut input = Vec::with_capacity(1 + frame.data.len());
    input.push((frame.ft << 3) | (u8::from(frame.quality) << 2));
    input.extend_from_slice(&frame.data);
    Ok((input, lost))
}

#[cfg(feature = "amr-wb")]
mod imp {
    use super::*;

    extern "C" {
        fn D_IF_init() -> *mut c_void;
        fn D_IF_decode(state: *mut c_void, bits: *const u8, synth: *mut i16, bfi: c_int);
        fn D_IF_exit(state: *mut c_void);
    }

    pub struct Decoder {
        state: *mut c_void,
    }

    impl Decoder {
        pub fn new() -> Result<Self, CodecError> {
            // SAFETY: D_IF_init allocates decoder state and returns either a
            // valid pointer or null. No Rust references cross the boundary.
            let state = unsafe { D_IF_init() };
            if state.is_null() {
                return Err(CodecError::Init("D_IF_init returned null"));
            }
            Ok(Self { state })
        }

        pub fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
            if out.len() < crate::FRAME_SAMPLES {
                return Err(CodecError::BufferTooSmall {
                    need: crate::FRAME_SAMPLES,
                    have: out.len(),
                });
            }
            let (input, lost) = decoder_frame(packet)?;
            // SAFETY: state is the non-null pointer from D_IF_init and is live
            // for &mut self. `input` and `out` are valid for their lengths; the
            // decoder writes exactly 320 i16 samples for one AMR-WB frame.
            unsafe {
                D_IF_decode(
                    self.state,
                    input.as_ptr(),
                    out.as_mut_ptr(),
                    c_int::from(lost),
                );
            }
            Ok(crate::FRAME_SAMPLES)
        }
    }

    impl Drop for Decoder {
        fn drop(&mut self) {
            // SAFETY: state came from D_IF_init, is non-null, and is freed once.
            unsafe { D_IF_exit(self.state) };
        }
    }
}

#[cfg(feature = "amr-wb-dlopen")]
mod imp {
    use super::*;
    use libloading::Library;
    use std::ffi::OsString;

    type InitFn = unsafe extern "C" fn() -> *mut c_void;
    type DecodeFn = unsafe extern "C" fn(*mut c_void, *const u8, *mut i16, c_int);
    type ExitFn = unsafe extern "C" fn(*mut c_void);

    pub struct Decoder {
        state: *mut c_void,
        decode_fn: DecodeFn,
        exit: ExitFn,
        // Kept alive until after `exit` runs (Drop below).
        _library: Library,
    }

    fn candidates() -> Vec<OsString> {
        if let Some(p) = std::env::var_os("OPENCODE_AMRWB_LIB") {
            return vec![p];
        }
        // Linux and Android first, then the macOS Homebrew soname. A target
        // without dlopen simply fails at runtime with `CodecUnavailable`.
        [
            "libopencore-amrwb.so.0",
            "libopencore-amrwb.so",
            "libopencore-amrwb.0.dylib",
            "libopencore-amrwb.dylib",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    impl Decoder {
        pub fn new() -> Result<Self, CodecError> {
            let mut last = String::new();
            for name in candidates() {
                // SAFETY: loading an arbitrary shared object is inherently
                // unsafe; the operator controls the path via env/defaults.
                let lib = match unsafe { Library::new(&name) } {
                    Ok(lib) => lib,
                    Err(e) => {
                        last = format!("{}: {e}", name.to_string_lossy());
                        continue;
                    }
                };
                // SAFETY: the symbol names and signatures match dec_if.h from
                // OpenCORE AMR-WB. The symbol pointers are copied out; the
                // Library stays alive in this struct.
                let (init, decode_fn, exit) = unsafe {
                    let init: InitFn = *lib.get(b"D_IF_init\0").map_err(|e| {
                        CodecError::Init(Box::leak(format!("D_IF_init: {e}").into_boxed_str()))
                    })?;
                    let decode_fn: DecodeFn = *lib.get(b"D_IF_decode\0").map_err(|e| {
                        CodecError::Init(Box::leak(format!("D_IF_decode: {e}").into_boxed_str()))
                    })?;
                    let exit: ExitFn = *lib.get(b"D_IF_exit\0").map_err(|e| {
                        CodecError::Init(Box::leak(format!("D_IF_exit: {e}").into_boxed_str()))
                    })?;
                    (init, decode_fn, exit)
                };
                // SAFETY: init returns either valid decoder state or null.
                let state = unsafe { init() };
                if state.is_null() {
                    return Err(CodecError::Init("D_IF_init returned null"));
                }
                let _ = init;
                return Ok(Self {
                    state,
                    decode_fn,
                    exit,
                    _library: lib,
                });
            }
            Err(CodecError::Unavailable(Box::leak(
                format!("libopencore-amrwb not loadable: {last}").into_boxed_str(),
            )))
        }

        pub fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
            if out.len() < crate::FRAME_SAMPLES {
                return Err(CodecError::BufferTooSmall {
                    need: crate::FRAME_SAMPLES,
                    have: out.len(),
                });
            }
            let (input, lost) = decoder_frame(packet)?;
            // SAFETY: state is live and owned by self; the function pointer was
            // resolved from the live library; buffers are valid for their
            // lengths and the decoder writes one 320-sample AMR-WB frame.
            unsafe {
                (self.decode_fn)(
                    self.state,
                    input.as_ptr(),
                    out.as_mut_ptr(),
                    c_int::from(lost),
                );
            }
            Ok(crate::FRAME_SAMPLES)
        }
    }

    impl Drop for Decoder {
        fn drop(&mut self) {
            // SAFETY: state came from this library's init and is freed once,
            // while the Library is still loaded (fields drop after this body).
            unsafe { (self.exit)(self.state) };
        }
    }
}

pub use imp::Decoder;
