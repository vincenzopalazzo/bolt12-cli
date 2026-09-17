//! C ABI for callers that cannot link Rust (CLN `ocean-pay` via cgo).
//!
//! `cargo build -p bolt12-common --release` writes `libbolt12_common.a`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn to_cstring(s: &str) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("invoice decode failed").expect("static"))
        .into_raw()
}

/// Returns NULL if the invoice is safe for Tides.
/// Otherwise a heap string the caller must free with [`bolt12_string_free`].
///
/// # Safety
/// `invoice` must be a valid NUL-terminated UTF-8 C string, or null.
#[no_mangle]
pub unsafe extern "C" fn bolt12_tides_unsafe_invoice(invoice: *const c_char) -> *mut c_char {
    if invoice.is_null() {
        return to_cstring("invoice decode failed: null pointer");
    }
    let s = match CStr::from_ptr(invoice).to_str() {
        Ok(s) => s,
        Err(err) => return to_cstring(&format!("invoice decode failed: {err}")),
    };
    match crate::tides_unsafe_invoice(s) {
        None => std::ptr::null_mut(),
        Some(reason) => to_cstring(&reason),
    }
}

/// # Safety
/// `s` must be NULL or a pointer returned by this crate's C API.
#[no_mangle]
pub unsafe extern "C" fn bolt12_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
