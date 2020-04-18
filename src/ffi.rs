// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

pub use secp256k1_sys::{
SECP256K1_START_NONE,
SECP256K1_START_VERIFY,
SECP256K1_START_SIGN,
SECP256K1_SER_UNCOMPRESSED,
SECP256K1_SER_COMPRESSED,
NonceFn,
EcdhHashFn,
Context,
PublicKey,
Signature,
secp256k1_ecdh_hash_function_default,
secp256k1_nonce_function_rfc6979,
secp256k1_nonce_function_default,
secp256k1_context_no_precomp,
secp256k1_context_preallocated_size,
secp256k1_context_preallocated_create,
secp256k1_context_preallocated_destroy,
secp256k1_context_preallocated_clone_size,
secp256k1_context_preallocated_clone,
secp256k1_context_randomize,
secp256k1_ec_pubkey_parse,
secp256k1_ec_pubkey_serialize,
secp256k1_ecdsa_signature_parse_der,
secp256k1_ecdsa_signature_parse_compact,
ecdsa_signature_parse_der_lax,
secp256k1_ecdsa_signature_serialize_der,
secp256k1_ecdsa_signature_serialize_compact,
secp256k1_ecdsa_signature_normalize,
secp256k1_ecdsa_verify,
secp256k1_ecdsa_sign,
secp256k1_ec_seckey_verify,
secp256k1_ec_pubkey_create,
secp256k1_ec_privkey_tweak_add,
secp256k1_ec_pubkey_tweak_add,
secp256k1_ec_privkey_tweak_mul,
secp256k1_ec_pubkey_tweak_mul,
secp256k1_ec_pubkey_combine,
secp256k1_ecdh,
secp256k1_context_create,
secp256k1_context_destroy,
};

pub use secp256k1_sys::rustsecp256k1_v0_1_1_default_illegal_callback_fn as secp256k1_default_illegal_callback_fn;
pub use secp256k1_sys::rustsecp256k1_v0_1_1_default_error_callback_fn as secp256k1_default_error_callback_fn;

pub(crate) use secp256k1_sys::CPtr;

use types::*;

/// Library-internal representation of an ECDH shared secret
#[repr(C)]
pub struct SharedSecret([c_uchar; 32]);
impl_array_newtype!(SharedSecret, c_uchar, 32);
impl_raw_debug!(SharedSecret);

impl SharedSecret {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> SharedSecret { SharedSecret([0; 32]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    #[deprecated(since = "0.15.3", note = "Please use the new function instead")]
    pub unsafe fn blank() -> SharedSecret { SharedSecret::new() }
}

impl Default for SharedSecret {
    fn default() -> Self {
        SharedSecret::new()
    }
}
