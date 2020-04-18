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

//! # FFI of the recovery module

pub use secp256k1_sys::recovery::{
    RecoverableSignature,
    secp256k1_ecdsa_recoverable_signature_parse_compact,
    secp256k1_ecdsa_recoverable_signature_serialize_compact,
    secp256k1_ecdsa_recoverable_signature_convert,
    secp256k1_ecdsa_sign_recoverable,
    secp256k1_ecdsa_recover,
};
