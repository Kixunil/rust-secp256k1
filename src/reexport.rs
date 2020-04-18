use types::*;
use secp256k1_sys::{Context, PublicKey, Signature, EcdhHashFn, NonceFn};
use ffi::SharedSecret;

macro_rules! reexport {
    ($(fn $fun:ident($($arg:ident: $arg_type:ty),* $(,)?) $(-> $ret:ty)?;)*) => {
        $(
            #[no_mangle]
            pub unsafe extern "C" fn $fun($($arg: $arg_type),*) $(-> $ret)? {
                ::ffi::$fun($($arg),*)
            }
        )*
    };
}

reexport!{
    fn secp256k1_context_create(flags: c_uint) -> *mut Context;

    fn secp256k1_context_destroy(ctx: *mut Context);

    fn secp256k1_context_preallocated_size(flags: c_uint) -> usize;

    fn secp256k1_context_preallocated_create(prealloc: *mut c_void, flags: c_uint) -> *mut Context;

    fn secp256k1_context_preallocated_destroy(cx: *mut Context);

    fn secp256k1_context_preallocated_clone_size(cx: *const Context) -> usize;

    fn secp256k1_context_preallocated_clone(cx: *const Context, prealloc: *mut c_void) -> *mut Context;

    fn secp256k1_context_randomize(cx: *mut Context,
                                       seed32: *const c_uchar)
                                       -> c_int;

    // Pubkeys
    fn secp256k1_ec_pubkey_parse(cx: *const Context, pk: *mut PublicKey,
                                     input: *const c_uchar, in_len: usize)
                                     -> c_int;

    fn secp256k1_ec_pubkey_serialize(cx: *const Context, output: *mut c_uchar,
                                         out_len: *mut usize, pk: *const PublicKey,
                                         compressed: c_uint)
                                         -> c_int;

    // Signatures
    fn secp256k1_ecdsa_signature_parse_der(cx: *const Context, sig: *mut Signature,
                                               input: *const c_uchar, in_len: usize)
                                               -> c_int;

    fn secp256k1_ecdsa_signature_parse_compact(cx: *const Context, sig: *mut Signature,
                                                   input64: *const c_uchar)
                                                   -> c_int;

    fn ecdsa_signature_parse_der_lax(cx: *const Context, sig: *mut Signature,
                                         input: *const c_uchar, in_len: usize)
                                         -> c_int;

    fn secp256k1_ecdsa_signature_serialize_der(cx: *const Context, output: *mut c_uchar,
                                                   out_len: *mut usize, sig: *const Signature)
                                                   -> c_int;

    fn secp256k1_ecdsa_signature_serialize_compact(cx: *const Context, output64: *mut c_uchar,
                                                       sig: *const Signature)
                                                       -> c_int;

    fn secp256k1_ecdsa_signature_normalize(cx: *const Context, out_sig: *mut Signature,
                                               in_sig: *const Signature)
                                               -> c_int;

    // ECDSA
    fn secp256k1_ecdsa_verify(cx: *const Context,
                                  sig: *const Signature,
                                  msg32: *const c_uchar,
                                  pk: *const PublicKey)
                                  -> c_int;

    fn secp256k1_ecdsa_sign(cx: *const Context,
                                sig: *mut Signature,
                                msg32: *const c_uchar,
                                sk: *const c_uchar,
                                noncefn: NonceFn,
                                noncedata: *const c_void)
                                -> c_int;

    // EC
    fn secp256k1_ec_seckey_verify(cx: *const Context,
                                      sk: *const c_uchar) -> c_int;

    fn secp256k1_ec_pubkey_create(cx: *const Context, pk: *mut PublicKey,
                                      sk: *const c_uchar) -> c_int;

//TODO secp256k1_ec_privkey_export
//TODO secp256k1_ec_privkey_import

    fn secp256k1_ec_privkey_tweak_add(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    fn secp256k1_ec_pubkey_tweak_add(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    fn secp256k1_ec_privkey_tweak_mul(cx: *const Context,
                                          sk: *mut c_uchar,
                                          tweak: *const c_uchar)
                                          -> c_int;

    fn secp256k1_ec_pubkey_tweak_mul(cx: *const Context,
                                         pk: *mut PublicKey,
                                         tweak: *const c_uchar)
                                         -> c_int;

    fn secp256k1_ec_pubkey_combine(cx: *const Context,
                                       out: *mut PublicKey,
                                       ins: *const *const PublicKey,
                                       n: c_int)
                                       -> c_int;

    fn secp256k1_ecdh(
        cx: *const Context,
        output: *mut c_uchar,
        pubkey: *const PublicKey,
        privkey: *const c_uchar,
        hashfp: EcdhHashFn,
        data: *mut c_void,
    ) -> c_int;
}
