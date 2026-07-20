//! Native (Rust) crypto primitives, installed into every V8 context.
//!
//! WebCrypto has to be *real*. A page that hashes a known input and compares the
//! digest catches any fake immediately, and `crypto.subtle` being absent — as it
//! was — is an instant tell, since every browser on a secure origin exposes it.
//! Implementing the primitives here also means the page-visible functions are
//! backed by genuine native code instead of readable JS.
//!
//! The bindings land as `__pt_*` globals (which the stealth layer filters out of
//! every introspection route); the JS layer wraps them in the standard
//! `Crypto`/`SubtleCrypto`/`CryptoKey` interfaces. Each takes and returns plain
//! byte arrays and is synchronous — SubtleCrypto's Promises are added in JS.
//!
//! A binding returns `null` for an unsupported algorithm or malformed input, and
//! the JS layer turns that into the rejection WebCrypto specifies.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Install every native binding on the current context's global object.
pub fn install(scope: &mut v8::HandleScope) {
    bind(scope, "__pt_randomBytes", random_bytes);
    bind(scope, "__pt_digest", digest);
    bind(scope, "__pt_hmac", hmac_sign);
    bind(scope, "__pt_pbkdf2", pbkdf2_derive);
    bind(scope, "__pt_hkdf", hkdf_derive);
    bind(scope, "__pt_aesgcm", aes_gcm_op);
    bind(scope, "__pt_aescbc", aes_cbc_op);
    bind(scope, "__pt_pngDataUrl", png_data_url);
}

fn bind(scope: &mut v8::HandleScope, name: &str, cb: impl v8::MapFnTo<v8::FunctionCallback>) {
    let global = scope.get_current_context().global(scope);
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let tmpl = v8::FunctionTemplate::new(scope, cb);
    if let Some(func) = tmpl.get_function(scope) {
        global.set(scope, key.into(), func.into());
    }
}

// ---- argument / return helpers ------------------------------------------

/// Bytes behind a `Uint8Array`/`DataView`/`ArrayBuffer` argument (empty if the
/// value is neither).
fn arg_bytes(value: v8::Local<v8::Value>) -> Vec<u8> {
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let mut out = vec![0u8; view.byte_length()];
        let n = view.copy_contents(&mut out);
        out.truncate(n);
        return out;
    }
    if let Ok(buf) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        let store = buf.get_backing_store();
        return (0..buf.byte_length()).map(|i| store[i].get()).collect();
    }
    Vec::new()
}

fn arg_string(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> String {
    value.to_rust_string_lossy(scope)
}

fn arg_usize(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> usize {
    value.integer_value(scope).unwrap_or(0).max(0) as usize
}

/// Return `bytes` to JS as a `Uint8Array`.
fn set_bytes(scope: &mut v8::HandleScope, rv: &mut v8::ReturnValue, bytes: &[u8]) {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    let buf = v8::ArrayBuffer::with_backing_store(scope, &store);
    match v8::Uint8Array::new(scope, buf, 0, bytes.len()) {
        Some(arr) => rv.set(arr.into()),
        None => rv.set_null(),
    }
}

// ---- bindings ------------------------------------------------------------

/// `__pt_randomBytes(n)` — cryptographically secure bytes from the OS. The old JS
/// shim used a seeded xorshift, which is neither random enough for real page
/// crypto nor plausible for `crypto.getRandomValues`.
fn random_bytes(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let n = arg_usize(scope, args.get(0)).min(65536);
    let mut buf = vec![0u8; n];
    if getrandom::getrandom(&mut buf).is_err() {
        rv.set_null();
        return;
    }
    set_bytes(scope, &mut rv, &buf);
}

/// `__pt_digest(alg, data)`
fn digest(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let alg = arg_string(scope, args.get(0)).to_ascii_uppercase();
    let data = arg_bytes(args.get(1));
    let out = match alg.as_str() {
        "SHA-1" => Sha1::digest(&data).to_vec(),
        "SHA-256" => Sha256::digest(&data).to_vec(),
        "SHA-384" => Sha384::digest(&data).to_vec(),
        "SHA-512" => Sha512::digest(&data).to_vec(),
        _ => {
            rv.set_null();
            return;
        }
    };
    set_bytes(scope, &mut rv, &out);
}

/// `__pt_hmac(hash, key, data)`
fn hmac_sign(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let hash = arg_string(scope, args.get(0)).to_ascii_uppercase();
    let key = arg_bytes(args.get(1));
    let data = arg_bytes(args.get(2));

    // Instantiated per concrete hash: the generic bounds for a hash-agnostic
    // HMAC helper are far more trouble than four expansions.
    macro_rules! hmac_out {
        ($h:ty) => {{
            <Hmac<$h> as Mac>::new_from_slice(&key).ok().map(|mut m| {
                m.update(&data);
                m.finalize().into_bytes().to_vec()
            })
        }};
    }

    let out = match hash.as_str() {
        "SHA-1" => hmac_out!(Sha1),
        "SHA-256" => hmac_out!(Sha256),
        "SHA-384" => hmac_out!(Sha384),
        "SHA-512" => hmac_out!(Sha512),
        _ => None,
    };
    match out {
        Some(bytes) => set_bytes(scope, &mut rv, &bytes),
        None => rv.set_null(),
    }
}

/// `__pt_pbkdf2(hash, password, salt, iterations, byteLength)`
fn pbkdf2_derive(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let hash = arg_string(scope, args.get(0)).to_ascii_uppercase();
    let pass = arg_bytes(args.get(1));
    let salt = arg_bytes(args.get(2));
    let iters = arg_usize(scope, args.get(3)).clamp(1, 10_000_000) as u32;
    let len = arg_usize(scope, args.get(4)).min(1024);

    let mut out = vec![0u8; len];
    let ok = match hash.as_str() {
        "SHA-1" => {
            pbkdf2::pbkdf2_hmac::<Sha1>(&pass, &salt, iters, &mut out);
            true
        }
        "SHA-256" => {
            pbkdf2::pbkdf2_hmac::<Sha256>(&pass, &salt, iters, &mut out);
            true
        }
        "SHA-384" => {
            pbkdf2::pbkdf2_hmac::<Sha384>(&pass, &salt, iters, &mut out);
            true
        }
        "SHA-512" => {
            pbkdf2::pbkdf2_hmac::<Sha512>(&pass, &salt, iters, &mut out);
            true
        }
        _ => false,
    };
    if ok {
        set_bytes(scope, &mut rv, &out);
    } else {
        rv.set_null();
    }
}

/// `__pt_hkdf(hash, ikm, salt, info, byteLength)`
fn hkdf_derive(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let hash = arg_string(scope, args.get(0)).to_ascii_uppercase();
    let ikm = arg_bytes(args.get(1));
    let salt = arg_bytes(args.get(2));
    let info = arg_bytes(args.get(3));
    let len = arg_usize(scope, args.get(4)).min(1024);

    macro_rules! hkdf_out {
        ($h:ty) => {{
            let mut out = vec![0u8; len];
            hkdf::Hkdf::<$h>::new(Some(&salt), &ikm)
                .expand(&info, &mut out)
                .ok()
                .map(|_| out)
        }};
    }

    let out = match hash.as_str() {
        "SHA-1" => hkdf_out!(Sha1),
        "SHA-256" => hkdf_out!(Sha256),
        "SHA-384" => hkdf_out!(Sha384),
        "SHA-512" => hkdf_out!(Sha512),
        _ => None,
    };
    match out {
        Some(bytes) => set_bytes(scope, &mut rv, &bytes),
        None => rv.set_null(),
    }
}

/// `__pt_aesgcm(encrypt, key, iv, aad, data)` — 128-bit tag (WebCrypto's default
/// and the only length browsers use in practice). Decryption returns `null` when
/// authentication fails, which the JS layer reports as an `OperationError`.
fn aes_gcm_op(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let encrypt = args.get(0).boolean_value(scope);
    let key = arg_bytes(args.get(1));
    let iv = arg_bytes(args.get(2));
    let aad = arg_bytes(args.get(3));
    let data = arg_bytes(args.get(4));

    // AES-GCM is defined for a 96-bit nonce; browsers reject anything else here.
    if iv.len() != 12 {
        rv.set_null();
        return;
    }
    let nonce = Nonce::from_slice(&iv);
    let payload = Payload {
        msg: &data,
        aad: &aad,
    };
    let out = match (key.len(), encrypt) {
        (16, true) => <Aes128Gcm as KeyInit>::new_from_slice(&key)
            .ok()
            .and_then(|c| c.encrypt(nonce, payload).ok()),
        (16, false) => <Aes128Gcm as KeyInit>::new_from_slice(&key)
            .ok()
            .and_then(|c| c.decrypt(nonce, payload).ok()),
        (32, true) => <Aes256Gcm as KeyInit>::new_from_slice(&key)
            .ok()
            .and_then(|c| c.encrypt(nonce, payload).ok()),
        (32, false) => <Aes256Gcm as KeyInit>::new_from_slice(&key)
            .ok()
            .and_then(|c| c.decrypt(nonce, payload).ok()),
        _ => None,
    };
    match out {
        Some(bytes) => set_bytes(scope, &mut rv, &bytes),
        None => rv.set_null(),
    }
}

/// `__pt_aescbc(encrypt, key, iv, data)` — PKCS#7 padded, as WebCrypto specifies.
fn aes_cbc_op(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let encrypt = args.get(0).boolean_value(scope);
    let key = arg_bytes(args.get(1));
    let iv = arg_bytes(args.get(2));
    let data = arg_bytes(args.get(3));

    if iv.len() != 16 {
        rv.set_null();
        return;
    }
    let out = match (key.len(), encrypt) {
        (16, true) => Aes128CbcEnc::new_from_slices(&key, &iv)
            .ok()
            .map(|c| c.encrypt_padded_vec_mut::<Pkcs7>(&data)),
        (16, false) => Aes128CbcDec::new_from_slices(&key, &iv)
            .ok()
            .and_then(|c| c.decrypt_padded_vec_mut::<Pkcs7>(&data).ok()),
        (32, true) => Aes256CbcEnc::new_from_slices(&key, &iv)
            .ok()
            .map(|c| c.encrypt_padded_vec_mut::<Pkcs7>(&data)),
        (32, false) => Aes256CbcDec::new_from_slices(&key, &iv)
            .ok()
            .and_then(|c| c.decrypt_padded_vec_mut::<Pkcs7>(&data).ok()),
        _ => None,
    };
    match out {
        Some(bytes) => set_bytes(scope, &mut rv, &bytes),
        None => rv.set_null(),
    }
}

/// `__pt_pngDataUrl(width, height, rgba)` — encode raw RGBA pixels as a real PNG
/// and return it as a `data:` URL.
///
/// Canvas fingerprinting hashes `toDataURL()`, so the value has to be a genuine
/// PNG *of the pixels the page drew*: returning a constant made every drawing —
/// including an empty canvas — hash identically, which a differential probe
/// spots immediately. Encoding here also keeps the expensive part out of JS.
fn png_data_url(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let width = arg_usize(scope, args.get(0)) as u32;
    let height = arg_usize(scope, args.get(1)) as u32;
    let rgba = arg_bytes(args.get(2));

    // Guard against absurd allocations from a hostile page.
    if width == 0 || height == 0 || width > 8192 || height > 8192 {
        rv.set_null();
        return;
    }
    let expected = width as usize * height as usize * 4;
    if rgba.len() != expected {
        rv.set_null();
        return;
    }

    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let Ok(mut writer) = encoder.write_header() else {
            rv.set_null();
            return;
        };
        if writer.write_image_data(&rgba).is_err() {
            rv.set_null();
            return;
        }
    }

    use base64::Engine as _;
    let url = format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(&out)
    );
    match v8::String::new(scope, &url) {
        Some(s) => rv.set(s.into()),
        None => rv.set_null(),
    }
}
