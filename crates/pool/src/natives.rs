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

/// The context bootstrap, parked on the isolate so [`make_realm`] can build a
/// second window from it without handing the source to the page.
pub struct RealmBootstrap(pub String);

/// Install every native binding on the current context's global object.
pub fn install(scope: &mut v8::HandleScope) {
    bind(scope, "__pt_makeRealm", make_realm);
    bind(scope, "__pt_randomBytes", random_bytes);
    bind(scope, "__pt_digest", digest);
    bind(scope, "__pt_hmac", hmac_sign);
    bind(scope, "__pt_pbkdf2", pbkdf2_derive);
    bind(scope, "__pt_hkdf", hkdf_derive);
    bind(scope, "__pt_aesgcm", aes_gcm_op);
    bind(scope, "__pt_aescbc", aes_cbc_op);
    bind(scope, "__pt_pngDataUrl", png_data_url);
    bind(scope, "__pt_hrtime", hrtime);

    // Optional real 2D rasterization (the `render` feature). Their presence is the
    // signal the JS canvas checks to use real pixels instead of synthesis.
    #[cfg(feature = "render")]
    {
        bind(scope, "__pt_canvasCreate", canvas_create);
        bind(scope, "__pt_canvasDestroy", canvas_destroy);
        bind(scope, "__pt_canvasFillRect", canvas_fill_rect);
        bind(scope, "__pt_canvasClearRect", canvas_clear_rect);
        bind(scope, "__pt_canvasFillText", canvas_fill_text);
        bind(scope, "__pt_canvasMeasureText", canvas_measure_text);
        bind(scope, "__pt_canvasFillPath", canvas_fill_path);
        bind(
            scope,
            "__pt_canvasFillPathGradient",
            canvas_fill_path_gradient,
        );
        bind(scope, "__pt_canvasStrokePath", canvas_stroke_path);
        bind(scope, "__pt_canvasPutImageData", canvas_put_image_data);
        bind(scope, "__pt_canvasGetImageData", canvas_get_image_data);
    }

    // Optional real WebGL (the `webgl` feature) — a headless Mesa GL context. Their
    // presence tells the JS WebGL context to draw for real instead of stamping.
    #[cfg(feature = "webgl")]
    {
        bind(scope, "__pt_glAvailable", gl_available);
        bind(scope, "__pt_glCreate", gl_create);
        bind(scope, "__pt_glDestroy", gl_destroy);
        bind(scope, "__pt_glClear", gl_clear);
        bind(scope, "__pt_glViewport", gl_viewport);
        bind(scope, "__pt_glEnable", gl_enable);
        bind(scope, "__pt_glCreateShader", gl_create_shader);
        bind(scope, "__pt_glCompileShader", gl_compile_shader);
        bind(scope, "__pt_glShaderCompiled", gl_shader_compiled);
        bind(scope, "__pt_glShaderInfoLog", gl_shader_info_log);
        bind(scope, "__pt_glCreateProgram", gl_create_program);
        bind(scope, "__pt_glAttachShader", gl_attach_shader);
        bind(scope, "__pt_glLinkProgram", gl_link_program);
        bind(scope, "__pt_glProgramLinked", gl_program_linked);
        bind(scope, "__pt_glUseProgram", gl_use_program);
        bind(scope, "__pt_glAttribLocation", gl_attrib_location);
        bind(scope, "__pt_glUniformLocation", gl_uniform_location);
        bind(scope, "__pt_glCreateBuffer", gl_create_buffer);
        bind(scope, "__pt_glBindBuffer", gl_bind_buffer);
        bind(scope, "__pt_glBufferData", gl_buffer_data);
        bind(
            scope,
            "__pt_glEnableVertexAttribArray",
            gl_enable_vertex_attrib_array,
        );
        bind(
            scope,
            "__pt_glVertexAttribPointer",
            gl_vertex_attrib_pointer,
        );
        bind(scope, "__pt_glUniformF", gl_uniform_f);
        bind(scope, "__pt_glUniform1i", gl_uniform_1i);
        bind(scope, "__pt_glUniformMatrix4", gl_uniform_matrix4);
        bind(scope, "__pt_glDrawArrays", gl_draw_arrays);
        bind(scope, "__pt_glDrawElements", gl_draw_elements);
        bind(scope, "__pt_glReadPixels", gl_read_pixels);
        bind(scope, "__pt_glCreateTexture", gl_create_texture);
        bind(scope, "__pt_glBindTexture", gl_bind_texture);
        bind(scope, "__pt_glActiveTexture", gl_active_texture);
        bind(scope, "__pt_glTexParameteri", gl_tex_parameteri);
        bind(scope, "__pt_glTexImage2D", gl_tex_image_2d);
        bind(scope, "__pt_glTexSubImage2D", gl_tex_sub_image_2d);
        bind(scope, "__pt_glGenerateMipmap", gl_generate_mipmap);
        bind(scope, "__pt_glCreateFramebuffer", gl_create_framebuffer);
        bind(scope, "__pt_glBindFramebuffer", gl_bind_framebuffer);
        bind(
            scope,
            "__pt_glFramebufferTexture2D",
            gl_framebuffer_texture_2d,
        );
        bind(
            scope,
            "__pt_glCheckFramebufferStatus",
            gl_check_framebuffer_status,
        );
        bind(scope, "__pt_glCreateRenderbuffer", gl_create_renderbuffer);
        bind(scope, "__pt_glBindRenderbuffer", gl_bind_renderbuffer);
        bind(scope, "__pt_glRenderbufferStorage", gl_renderbuffer_storage);
        bind(
            scope,
            "__pt_glFramebufferRenderbuffer",
            gl_framebuffer_renderbuffer,
        );
        bind(scope, "__pt_glCreateVertexArray", gl_create_vertex_array);
        bind(scope, "__pt_glBindVertexArray", gl_bind_vertex_array);
        bind(scope, "__pt_glDelete", gl_delete);
        bind(scope, "__pt_glBlendFunc", gl_blend_func);
        bind(scope, "__pt_glDepthFunc", gl_depth_func);
    }
}

#[cfg(feature = "render")]
fn arg_f32(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> f32 {
    value.number_value(scope).unwrap_or(0.0) as f32
}

#[cfg(feature = "webgl")]
fn arg_i32(scope: &mut v8::HandleScope, value: v8::Local<v8::Value>) -> i32 {
    value.integer_value(scope).unwrap_or(0) as i32
}

/// Little-endian `f32`s behind a `Float32Array` argument (the path verb stream).
#[cfg(any(feature = "render", feature = "webgl"))]
fn arg_f32s(value: v8::Local<v8::Value>) -> Vec<f32> {
    arg_bytes(value)
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect()
}

/// `__pt_canvasCreate(id, w, h)`
#[cfg(feature = "render")]
fn canvas_create(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::canvas::create(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_canvasDestroy(id)`
#[cfg(feature = "render")]
fn canvas_destroy(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::canvas::destroy(arg_usize(scope, args.get(0)) as u32);
}

/// `__pt_canvasFillRect(id, x, y, w, h, r, g, b, a)`
#[cfg(feature = "render")]
fn canvas_fill_rect(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let (x, y, w, h) = (
        arg_f32(scope, args.get(1)),
        arg_f32(scope, args.get(2)),
        arg_f32(scope, args.get(3)),
        arg_f32(scope, args.get(4)),
    );
    let rgba = [
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
        arg_usize(scope, args.get(7)) as u8,
        arg_usize(scope, args.get(8)) as u8,
    ];
    crate::canvas::fill_rect(id, x, y, w, h, rgba);
}

/// `__pt_canvasClearRect(id, x, y, w, h)`
#[cfg(feature = "render")]
fn canvas_clear_rect(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::canvas::clear_rect(
        arg_usize(scope, args.get(0)) as u32,
        arg_f32(scope, args.get(1)),
        arg_f32(scope, args.get(2)),
        arg_f32(scope, args.get(3)),
        arg_f32(scope, args.get(4)),
    );
}

/// `__pt_canvasFillText(id, text, x, y, size, r, g, b, a)` — real glyph pixels.
#[cfg(feature = "render")]
fn canvas_fill_text(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let text = arg_string(scope, args.get(1));
    let (x, y, size) = (
        arg_f32(scope, args.get(2)),
        arg_f32(scope, args.get(3)),
        arg_f32(scope, args.get(4)),
    );
    let rgba = [
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
        arg_usize(scope, args.get(7)) as u8,
        arg_usize(scope, args.get(8)) as u8,
    ];
    crate::canvas::fill_text(id, &text, x, y, size, rgba);
}

/// `__pt_canvasMeasureText(text, size)` → advance width in CSS px (a number).
#[cfg(feature = "render")]
fn canvas_measure_text(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let text = arg_string(scope, args.get(0));
    let size = arg_f32(scope, args.get(1));
    rv.set_double(crate::canvas::measure_text(&text, size) as f64);
}

/// `__pt_canvasFillPath(id, verbsF32, evenOdd, r, g, b, a)` — fill a tessellated path.
#[cfg(feature = "render")]
fn canvas_fill_path(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let verbs = arg_f32s(args.get(1));
    let even_odd = arg_usize(scope, args.get(2)) != 0;
    let rgba = [
        arg_usize(scope, args.get(3)) as u8,
        arg_usize(scope, args.get(4)) as u8,
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
    ];
    crate::canvas::fill_path(id, &verbs, even_odd, rgba);
}

/// `__pt_canvasFillPathGradient(id, verbsF32, evenOdd, gradF32)` — gradient fill.
#[cfg(feature = "render")]
fn canvas_fill_path_gradient(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let verbs = arg_f32s(args.get(1));
    let even_odd = arg_usize(scope, args.get(2)) != 0;
    let grad = arg_f32s(args.get(3));
    crate::canvas::fill_path_grad(id, &verbs, even_odd, &grad);
}

/// `__pt_canvasStrokePath(id, verbsF32, lineWidth, r, g, b, a)` — stroke a path.
#[cfg(feature = "render")]
fn canvas_stroke_path(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let verbs = arg_f32s(args.get(1));
    let line_width = arg_f32(scope, args.get(2));
    let rgba = [
        arg_usize(scope, args.get(3)) as u8,
        arg_usize(scope, args.get(4)) as u8,
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
    ];
    crate::canvas::stroke_path(id, &verbs, line_width, rgba);
}

/// `__pt_canvasPutImageData(id, x, y, w, h, data)` — overwrite from straight-alpha RGBA.
#[cfg(feature = "render")]
fn canvas_put_image_data(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let x = arg_f32(scope, args.get(1)) as i32;
    let y = arg_f32(scope, args.get(2)) as i32;
    let w = arg_usize(scope, args.get(3)) as u32;
    let h = arg_usize(scope, args.get(4)) as u32;
    let data = arg_bytes(args.get(5));
    crate::canvas::put_image_data(id, x, y, w, h, &data);
}

/// `__pt_canvasGetImageData(id, x, y, w, h)` → straight-alpha RGBA `Uint8Array`.
#[cfg(feature = "render")]
fn canvas_get_image_data(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let bytes = crate::canvas::get_image_data(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
        arg_usize(scope, args.get(3)) as u32,
        arg_usize(scope, args.get(4)) as u32,
    );
    set_bytes(scope, &mut rv, &bytes);
}

// ---- WebGL (`webgl` feature) --------------------------------------------
// Each maps one WebGL call onto the headless GL backend in `crate::webgl`. GL
// object handles cross as plain numbers (0 = null). `getParameter`, extensions and
// precision stay synthesized in JS for renderer-string coherence; only the drawing
// pipeline is native.

/// `__pt_glAvailable()` → whether a real headless GL context can be created here.
#[cfg(feature = "webgl")]
fn gl_available(
    _scope: &mut v8::HandleScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_bool(crate::webgl::available());
}

/// `__pt_glCreate(id, w, h)`
#[cfg(feature = "webgl")]
fn gl_create(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::create(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glDestroy(id)`
#[cfg(feature = "webgl")]
fn gl_destroy(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::destroy(arg_usize(scope, args.get(0)) as u32);
}

/// `__pt_glClear(id, r, g, b, a, mask)`
#[cfg(feature = "webgl")]
fn gl_clear(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::clear(
        arg_usize(scope, args.get(0)) as u32,
        [
            arg_usize(scope, args.get(1)) as u8,
            arg_usize(scope, args.get(2)) as u8,
            arg_usize(scope, args.get(3)) as u8,
            arg_usize(scope, args.get(4)) as u8,
        ],
        arg_usize(scope, args.get(5)) as u32,
    );
}

/// `__pt_glViewport(id, x, y, w, h)`
#[cfg(feature = "webgl")]
fn gl_viewport(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::viewport(
        arg_usize(scope, args.get(0)) as u32,
        arg_i32(scope, args.get(1)),
        arg_i32(scope, args.get(2)),
        arg_i32(scope, args.get(3)),
        arg_i32(scope, args.get(4)),
    );
}

/// `__pt_glEnable(id, cap, on)`
#[cfg(feature = "webgl")]
fn gl_enable(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::enable(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) != 0,
    );
}

/// `__pt_glCreateShader(id, type)` → handle
#[cfg(feature = "webgl")]
fn gl_create_shader(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let h = crate::webgl::create_shader(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
    rv.set_uint32(h);
}

/// `__pt_glCompileShader(id, shader, source)`
#[cfg(feature = "webgl")]
fn gl_compile_shader(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let shader = arg_usize(scope, args.get(1)) as u32;
    let src = arg_string(scope, args.get(2));
    crate::webgl::compile_shader(id, shader, &src);
}

/// `__pt_glShaderCompiled(id, shader)` → bool
#[cfg(feature = "webgl")]
fn gl_shader_compiled(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_bool(crate::webgl::shader_compiled(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    ));
}

/// `__pt_glShaderInfoLog(id, shader)` → string
#[cfg(feature = "webgl")]
fn gl_shader_info_log(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let log = crate::webgl::shader_info_log(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
    if let Some(s) = v8::String::new(scope, &log) {
        rv.set(s.into());
    }
}

/// `__pt_glCreateProgram(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_program(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_program(
        arg_usize(scope, args.get(0)) as u32
    ));
}

/// `__pt_glAttachShader(id, program, shader)`
#[cfg(feature = "webgl")]
fn gl_attach_shader(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::attach_shader(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glLinkProgram(id, program)`
#[cfg(feature = "webgl")]
fn gl_link_program(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::link_program(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glProgramLinked(id, program)` → bool
#[cfg(feature = "webgl")]
fn gl_program_linked(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_bool(crate::webgl::program_linked(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    ));
}

/// `__pt_glUseProgram(id, program)`
#[cfg(feature = "webgl")]
fn gl_use_program(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::use_program(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glAttribLocation(id, program, name)` → i32
#[cfg(feature = "webgl")]
fn gl_attrib_location(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let program = arg_usize(scope, args.get(1)) as u32;
    let name = arg_string(scope, args.get(2));
    rv.set_int32(crate::webgl::attrib_location(id, program, &name));
}

/// `__pt_glUniformLocation(id, program, name)` → i32 (-1 = null)
#[cfg(feature = "webgl")]
fn gl_uniform_location(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let program = arg_usize(scope, args.get(1)) as u32;
    let name = arg_string(scope, args.get(2));
    rv.set_int32(crate::webgl::uniform_location(id, program, &name));
}

/// `__pt_glCreateBuffer(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_buffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_buffer(
        arg_usize(scope, args.get(0)) as u32
    ));
}

/// `__pt_glBindBuffer(id, target, buffer)`
#[cfg(feature = "webgl")]
fn gl_bind_buffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::bind_buffer(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glBufferData(id, target, data, usage)`
#[cfg(feature = "webgl")]
fn gl_buffer_data(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let target = arg_usize(scope, args.get(1)) as u32;
    let data = arg_bytes(args.get(2));
    let usage = arg_usize(scope, args.get(3)) as u32;
    crate::webgl::buffer_data(id, target, &data, usage);
}

/// `__pt_glEnableVertexAttribArray(id, index)`
#[cfg(feature = "webgl")]
fn gl_enable_vertex_attrib_array(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::enable_vertex_attrib_array(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glVertexAttribPointer(id, index, size, type, normalized, stride, offset)`
#[cfg(feature = "webgl")]
fn gl_vertex_attrib_pointer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::vertex_attrib_pointer(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_i32(scope, args.get(2)),
        arg_usize(scope, args.get(3)) as u32,
        arg_usize(scope, args.get(4)) != 0,
        arg_i32(scope, args.get(5)),
        arg_i32(scope, args.get(6)),
    );
}

/// `__pt_glUniformF(id, location, valuesF32)` — uniform{1,2,3,4}f by array length.
#[cfg(feature = "webgl")]
fn gl_uniform_f(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let loc = arg_i32(scope, args.get(1));
    let vals = arg_f32s(args.get(2));
    crate::webgl::uniform_f(id, loc, &vals);
}

/// `__pt_glUniform1i(id, location, v)`
#[cfg(feature = "webgl")]
fn gl_uniform_1i(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::uniform_1i(
        arg_usize(scope, args.get(0)) as u32,
        arg_i32(scope, args.get(1)),
        arg_i32(scope, args.get(2)),
    );
}

/// `__pt_glUniformMatrix4(id, location, transpose, valuesF32)`
#[cfg(feature = "webgl")]
fn gl_uniform_matrix4(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let loc = arg_i32(scope, args.get(1));
    let transpose = arg_usize(scope, args.get(2)) != 0;
    let vals = arg_f32s(args.get(3));
    crate::webgl::uniform_matrix4(id, loc, transpose, &vals);
}

/// `__pt_glDrawArrays(id, mode, first, count)`
#[cfg(feature = "webgl")]
fn gl_draw_arrays(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::draw_arrays(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_i32(scope, args.get(2)),
        arg_i32(scope, args.get(3)),
    );
}

/// `__pt_glDrawElements(id, mode, count, type, offset)`
#[cfg(feature = "webgl")]
fn gl_draw_elements(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::draw_elements(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_i32(scope, args.get(2)),
        arg_usize(scope, args.get(3)) as u32,
        arg_i32(scope, args.get(4)),
    );
}

/// `__pt_glReadPixels(id, x, y, w, h, flip)` → straight-alpha RGBA `Uint8Array`
/// of that rectangle of the bound framebuffer. `flip` turns GL's bottom-up rows
/// into the canvas' top-left origin (for `toDataURL`).
#[cfg(feature = "webgl")]
fn gl_read_pixels(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let bytes = crate::webgl::read_pixels(
        arg_usize(scope, args.get(0)) as u32,
        arg_i32(scope, args.get(1)),
        arg_i32(scope, args.get(2)),
        arg_i32(scope, args.get(3)),
        arg_i32(scope, args.get(4)),
        arg_usize(scope, args.get(5)) != 0,
    );
    set_bytes(scope, &mut rv, &bytes);
}

/// `__pt_glCreateTexture(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_texture(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_texture(
        arg_usize(scope, args.get(0)) as u32
    ));
}

/// `__pt_glBindTexture(id, target, texture)`
#[cfg(feature = "webgl")]
fn gl_bind_texture(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::bind_texture(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glActiveTexture(id, unit)`
#[cfg(feature = "webgl")]
fn gl_active_texture(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::active_texture(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glTexParameteri(id, target, pname, param)`
#[cfg(feature = "webgl")]
fn gl_tex_parameteri(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::tex_parameter_i(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
        arg_i32(scope, args.get(3)),
    );
}

/// `__pt_glTexImage2D(id, target, level, internalFormat, w, h, border, format,
/// type, pixels, flipY, premultiply)` — `pixels` empty means WebGL's `null`.
#[cfg(feature = "webgl")]
fn gl_tex_image_2d(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let pixels = arg_bytes(args.get(9));
    crate::webgl::tex_image_2d(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_i32(scope, args.get(2)),
        arg_i32(scope, args.get(3)),
        arg_i32(scope, args.get(4)),
        arg_i32(scope, args.get(5)),
        arg_i32(scope, args.get(6)),
        arg_usize(scope, args.get(7)) as u32,
        arg_usize(scope, args.get(8)) as u32,
        &pixels,
        arg_usize(scope, args.get(10)) != 0,
        arg_usize(scope, args.get(11)) != 0,
    );
}

/// `__pt_glTexSubImage2D(id, target, level, xoff, yoff, w, h, format, type,
/// pixels, flipY, premultiply)`
#[cfg(feature = "webgl")]
fn gl_tex_sub_image_2d(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let pixels = arg_bytes(args.get(9));
    crate::webgl::tex_sub_image_2d(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_i32(scope, args.get(2)),
        arg_i32(scope, args.get(3)),
        arg_i32(scope, args.get(4)),
        arg_i32(scope, args.get(5)),
        arg_i32(scope, args.get(6)),
        arg_usize(scope, args.get(7)) as u32,
        arg_usize(scope, args.get(8)) as u32,
        &pixels,
        arg_usize(scope, args.get(10)) != 0,
        arg_usize(scope, args.get(11)) != 0,
    );
}

/// `__pt_glGenerateMipmap(id, target)`
#[cfg(feature = "webgl")]
fn gl_generate_mipmap(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::generate_mipmap(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glCreateFramebuffer(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_framebuffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_framebuffer(
        arg_usize(scope, args.get(0)) as u32,
    ));
}

/// `__pt_glBindFramebuffer(id, target, framebuffer)` (0 = the drawing buffer)
#[cfg(feature = "webgl")]
fn gl_bind_framebuffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::bind_framebuffer(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glFramebufferTexture2D(id, target, attachment, texTarget, texture, level)`
#[cfg(feature = "webgl")]
fn gl_framebuffer_texture_2d(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::framebuffer_texture_2d(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
        arg_usize(scope, args.get(3)) as u32,
        arg_usize(scope, args.get(4)) as u32,
        arg_i32(scope, args.get(5)),
    );
}

/// `__pt_glCheckFramebufferStatus(id, target)` → enum
#[cfg(feature = "webgl")]
fn gl_check_framebuffer_status(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::check_framebuffer_status(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    ));
}

/// `__pt_glCreateRenderbuffer(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_renderbuffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_renderbuffer(
        arg_usize(scope, args.get(0)) as u32,
    ));
}

/// `__pt_glBindRenderbuffer(id, target, renderbuffer)`
#[cfg(feature = "webgl")]
fn gl_bind_renderbuffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::bind_renderbuffer(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glRenderbufferStorage(id, target, internalFormat, w, h)`
#[cfg(feature = "webgl")]
fn gl_renderbuffer_storage(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::renderbuffer_storage(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
        arg_i32(scope, args.get(3)),
        arg_i32(scope, args.get(4)),
    );
}

/// `__pt_glFramebufferRenderbuffer(id, target, attachment, rbTarget, renderbuffer)`
#[cfg(feature = "webgl")]
fn gl_framebuffer_renderbuffer(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::framebuffer_renderbuffer(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
        arg_usize(scope, args.get(3)) as u32,
        arg_usize(scope, args.get(4)) as u32,
    );
}

/// `__pt_glCreateVertexArray(id)` → handle
#[cfg(feature = "webgl")]
fn gl_create_vertex_array(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_uint32(crate::webgl::create_vertex_array(
        arg_usize(scope, args.get(0)) as u32,
    ));
}

/// `__pt_glBindVertexArray(id, vao)`
#[cfg(feature = "webgl")]
fn gl_bind_vertex_array(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::bind_vertex_array(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// `__pt_glDelete(id, kind, handle)` — one binding for every `deleteX` (see the
/// `OBJ_*` kinds in `crate::webgl`).
#[cfg(feature = "webgl")]
fn gl_delete(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::delete_object(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glBlendFunc(id, src, dst)`
#[cfg(feature = "webgl")]
fn gl_blend_func(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::blend_func(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glDepthFunc(id, func)`
#[cfg(feature = "webgl")]
fn gl_depth_func(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::depth_func(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
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
/// `__pt_makeRealm()` → the global object of a brand-new realm.
///
/// A same-origin `<iframe>` is a second window with its own untouched natives,
/// and a page reaches into it synchronously: `iframe.contentWindow.eval(…)`,
/// `contentWindow.Function`, `contentWindow.navigator`. Anti-bot code does this
/// deliberately — a fresh realm is where you compare a possibly-patched function
/// against a clean one — and Cloudflare's challenge VM dies on the spot when
/// `contentWindow` is null.
///
/// Our frames each live in their own V8 context bridged by evaluating strings,
/// which cannot answer a synchronous property read from the parent. This can: the
/// new context is created *in the same isolate*, so its global is an ordinary
/// object the caller may hold and use directly. It gets the same native bindings
/// and the same bootstrap as any other context, so it looks like the window it
/// claims to be rather than a bare V8 global.
fn make_realm(
    scope: &mut v8::HandleScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let bootstrap = match scope.get_slot::<RealmBootstrap>() {
        Some(b) => b.0.clone(),
        None => {
            rv.set_null();
            return;
        }
    };
    let context = v8::Context::new(scope, v8::ContextOptions::default());
    // Same origin, in V8's own terms: without a shared security token every
    // property read across the boundary answers "no access", which is exactly
    // what a *cross*-origin frame should do and precisely wrong for this one.
    let token = scope.get_current_context().get_security_token(scope);
    context.set_security_token(token);
    let global = context.global(scope);
    {
        let inner = &mut v8::ContextScope::new(scope, context);
        install(inner);
        let inner = &mut v8::TryCatch::new(inner);
        if let Some(src) = v8::String::new(inner, &bootstrap) {
            if let Some(script) = v8::Script::compile(inner, src, None) {
                // A realm whose bootstrap threw is still a realm; the page gets
                // what did get built rather than a null it cannot use.
                let _ = script.run(inner);
            }
        }
    }
    rv.set(global.into());
}

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

/// `__pt_hrtime()` — миллисекунды с запуска процесса, с разрешением часов
/// операционной системы.
///
/// `performance.now()` считался от `Date.now()`, а тот идёт целыми
/// миллисекундами: внутри одной задачи время не двигалось вовсе. Челлендж
/// Cloudflare меряет это в лоб — пять тысяч подряд идущих замеров и минимальная
/// положительная разница между ними; у браузера она 0.1 мс, у нас не было ни
/// одного продвижения. Отсюда и берётся настоящий монотонный источник, а
/// огрубление до браузерного шага делает уже JS.
fn hrtime(
    scope: &mut v8::HandleScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    let ms = start.elapsed().as_nanos() as f64 / 1.0e6;
    rv.set(v8::Number::new(scope, ms).into());
}
