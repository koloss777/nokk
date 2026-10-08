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

/// Pool of prebuilt realms. Building one (new context plus the whole bootstrap)
/// takes 50-90 ms, while Chrome creates an empty frame in about 1 ms. The
/// challenge inserts such frames several times and times itself, so on-demand
/// building tripled its stage times. Filled ahead, handed out instantly.
#[derive(Default)]
pub struct SpareRealms(pub Vec<v8::Global<v8::Context>>);

/// Realms pages on this isolate asked for: when last, and how many since the
/// demand began. Spares are kept in proportion and dropped when it has gone
/// quiet: each is a whole context (~8 MB), and frames that never asked kept
/// eight apiece.
pub struct RealmDemand {
    pub last: std::time::Instant,
    pub recent: usize,
}

/// When spares were built ahead of any request (a cross-origin frame
/// opening), so they expire if none comes.
pub struct RealmPrewarm(pub std::time::Instant);

/// How long realm demand counts.
pub const REALM_DEMAND_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Prebuilt worker contexts, see `Isolate::prewarm_contexts`.
#[derive(Default)]
pub struct SpareContexts(pub Vec<v8::Global<v8::Context>>);

/// Install every native binding on the current context's global object.
pub fn install(scope: &mut v8::PinScope) {
    bind(scope, "__pt_makeRealm", make_realm);
    bind(scope, "__pt_protoTemplates", proto_templates_js);
    bind(scope, "__pt_codeLike", code_like_js);
    bind(scope, "__pt_randomBytes", random_bytes);
    bind(scope, "__pt_digest", digest);
    bind(scope, "__pt_hmac", hmac_sign);
    bind(scope, "__pt_pbkdf2", pbkdf2_derive);
    bind(scope, "__pt_hkdf", hkdf_derive);
    bind(scope, "__pt_aesgcm", aes_gcm_op);
    bind(scope, "__pt_aescbc", aes_cbc_op);
    bind(scope, "__pt_pngDataUrl", png_data_url);
    bind(scope, "__pt_hrtime", hrtime);
    bind(scope, "__pt_waveTable", wave_table);
    bind(scope, "__pt_waveTableCustom", wave_table_custom);
    bind(scope, "__pt_compress", compress);
    bind(scope, "__pt_atob", atob_native);
    bind(scope, "__pt_heapStats", heap_stats);
    bind(scope, "__pt_setCodegen", set_codegen);
    bind(scope, "__pt_fnLocation", fn_location);
    bind(scope, "__pt_isBoot", fn_is_boot);
    bind(scope, "__pt_rtcStart", rtc_start);
    bind(scope, "__pt_rtcPoll", rtc_poll);

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
        bind(scope, "__pt_localFont", local_font);
        bind(scope, "__pt_canvasFillPath", canvas_fill_path);
        bind(scope, "__pt_canvasFillOps", canvas_fill_ops);
        bind(scope, "__pt_canvasFillOpsGradient", canvas_fill_ops_gradient);
        bind(scope, "__pt_canvasStrokeOps", canvas_stroke_ops);
        bind(scope, "__pt_canvasTextOps", canvas_text_ops);
        bind(
            scope,
            "__pt_canvasFillPathGradient",
            canvas_fill_path_gradient,
        );
        bind(scope, "__pt_canvasStrokePath", canvas_stroke_path);
        bind(scope, "__pt_canvasPutImageData", canvas_put_image_data);
        bind(scope, "__pt_canvasGetImageData", canvas_get_image_data);
        bind(scope, "__pt_imageBytes", image_bytes);
        bind(scope, "__pt_fsOpen", fs_open);
        bind(scope, "__pt_fsFlush", fs_flush);
        bind(scope, "__pt_fsRead", fs_read);
        bind(scope, "__pt_fsClose", fs_close);
        bind(scope, "__pt_canvasDrawImage", canvas_draw_image);
        bind(scope, "__pt_canvasBlit", canvas_blit);
    }

    // Classic page scripts run as real scripts, not via eval.
    bind(scope, "__pt_evalScript", eval_script);

    // Optional real WebGL (the `webgl` feature) — a headless Mesa GL context. Their
    // presence tells the JS WebGL context to draw for real instead of stamping.
    #[cfg(feature = "webgl")]
    {
        bind(scope, "__pt_glAvailable", gl_available);
        bind(scope, "__pt_glCreate", gl_create);
        bind(scope, "__pt_glDestroy", gl_destroy);
        bind(scope, "__pt_glResize", gl_resize);
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
fn arg_f32(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> f32 {
    value.number_value(scope).unwrap_or(0.0) as f32
}

#[cfg(feature = "webgl")]
fn arg_i32(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> i32 {
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::canvas::destroy(arg_usize(scope, args.get(0)) as u32);
}

/// `__pt_canvasFillRect(id, x, y, w, h, r, g, b, a)`
#[cfg(feature = "render")]
fn canvas_fill_rect(
    scope: &mut v8::PinScope,
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
    crate::canvas::fill_rect(id, x, y, w, h, rgba, &arg_f32s(args.get(9)),
        arg_usize(scope, args.get(10)) as u32);
}

/// `__pt_canvasClearRect(id, x, y, w, h)`
#[cfg(feature = "render")]
fn canvas_clear_rect(
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    let families = arg_string(scope, args.get(9));
    let bold = args.get(10).boolean_value(scope);
    let italic = args.get(11).boolean_value(scope);
    crate::canvas::fill_text(id, &text, x, y, size, rgba, &families, bold, italic,
        &arg_f32s(args.get(12)));
}

/// `__pt_canvasTextOps(id, text, x, y, ctmF32, size, families, bold, italic,
/// stroke, lineWidth, r, g, b, a, gradF32, shF32, mode, align, baseline, cap, join, miter)` → bool.
#[cfg(feature = "render")]
fn canvas_text_ops(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let text = arg_string(scope, args.get(1));
    let (x, y) = (arg_f32(scope, args.get(2)), arg_f32(scope, args.get(3)));
    let m = arg_f32s(args.get(4));
    let mut ctm = [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0];
    if m.len() >= 6 {
        ctm.copy_from_slice(&m[..6]);
    }
    let size = arg_f32(scope, args.get(5));
    let families = arg_string(scope, args.get(6));
    let bold = args.get(7).boolean_value(scope);
    let italic = args.get(8).boolean_value(scope);
    let stroke = args.get(9).boolean_value(scope);
    let lw = arg_f32(scope, args.get(10));
    let rgba = [
        arg_usize(scope, args.get(11)) as u8,
        arg_usize(scope, args.get(12)) as u8,
        arg_usize(scope, args.get(13)) as u8,
        arg_usize(scope, args.get(14)) as u8,
    ];
    let grad = arg_f32s(args.get(15));
    let sh = arg_f32s(args.get(16));
    let mode = arg_usize(scope, args.get(17)) as u32;
    let align = arg_usize(scope, args.get(18)) as u32;
    let baseline = arg_usize(scope, args.get(19)) as u32;
    let line = crate::skia::LineStyle::from_codes(lw, arg_usize(scope, args.get(20)) as u32,
        arg_usize(scope, args.get(21)) as u32, arg_f32(scope, args.get(22)));
    let ok = crate::canvas::text_ops(id, &text, x, y, ctm, size, &families, bold, italic, stroke, &line, rgba, &grad, &sh, mode, align, baseline);
    rv.set_bool(ok);
}

/// `__pt_localFont(name)`: whether a system font with this name exists.
#[cfg(feature = "render")]
fn local_font(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let name = arg_string(scope, args.get(0));
    rv.set_bool(crate::canvas::has_local_font(&name));
}

/// `__pt_canvasMeasureText(text, size)` → advance width in CSS px (a number).
#[cfg(feature = "render")]
fn canvas_measure_text(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let text = arg_string(scope, args.get(0));
    let size = arg_f32(scope, args.get(1));
    let families = arg_string(scope, args.get(2));
    let bold = args.get(3).boolean_value(scope);
    let italic = args.get(4).boolean_value(scope);
    let m = crate::canvas::measure_text(&text, size, &families, bold, italic);
    let out = v8::Array::new(scope, 8);
    for (i, v) in [
        m.width,
        m.left,
        m.right,
        m.ascent,
        m.descent,
        m.font_ascent,
        m.font_descent,
        m.line,
    ]
        .into_iter()
        .enumerate()
    {
        let n = v8::Number::new(scope, v as f64);
        out.set_index(scope, i as u32, n.into());
    }
    rv.set(out.into());
}

/// `__pt_canvasFillPath(id, verbsF32, evenOdd, r, g, b, a)` — fill a tessellated path.
#[cfg(feature = "render")]
fn canvas_fill_path(
    scope: &mut v8::PinScope,
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
    crate::canvas::fill_path(id, &verbs, even_odd, rgba, &arg_f32s(args.get(7)),
        arg_usize(scope, args.get(8)) as u32);
}

/// `__pt_canvasFillOps(id, opsF32, ctmF32, evenOdd, r, g, b, a, shF32, mode)` —
/// fill from path ops (page coordinates) and the canvas matrix.
#[cfg(feature = "render")]
fn canvas_fill_ops(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let ops = arg_f32s(args.get(1));
    let m = arg_f32s(args.get(2));
    let mut ctm = [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0];
    if m.len() >= 6 {
        ctm.copy_from_slice(&m[..6]);
    }
    let even_odd = arg_usize(scope, args.get(3)) != 0;
    let rgba = [
        arg_usize(scope, args.get(4)) as u8,
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
        arg_usize(scope, args.get(7)) as u8,
    ];
    crate::canvas::fill_ops(id, &ops, ctm, even_odd, rgba, &arg_f32s(args.get(8)),
        arg_usize(scope, args.get(9)) as u32);
}

/// `__pt_canvasFillOpsGradient(id, opsF32, ctmF32, evenOdd, gradF32, shF32, mode)`.
#[cfg(feature = "render")]
fn canvas_fill_ops_gradient(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let ops = arg_f32s(args.get(1));
    let m = arg_f32s(args.get(2));
    let mut ctm = [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0];
    if m.len() >= 6 {
        ctm.copy_from_slice(&m[..6]);
    }
    let even_odd = arg_usize(scope, args.get(3)) != 0;
    let grad = arg_f32s(args.get(4));
    crate::canvas::fill_ops_grad(id, &ops, ctm, even_odd, &grad, &arg_f32s(args.get(5)),
        arg_usize(scope, args.get(6)) as u32);
}

/// `__pt_canvasStrokeOps(id, opsF32, ctmF32, lineWidth, r, g, b, a, gradF32, shF32, mode)` → bool.
#[cfg(feature = "render")]
fn canvas_stroke_ops(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let ops = arg_f32s(args.get(1));
    let m = arg_f32s(args.get(2));
    let mut ctm = [1.0f32, 0.0, 0.0, 1.0, 0.0, 0.0];
    if m.len() >= 6 {
        ctm.copy_from_slice(&m[..6]);
    }
    let lw = arg_f32(scope, args.get(3));
    let rgba = [
        arg_usize(scope, args.get(4)) as u8,
        arg_usize(scope, args.get(5)) as u8,
        arg_usize(scope, args.get(6)) as u8,
        arg_usize(scope, args.get(7)) as u8,
    ];
    let grad = arg_f32s(args.get(8));
    let line = crate::skia::LineStyle::from_codes(lw, arg_usize(scope, args.get(11)) as u32,
        arg_usize(scope, args.get(12)) as u32, arg_f32(scope, args.get(13)));
    let ok = crate::canvas::stroke_ops(id, &ops, ctm, &line, rgba, &grad, &arg_f32s(args.get(9)),
        arg_usize(scope, args.get(10)) as u32);
    rv.set_bool(ok);
}

/// `__pt_canvasFillPathGradient(id, verbsF32, evenOdd, gradF32)` — gradient fill.
#[cfg(feature = "render")]
fn canvas_fill_path_gradient(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let verbs = arg_f32s(args.get(1));
    let even_odd = arg_usize(scope, args.get(2)) != 0;
    let grad = arg_f32s(args.get(3));
    crate::canvas::fill_path_grad(id, &verbs, even_odd, &grad, &arg_f32s(args.get(4)),
        arg_usize(scope, args.get(5)) as u32);
}

/// `__pt_canvasStrokePath(id, verbsF32, lineWidth, r, g, b, a, shadowF32)` — stroke a path.
#[cfg(feature = "render")]
fn canvas_stroke_path(
    scope: &mut v8::PinScope,
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
    crate::canvas::stroke_path(id, &verbs, line_width, rgba, &arg_f32s(args.get(7)),
        arg_usize(scope, args.get(8)) as u32);
}

/// `__pt_canvasPutImageData(id, x, y, w, h, data)` — overwrite from straight-alpha RGBA.
#[cfg(feature = "render")]
fn canvas_put_image_data(
    scope: &mut v8::PinScope,
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

/// `__pt_imageBytes(url, base64)` — hand an image's encoded bytes to the
/// rasterizer, which decodes and keeps them under that address.
///
/// The body of a fetched image reaches JS as lossy text, so the pixels can only
/// travel this way: base64 in, decoded RGBA kept in Rust. Answers the image's
/// size, or 0 when the format is one we do not decode.
#[cfg(feature = "render")]
fn image_bytes(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let url = arg_string(scope, args.get(0));
    let b64 = arg_string(scope, args.get(1));
    let Ok(bytes) = base64_decode(&b64) else {
        rv.set_uint32(0);
        return;
    };
    match crate::canvas::remember_image(&url, &bytes) {
        Some((w, h)) => rv.set_uint32(w << 16 | (h & 0xffff)),
        None => rv.set_uint32(0),
    }
}

/// `__pt_canvasDrawImage(id, url, dx, dy, dw, dh)` → true when it was drawn.
#[cfg(feature = "render")]
fn canvas_draw_image(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let url = arg_string(scope, args.get(1));
    let dx = arg_f32(scope, args.get(2));
    let dy = arg_f32(scope, args.get(3));
    let dw = arg_f32(scope, args.get(4));
    let dh = arg_f32(scope, args.get(5));
    rv.set_bool(crate::canvas::draw_image(id, &url, dx, dy, dw, dh));
}

/// `__pt_canvasBlit(dstId, srcId, sx, sy, sw, sh, dx, dy, dw, dh)` → true when drawn.
#[cfg(feature = "render")]
fn canvas_blit(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let dst = arg_usize(scope, args.get(0)) as u32;
    let src = arg_usize(scope, args.get(1)) as u32;
    let sx = arg_f32(scope, args.get(2));
    let sy = arg_f32(scope, args.get(3));
    let sw = arg_f32(scope, args.get(4));
    let sh = arg_f32(scope, args.get(5));
    let dx = arg_f32(scope, args.get(6));
    let dy = arg_f32(scope, args.get(7));
    let dw = arg_f32(scope, args.get(8));
    let dh = arg_f32(scope, args.get(9));
    rv.set_bool(crate::canvas::blit(dst, src, sx, sy, sw, sh, dx, dy, dw, dh));
}

/// Standard base64, decoded here so no crate feature has to reach the isolate.
#[cfg(feature = "render")]
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| ())
}

/// Real files behind OPFS.
///
/// The tree lives in memory, but the challenge times `flush()`: in Chrome it is
/// a disk write plus wait, about 4 ms, and a no-op costing zero is obvious.
/// So a sync handle keeps a temp file: content stays in memory, `flush`
/// actually writes it to disk.
#[cfg(feature = "render")]
mod opfs {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    thread_local! {
        static FILES: RefCell<HashMap<u32, File>> = RefCell::new(HashMap::new());
        static NEXT: RefCell<u32> = const { RefCell::new(0) };
    }

    /// One directory per process under the temp dir. The file name comes from
    /// the key with non-alphanumerics replaced, since the path comes from the page.
    fn path_for(key: &str) -> std::path::PathBuf {
        let safe: String = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(80)
            .collect();
        let dir = std::env::temp_dir().join(format!("nokk-opfs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(safe)
    }

    pub fn open(key: &str) -> u32 {
        let Ok(file) = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path_for(key))
        else {
            return 0;
        };
        NEXT.with(|n| {
            let mut n = n.borrow_mut();
            *n += 1;
            let id = *n;
            FILES.with(|f| f.borrow_mut().insert(id, file));
            id
        })
    }

    /// Write and sync to disk: the milliseconds Chrome pays.
    pub fn flush(id: u32, bytes: &[u8]) -> bool {
        FILES.with(|f| {
            let mut map = f.borrow_mut();
            let Some(file) = map.get_mut(&id) else {
                return false;
            };
            if file.seek(SeekFrom::Start(0)).is_err() {
                return false;
            }
            if file.write_all(bytes).is_err() {
                return false;
            }
            // Truncate only when the length changed, and sync data without
            // metadata: Chrome's `flush` costs ~4 ms, a full `sync_all` is three
            // times that.
            if file.metadata().map(|m| m.len()).unwrap_or(0) != bytes.len() as u64 {
                let _ = file.set_len(bytes.len() as u64);
            }
            file.sync_data().is_ok()
        })
    }

    pub fn read_all(id: u32) -> Vec<u8> {
        FILES.with(|f| {
            let mut map = f.borrow_mut();
            let Some(file) = map.get_mut(&id) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            if file.seek(SeekFrom::Start(0)).is_err() {
                return Vec::new();
            }
            let _ = file.read_to_end(&mut out);
            out
        })
    }

    pub fn close(id: u32) {
        FILES.with(|f| f.borrow_mut().remove(&id));
    }
}

/// `__pt_fsOpen(key)` → handle, or 0 when the file could not be opened.
#[cfg(feature = "render")]
fn fs_open(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let key = arg_string(scope, args.get(0));
    rv.set_uint32(opfs::open(&key));
}

/// `__pt_fsFlush(handle, bytes)` → true when the bytes reached the disk.
#[cfg(feature = "render")]
fn fs_flush(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let bytes = arg_bytes(args.get(1));
    rv.set_bool(opfs::flush(id, &bytes));
}

/// `__pt_fsRead(handle)` → everything the file holds.
#[cfg(feature = "render")]
fn fs_read(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = arg_usize(scope, args.get(0)) as u32;
    let bytes = opfs::read_all(id);
    set_bytes(scope, &mut rv, &bytes);
}

/// `__pt_fsClose(handle)`
#[cfg(feature = "render")]
fn fs_close(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    opfs::close(arg_usize(scope, args.get(0)) as u32);
}

/// `__pt_canvasGetImageData(id, x, y, w, h)` → straight-alpha RGBA `Uint8Array`.
#[cfg(feature = "render")]
fn canvas_get_image_data(
    scope: &mut v8::PinScope,
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
    _scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    rv.set_bool(crate::webgl::available());
}

/// `__pt_glCreate(id, w, h)`
#[cfg(feature = "webgl")]
fn gl_create(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::create(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glResize(id, w, h)`: canvas resized, drawing buffer follows.
#[cfg(feature = "webgl")]
fn gl_resize(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::resize(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
        arg_usize(scope, args.get(2)) as u32,
    );
}

/// `__pt_glDestroy(id)`
#[cfg(feature = "webgl")]
fn gl_destroy(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::destroy(arg_usize(scope, args.get(0)) as u32);
}

/// `__pt_glClear(id, r, g, b, a, mask)`
#[cfg(feature = "webgl")]
fn gl_clear(
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    crate::webgl::depth_func(
        arg_usize(scope, args.get(0)) as u32,
        arg_usize(scope, args.get(1)) as u32,
    );
}

/// Pointers of all native callbacks in first-install order: the external
/// references list for the V8 snapshot (same at creation and restore: same
/// process, same addresses).
static NATIVE_REFS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// Frozen external references list (after the first full install).
struct RefsSlice(&'static [v8::ExternalReference]);
// Function addresses only, constant for the process lifetime.
unsafe impl Send for RefsSlice {}
unsafe impl Sync for RefsSlice {}

pub fn external_refs() -> std::borrow::Cow<'static, [v8::ExternalReference]> {
    static REFS: std::sync::OnceLock<RefsSlice> = std::sync::OnceLock::new();
    let v = REFS.get_or_init(|| {
        let ptrs = NATIVE_REFS.lock().map(|v| v.clone()).unwrap_or_default();
        let list: Vec<v8::ExternalReference> = ptrs
            .into_iter()
            .map(|p| v8::ExternalReference { function: unsafe { std::mem::transmute::<usize, v8::FunctionCallback>(p) } })
            .chain(std::iter::once(v8::ExternalReference { pointer: std::ptr::null_mut() }))
            .collect();
        RefsSlice(Box::leak(list.into_boxed_slice()))
    });
    std::borrow::Cow::Borrowed(v.0)
}

fn bind(scope: &mut v8::PinScope, name: &str, cb: impl v8::MapFnTo<v8::FunctionCallback>) {
    let global = scope.get_current_context().global(scope);
    let Some(key) = v8::String::new(scope, name) else {
        return;
    };
    let raw: v8::FunctionCallback = cb.map_fn_to();
    if let Ok(mut v) = NATIVE_REFS.lock() {
        let p = raw as usize;
        if !v.contains(&p) {
            v.push(p);
        }
    }
    let tmpl = v8::FunctionTemplate::new_raw(scope, raw);
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

fn arg_string(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> String {
    value.to_rust_string_lossy(scope)
}

fn arg_usize(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> usize {
    value.integer_value(scope).unwrap_or(0).max(0) as usize
}

/// Return numbers to JS as a `Float32Array`.
fn set_floats(scope: &mut v8::PinScope, rv: &mut v8::ReturnValue, values: &[f32]) {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for v in values {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    let n = values.len();
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
    let buf = v8::ArrayBuffer::with_backing_store(scope, &store);
    match v8::Float32Array::new(scope, buf, 0, n) {
        Some(arr) => rv.set(arr.into()),
        None => rv.set_null(),
    }
}

/// Read a `Float32Array` (or a plain number array) from an argument.
fn arg_floats(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> Vec<f32> {
    if let Ok(arr) = v8::Local::<v8::Array>::try_from(value) {
        let n = arr.length() as usize;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let v = arr
                .get_index(scope, i as u32)
                .and_then(|x| x.number_value(scope))
                .unwrap_or(0.0);
            out.push(v as f32);
        }
        return out;
    }
    let bytes = arg_bytes(value);
    bytes
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect()
}

/// `__pt_waveTable(shape, sampleRate, rangeIndex)`: wavetable for a built-in
/// shape, bit-exact with the browser's.
fn wave_table(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let shape = arg_string(scope, args.get(0));
    let rate = arg_f32_any(scope, args.get(1));
    let range = arg_usize(scope, args.get(2));
    let table = crate::wavetable::basic_table(&shape, rate, range);
    set_floats(scope, &mut rv, &table);
}

/// `__pt_waveTableCustom(real, imag, sampleRate, rangeIndex, disableNormalization)`
/// - the same for a page-defined shape from `createPeriodicWave`.
fn wave_table_custom(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let real = arg_floats(scope, args.get(0));
    let imag = arg_floats(scope, args.get(1));
    let rate = arg_f32_any(scope, args.get(2));
    let range = arg_usize(scope, args.get(3));
    let plain = args.get(4).boolean_value(scope);
    let table = crate::wavetable::custom_table(&real, &imag, rate, range, plain);
    set_floats(scope, &mut rv, &table);
}

/// `__pt_compress(samples, rate, threshold, knee, ratio, attack, release)` —
/// dynamics compressor. Returns the samples, with the `reduction` reading the
/// page sees on the node as the last number.
fn compress(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let input = arg_floats(scope, args.get(0));
    let rate = arg_f32_any(scope, args.get(1));
    let out = crate::compressor::process(
        &input,
        rate,
        arg_f32_any(scope, args.get(2)),
        arg_f32_any(scope, args.get(3)),
        arg_f32_any(scope, args.get(4)),
        arg_f32_any(scope, args.get(5)),
        arg_f32_any(scope, args.get(6)),
    );
    let mut all = out.samples;
    all.push(out.reduction);
    set_floats(scope, &mut rv, &all);
}

/// `__pt_atob(s)`: forgiving base64 decode per the HTML spec (ASCII whitespace
/// dropped, up to two trailing `=`, extra tail bits ignored). Returns a
/// byte-per-char string, or `null` if the input is not base64 (the wrapper then
/// throws the browser error). Native because the challenge decodes about a
/// megabyte this way, and the JS loop took 80 ms over three calls.
fn atob_native(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    use base64::Engine as _;
    let Some(text) = args.get(0).to_string(scope) else {
        rv.set_null();
        return;
    };
    let raw = text.to_rust_string_lossy(scope);
    let mut body: Vec<u8> = raw
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r'))
        .collect();
    if body.len() % 4 == 0 {
        for _ in 0..2 {
            if body.last() == Some(&b'=') {
                body.pop();
            }
        }
    }
    if body.len() % 4 == 1
        || body.iter().any(|b| !(b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'))
    {
        rv.set_null();
        return;
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    match engine.decode(&body) {
        Ok(bytes) => match v8::String::new_from_one_byte(scope, &bytes, v8::NewStringType::Normal) {
            Some(out) => rv.set(out.into()),
            None => rv.set_null(),
        },
        Err(_) => rv.set_null(),
    }
}

/// Number from an argument, regardless of the `render` feature.
fn arg_f32_any(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> f32 {
    value.number_value(scope).unwrap_or(0.0) as f32
}

/// Return `bytes` to JS as a `Uint8Array`.
fn set_bytes(scope: &mut v8::PinScope, rv: &mut v8::ReturnValue, bytes: &[u8]) {
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
    scope: &mut v8::PinScope,
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
    // Demand is marked by the pool's presence: where it exists, it is refilled.
    if scope.get_slot::<SpareRealms>().is_none() {
        scope.set_slot(SpareRealms::default());
    }
    let recent = scope
        .get_slot::<RealmDemand>()
        .filter(|d| d.last.elapsed() <= REALM_DEMAND_TTL)
        .map_or(0, |d| d.recent);
    scope.set_slot(RealmDemand { last: std::time::Instant::now(), recent: recent + 1 });
    let spare = scope.get_slot_mut::<SpareRealms>().and_then(|s| s.0.pop());
    tracing::debug!(target: "nokk::realm", from_spare = spare.is_some(), "a page asked for a fresh realm");
    if let Some(ready) = spare {
        let context = v8::Local::new(scope, &ready);
        let token = scope.get_current_context().get_security_token(scope);
        context.set_security_token(token);
        let global = context.global(scope);
        {
            let inner = &mut v8::ContextScope::new(scope, context);
            v8::tc_scope!(inner, inner);
            // The new window's clock starts when handed out, not when built.
            if let Some(src) = v8::String::new(inner, "globalThis.__pt_resetClock && __pt_resetClock()") {
                if let Some(script) = v8::Script::compile(inner, src, None) {
                    let _ = script.run(inner);
                }
            }
        }
        rv.set(global.into());
        return;
    }
    let snapped = if crate::isolate::snapshot_matches(&bootstrap) {
        v8::Context::from_snapshot(scope, 0, v8::ContextOptions::default())
    } else {
        None
    };
    let from_snapshot = snapped.is_some();
    let context = snapped.unwrap_or_else(|| new_page_context(scope));
    // Same origin, in V8's own terms: without a shared security token every
    // property read across the boundary answers "no access", which is exactly
    // what a *cross*-origin frame should do and precisely wrong for this one.
    let token = scope.get_current_context().get_security_token(scope);
    context.set_security_token(token);
    let global = context.global(scope);
    {
        let inner = &mut v8::ContextScope::new(scope, context);
        if from_snapshot {
            v8::tc_scope!(inner, inner);
            if let Some(src) = v8::String::new(inner, crate::isolate::AFTER_SNAPSHOT) {
                if let Some(script) = v8::Script::compile(inner, src, None) {
                    let _ = script.run(inner);
                }
            }
            rv.set(global.into());
            return;
        }
        install(inner);
        v8::tc_scope!(inner, inner);
        let t0 = std::time::Instant::now();
        if let Some(src) = v8::String::new(inner, &bootstrap) {
            if let Some(script) = v8::Script::compile(inner, src, None) {
                let compiled = t0.elapsed();
                // A realm whose bootstrap threw is still a realm; the page gets
                // what did get built rather than a null it cannot use.
                let _ = script.run(inner);
                tracing::debug!(target: "nokk::build", kind = "realm on demand", ms = t0.elapsed().as_millis() as u64, thread = ?std::thread::current().name(), "context built");
            }
        }
    }
    rv.set(global.into());
}

/// `__pt_evalScript(code, url)`: run a classic page script the way Chrome
/// does, as a real script with its own source, not via `eval`. Under `eval` V8
/// tags every stack frame with "eval at <caller>", exposing our internal name.
fn eval_script(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let code = arg_string(scope, args.get(0));
    let url = arg_string(scope, args.get(1));
    // Document line where the inline script starts: Chrome counts stack and
    // CSP violation lines from the start of the markup, not from `<script>`.
    let line_offset = args.get(2).int32_value(scope).unwrap_or(0).max(0);
    tracing::debug!(target: "nokk::script", bytes = code.len(), url = %url, "inline script");
    let Some(src) = v8::String::new(scope, &code) else {
        return;
    };
    let Some(name) = v8::String::new(scope, &url) else {
        return;
    };
    let origin = v8::ScriptOrigin::new(
        scope,
        name.into(),
        line_offset,
        0,
        false,
        0,
        None,
        false,
        false,
        false,
        None,
    );
    let mut source = v8::script_compiler::Source::new(src, Some(&origin));
    let Some(script) = v8::script_compiler::compile(
        scope,
        &mut source,
        v8::script_compiler::CompileOptions::NoCompileOptions,
        v8::script_compiler::NoCacheReason::NoReason,
    ) else {
        return;
    };
    if let Some(v) = script.run(scope) {
        rv.set(v);
    }
}

fn random_bytes(
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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
    scope: &mut v8::PinScope,
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

/// V8 heap usage: used, total, limit. In Chrome `performance.memory` grows as
/// the page allocates, so it must not be three constants.
fn heap_stats(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let st = scope.get_heap_statistics();
    let out = v8::Array::new(scope, 3);
    for (i, v) in [st.used_heap_size(), st.total_heap_size(), st.heap_size_limit()]
        .into_iter()
        .enumerate()
    {
        let n = v8::Number::new(scope, v as f64);
        out.set_index(scope, i as u32, n.into());
    }
    rv.set(out.into());
}

// --- WebRTC: real sockets and STUN ---------------------------------------
//
// For each offer section Chrome opens a UDP socket per address family (host
// candidates: their ports, under mDNS names) and sends a STUN Binding to the
// configured servers; the XOR-MAPPED-ADDRESS reply becomes the srflx candidate
// with the public address. stun.cloudflare.com belongs to the same party that
// checks the report, so the request must be real.

struct RtcJob {
    results: Vec<(u8, usize, String, u16)>,
    done: bool,
}

fn rtc_jobs() -> &'static std::sync::Mutex<std::collections::HashMap<u32, RtcJob>> {
    static JOBS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u32, RtcJob>>> = std::sync::OnceLock::new();
    JOBS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn stun_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0] = 0x00;
    m[1] = 0x01; // Binding Request
    m[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    m[8..20].copy_from_slice(txid);
    m
}

fn stun_mapped(buf: &[u8], txid: &[u8; 12]) -> Option<(String, u16)> {
    if buf.len() < 20 || buf[0] != 0x01 || buf[1] != 0x01 || &buf[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut i = 20;
    let end = (20 + len).min(buf.len());
    let cookie = 0x2112A442u32.to_be_bytes();
    while i + 4 <= end {
        let t = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let l = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let v = &buf[(i + 4).min(end)..(i + 4 + l).min(end)];
        if (t == 0x0020 || t == 0x0001) && v.len() >= 8 {
            let xor = t == 0x0020;
            let port = u16::from_be_bytes([v[2], v[3]]) ^ if xor { 0x2112 } else { 0 };
            if v[1] == 0x01 && v.len() >= 8 {
                let mut a = [v[4], v[5], v[6], v[7]];
                if xor {
                    for k in 0..4 {
                        a[k] ^= cookie[k];
                    }
                }
                return Some((std::net::Ipv4Addr::from(a).to_string(), port));
            }
            if v[1] == 0x02 && v.len() >= 20 {
                let mut a = [0u8; 16];
                a.copy_from_slice(&v[4..20]);
                if xor {
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&cookie);
                    key[4..].copy_from_slice(txid);
                    for k in 0..16 {
                        a[k] ^= key[k];
                    }
                }
                return Some((std::net::Ipv6Addr::from(a).to_string(), port));
            }
        }
        i += 4 + ((l + 3) & !3);
    }
    None
}

/// `__pt_rtcStart(n, serversJson)` -> `{"id","v4":[ports],"v6":[ports]}`:
/// open `n` sockets per family and query STUN in the background.
fn rtc_start(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    use std::net::{ToSocketAddrs, UdpSocket};
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let n = args.get(0).int32_value(scope).unwrap_or(1).clamp(1, 8) as usize;
    let servers: Vec<String> = serde_json::from_str(&arg_string(scope, args.get(1))).unwrap_or_default();
    let mut v4: Vec<UdpSocket> = Vec::new();
    let mut v6: Vec<UdpSocket> = Vec::new();
    for _ in 0..n {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            v4.push(s);
        }
    }
    // IPv6 only with an outbound route (as in Chrome: a v6 host candidate
    // exists only with a global address).
    let has6 = UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2606:4700:4700::1111]:53").map(|_| s))
        .is_ok();
    if has6 {
        for _ in 0..n {
            if let Ok(s) = UdpSocket::bind("[::]:0") {
                v6.push(s);
            }
        }
    }
    let ports = |v: &Vec<UdpSocket>| v.iter().map(|s| s.local_addr().map(|a| a.port()).unwrap_or(0)).collect::<Vec<_>>();
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let out = serde_json::json!({ "id": id, "v4": ports(&v4), "v6": ports(&v6) }).to_string();
    if let Ok(mut m) = rtc_jobs().lock() {
        m.insert(id, RtcJob { results: Vec::new(), done: false });
    }
    let off = std::env::var_os("NOKK_NO_STUN").is_some() || servers.is_empty();
    std::thread::spawn(move || {
        if !off {
            let mut socks: Vec<(u8, usize, UdpSocket)> = Vec::new();
            for (i, s) in v4.into_iter().enumerate() {
                socks.push((4, i, s));
            }
            for (i, s) in v6.into_iter().enumerate() {
                socks.push((6, i, s));
            }
            // Server addresses per family.
            let mut addrs4 = Vec::new();
            let mut addrs6 = Vec::new();
            for srv in &servers {
                if let Ok(it) = srv.to_socket_addrs() {
                    for a in it {
                        if a.is_ipv4() { addrs4.push(a) } else { addrs6.push(a) }
                    }
                }
            }
            let mut pending: Vec<(u8, usize, UdpSocket, [u8; 12])> = Vec::new();
            for (fam, i, s) in socks {
                let mut tx = [0u8; 12];
                for (k, b) in tx.iter_mut().enumerate() {
                    *b = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) >> (k % 4 * 8)) as u8 ^ (i as u8).wrapping_mul(31) ^ (k as u8).wrapping_mul(97) ^ fam;
                }
                let targets = if fam == 4 { &addrs4 } else { &addrs6 };
                for t in targets.iter() {
                    let _ = s.send_to(&stun_request(&tx), t);
                }
                let _ = s.set_nonblocking(true);
                pending.push((fam, i, s, tx));
            }
            let start = std::time::Instant::now();
            let mut buf = [0u8; 1500];
            while !pending.is_empty() && start.elapsed() < std::time::Duration::from_millis(1500) {
                let mut k = 0;
                while k < pending.len() {
                    let mut got = None;
                    if let Ok((n, _)) = pending[k].2.recv_from(&mut buf) {
                        got = stun_mapped(&buf[..n], &pending[k].3);
                    }
                    if let Some((ip, port)) = got {
                        let (fam, i, _, _) = pending.remove(k);
                        if let Ok(mut m) = rtc_jobs().lock() {
                            if let Some(j) = m.get_mut(&id) {
                                j.results.push((fam, i, ip, port));
                            }
                        }
                    } else {
                        k += 1;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        if let Ok(mut m) = rtc_jobs().lock() {
            if let Some(j) = m.get_mut(&id) {
                j.done = true;
            }
        }
    });
    if let Some(s) = v8::String::new(scope, &out) {
        rv.set(s.into());
    }
}

/// `__pt_rtcPoll(id)` -> `{"r":[[family,index,address,port]...],"done"}`:
/// STUN replies received since the last poll.
fn rtc_poll(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let id = args.get(0).uint32_value(scope).unwrap_or(0);
    let (r, done) = match rtc_jobs().lock() {
        Ok(mut m) => match m.get_mut(&id) {
            Some(j) => {
                let r: Vec<_> = j.results.drain(..).collect();
                let done = j.done;
                if done {
                    m.remove(&id);
                }
                (r, done)
            }
            None => (Vec::new(), true),
        },
        Err(_) => (Vec::new(), true),
    };
    let out = serde_json::json!({ "r": r, "done": done }).to_string();
    if let Some(s) = v8::String::new(scope, &out) {
        rv.set(s.into());
    }
}

/// `__pt_fnLocation(fn)` -> `[resource name, line, column]` (zero-based) or
/// null: where a function starts in its source, for long-animation-frame
/// entries (sourceURL / sourceCharPosition of PerformanceScriptTiming).
fn fn_location(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let Ok(f) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        rv.set_null();
        return;
    };
    let line = f.get_script_line_number();
    let col = f.get_script_column_number();
    let origin = f.get_script_origin(scope);
    let name = origin.resource_name();
    let arr = v8::Array::new(scope, 3);
    let n: v8::Local<v8::Value> = match name {
        Some(v) if v.is_string() => v,
        _ => v8::String::empty(scope).into(),
    };
    arr.set_index(scope, 0, n);
    let l = v8::Integer::new(scope, line.map(|x| x as i32).unwrap_or(-1));
    arr.set_index(scope, 1, l.into());
    let c = v8::Integer::new(scope, col.map(|x| x as i32).unwrap_or(-1));
    arr.set_index(scope, 2, c.into());
    rv.set(arr.into());
}

/// The bootstrap's source map URL: it marks the loader's script in every
/// context (snapshot, realm, worker) without a per-function registry.
pub const BOOT_SCRIPT_MARK: &str = "nokk:boot";

/// `__pt_isBoot(fn)`: whether `fn` was compiled from the bootstrap, in any
/// context of this isolate. Such functions are the engine's and read as native.
fn fn_is_boot(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let Ok(f) = v8::Local::<v8::Function>::try_from(args.get(0)) else {
        rv.set_bool(false);
        return;
    };
    let origin = f.get_script_origin(scope);
    let boot = origin
        .source_map_url()
        .filter(|v| v.is_string())
        .is_some_and(|v| v.to_rust_string_lossy(scope) == BOOT_SCRIPT_MARK);
    rv.set_bool(boot);
}

/// `__pt_setCodegen(allowed)`: whether this context may generate code from
/// strings (`eval`, `Function`). When disallowed V8 calls our source-modifying
/// hook (`modify_codegen` in isolate.rs), so CSP without 'unsafe-eval' throws
/// Chrome's EvalError text even for direct `eval`.
fn set_codegen(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let allowed = args.get(0).boolean_value(scope);
    let context = scope.get_current_context();
    context.set_allow_generation_from_strings(allowed);
}

/// `__pt_hrtime()`: milliseconds since process start at OS clock resolution.
///
/// Deriving `performance.now()` from `Date.now()` froze time within a task.
/// Cloudflare takes 5000 consecutive readings and checks the minimum positive
/// delta (0.1 ms in Chrome). Hence a real monotonic source; JS coarsens it to
/// the browser's step.
fn hrtime(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    let ms = start.elapsed().as_nanos() as f64 / 1.0e6;
    rv.set(v8::Number::new(scope, ms).into());
}

// ---- immutable prototypes ---------------------------------------------
//
// In Chrome the prototype of window, Window.prototype, WindowProperties,
// EventTarget.prototype, location and Location.prototype cannot be changed:
// `Object.setPrototypeOf` throws "Immutable prototype object '#<Window>' cannot
// have their prototype set" but accepts the same prototype silently. The
// challenge's graph walk (section oebe1) checks this on every object. JS cannot
// make such objects; only V8 templates can, as Blink does: prototypes come from
// the FunctionTemplate chain (EventTarget <- WindowProperties <- Window), the
// global from Window's instance template.

struct ProtoTemplates {
    et: v8::Global<v8::FunctionTemplate>,
    wp: v8::Global<v8::FunctionTemplate>,
    w: v8::Global<v8::FunctionTemplate>,
    loc: v8::Global<v8::FunctionTemplate>,
}

fn note_ref(p: usize) {
    if let Ok(mut v) = NATIVE_REFS.lock() {
        if !v.contains(&p) {
            v.push(p);
        }
    }
}

/// Template functions are not visible to the page (interfaces have their own
/// facades) but must not be constructible.
fn template_ctor(scope: &mut v8::PinScope, _args: v8::FunctionCallbackArguments, _rv: v8::ReturnValue) {
    if let Some(msg) = v8::String::new(scope, "Illegal constructor") {
        let err = v8::Exception::type_error(scope, msg);
        scope.throw_exception(err);
    }
}

/// Chrome's WindowProperties is a named-properties object: own properties
/// cannot be defined on it ("Named property setter is not supported").
fn named_props_definer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    key: v8::Local<'s, v8::Name>,
    _desc: &v8::PropertyDescriptor,
    args: v8::PropertyCallbackArguments<'s>,
    _rv: v8::ReturnValue<v8::Boolean>,
) -> v8::Intercepted {
    // Refuse only while the object is still WindowProperties: a worker reuses
    // this link under WorkerGlobalScope.prototype (with the tag removed) and
    // defines its members on it.
    let tag = v8::Symbol::get_to_string_tag(scope);
    let is_wp = args
        .holder()
        .get(scope, tag.into())
        .is_some_and(|v| v.is_string() && v.to_rust_string_lossy(scope) == "WindowProperties");
    if !is_wp {
        return v8::Intercepted::kNo;
    }
    let name = key.to_rust_string_lossy(scope);
    let text = format!("Failed to set a named property '{name}' on 'WindowProperties': Named property setter is not supported.");
    if let Some(msg) = v8::String::new(scope, &text) {
        let err = v8::Exception::type_error(scope, msg);
        scope.throw_exception(err);
    }
    v8::Intercepted::kYes
}

fn build_proto_templates(scope: &mut v8::PinScope<'_, '_, ()>) -> ProtoTemplates {
    use v8::MapFnTo;
    let ctor: v8::FunctionCallback = template_ctor.map_fn_to();
    note_ref(ctor as usize);
    let definer: v8::NamedPropertyDefinerCallback = named_props_definer.map_fn_to();
    note_ref(definer as usize);
    let et = v8::FunctionTemplate::new_raw(scope, ctor);
    et.prototype_template(scope).set_immutable_proto();
    let wp = v8::FunctionTemplate::new_raw(scope, ctor);
    wp.inherit(et);
    let wpt = wp.prototype_template(scope);
    wpt.set_immutable_proto();
    wpt.set_named_property_handler(
        v8::NamedPropertyHandlerConfiguration::new()
            .definer_raw(definer)
            .flags(v8::PropertyHandlerFlags::ONLY_INTERCEPT_STRINGS | v8::PropertyHandlerFlags::NON_MASKING),
    );
    // No class name on Window on purpose: V8 would use it for the worker's
    // global too. Without it the error message takes the name from the
    // prototype's tag: "Window" in a window, "DedicatedWorkerGlobalScope" in a worker.
    let w = v8::FunctionTemplate::new_raw(scope, ctor);
    w.inherit(wp);
    w.prototype_template(scope).set_immutable_proto();
    w.instance_template(scope).set_immutable_proto();
    let loc = v8::FunctionTemplate::new_raw(scope, ctor);
    loc.prototype_template(scope).set_immutable_proto();
    loc.instance_template(scope).set_immutable_proto();
    ProtoTemplates {
        et: v8::Global::new(scope, et),
        wp: v8::Global::new(scope, wp),
        w: v8::Global::new(scope, w),
        loc: v8::Global::new(scope, loc),
    }
}

fn proto_templates_ready(scope: &mut v8::PinScope<'_, '_, ()>) {
    if scope.get_slot::<std::rc::Rc<ProtoTemplates>>().is_none() {
        let t = build_proto_templates(scope);
        scope.set_slot(std::rc::Rc::new(t));
    }
}

/// Drop the templates from the isolate: the snapshot creator rejects live
/// global handles (the templates reach the snapshot via context objects).
pub(crate) fn drop_proto_templates(iso: &mut v8::Isolate) {
    let _ = iso.remove_slot::<std::rc::Rc<ProtoTemplates>>();
}

/// Page context: the global comes from the Window template (immutable
/// prototype, Window -> WindowProperties -> EventTarget chain in place).
pub(crate) fn new_page_context<'s>(scope: &mut v8::PinScope<'s, '_, ()>) -> v8::Local<'s, v8::Context> {
    proto_templates_ready(scope);
    let t = scope.get_slot::<std::rc::Rc<ProtoTemplates>>().cloned();
    let global = t.map(|t| {
        let w = v8::Local::new(scope, &t.w);
        w.instance_template(scope)
    });
    v8::Context::new(scope, v8::ContextOptions { global_template: global, ..Default::default() })
}

/// `__pt_protoTemplates()` -> `{et, wp, w, loc, location}`: prototypes from
/// this context's templates plus a Location instance. Called once by the loader.
fn proto_templates_js(scope: &mut v8::PinScope, _args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let Some(t) = scope.get_slot::<std::rc::Rc<ProtoTemplates>>().cloned() else {
        return;
    };
    let out = v8::Object::new(scope);
    let proto_key = v8::String::new(scope, "prototype").unwrap();
    for (name, g) in [("et", &t.et), ("wp", &t.wp), ("w", &t.w), ("loc", &t.loc)] {
        let ft = v8::Local::new(scope, g);
        let Some(f) = ft.get_function(scope) else { return };
        let Some(p) = f.get(scope, proto_key.into()) else { return };
        let k = v8::String::new(scope, name).unwrap();
        out.set(scope, k.into(), p);
        if name == "loc" {
            // Instance template, not a function call: that throws "Illegal constructor".
            if let Some(inst) = ft.instance_template(scope).new_instance(scope) {
                let k = v8::String::new(scope, "location").unwrap();
                out.set(scope, k.into(), inst.into());
            }
        }
    }
    rv.set(out.into());
}

/// Hidden TrustedScript field holding the script text, read by the codegen
/// handler (isolate.rs) without running JS.
pub(crate) const TRUSTED_SCRIPT_KEY: &str = "nokk::trustedScript";

/// `__pt_codeLike(text)` -> empty object carrying script text hidden: eval and
/// new Function run it as a string (the loader makes TrustedScript from it).
fn code_like_js(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, mut rv: v8::ReturnValue) {
    let Some(text) = args.get(0).to_string(scope) else { return };
    let o = v8::Object::new(scope);
    let Some(name) = v8::String::new(scope, TRUSTED_SCRIPT_KEY) else { return };
    let key = v8::Private::for_api(scope, Some(name));
    o.set_private(scope, key, text.into());
    rv.set(o.into());
}
