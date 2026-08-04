//! Optional real WebGL rasterization — the `webgl` feature (Phase 2 of `render`).
//!
//! Backs the JS WebGL context with a genuine headless GL context (Mesa software
//! rendering via surfaceless EGL), so `readPixels` / `toDataURL` reflect what was
//! actually drawn instead of the deterministic stamp. Kept a *separate* feature
//! from `render` (2D) because it links a real GL stack: `webgl` builds anywhere
//! (EGL is loaded dynamically at runtime via `libEGL.so.1`) but only *runs* where
//! Mesa/EGL is installed — a `libgl1-mesa-dri` + `libegl1` container or host.
//!
//! One GL context + FBO per canvas id, thread-local (one V8 isolate per worker
//! thread — no cross-thread GL sharing). This module is the raster backend; the
//! `__pt_gl*` natives and JS wiring come on top.
//!
//! Coherence note: Mesa software reports `llvmpipe` as the renderer, itself a
//! headless tell. The stealth layer keeps *reporting* a plausible GPU string; we
//! only borrow llvmpipe's pixels. That claimed-vs-actual mismatch is a deep probe
//! few fingerprinters run; documented in docs/rendering.md.

use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroU32;

use glow::HasContext;
use khronos_egl as egl;

/// `EGL_PLATFORM_SURFACELESS_MESA` — a display with no window system, exactly
/// what a headless renderer wants.
const EGL_PLATFORM_SURFACELESS_MESA: egl::Enum = 0x31DD;

type EglInstance = egl::DynamicInstance<egl::EGL1_5>;

/// A headless GL context rendering into an off-screen RGBA8 framebuffer.
struct GlSurface {
    gl: glow::Context,
    w: i32,
    h: i32,
    /// The FBO standing in for the drawing buffer. WebGL's `bindFramebuffer(t, null)`
    /// means "the canvas", which here is this object rather than the window-system
    /// framebuffer 0 (surfaceless: there isn't one).
    fbo: glow::NativeFramebuffer,
    // Held for lifetime/cleanup; the context must stay current on this thread.
    _egl: &'static EglInstance,
    display: egl::Display,
    context: egl::Context,
}

thread_local! {
    /// One shared EGL instance + display per thread, initialized on first use.
    static EGL: RefCell<Option<(&'static EglInstance, egl::Display)>> = const { RefCell::new(None) };
    static SURFACES: RefCell<HashMap<u32, GlSurface>> = RefCell::new(HashMap::new());
}

/// Whether a real headless GL stack is usable (EGL loads + a surfaceless display
/// initializes). Cheap after the first call; used to decide native vs. fallback.
pub fn available() -> bool {
    egl_display().is_ok()
}

/// Lazily load EGL and initialize a surfaceless display, once per thread.
fn egl_display() -> Result<(&'static EglInstance, egl::Display), String> {
    EGL.with(|cell| {
        if let Some(v) = *cell.borrow() {
            return Ok(v);
        }
        let lib = unsafe { libloading::Library::new("libEGL.so.1") }
            .map_err(|e| format!("libEGL.so.1: {e}"))?;
        let instance = unsafe { EglInstance::load_required_from(lib) }
            .map_err(|e| format!("EGL load: {e}"))?;
        // Leak the instance to 'static: it lives for the whole process, and GL
        // proc pointers borrowed from it must stay valid for the thread's life.
        let instance: &'static EglInstance = Box::leak(Box::new(instance));
        let display = unsafe {
            instance.get_platform_display(
                EGL_PLATFORM_SURFACELESS_MESA,
                egl::DEFAULT_DISPLAY,
                &[egl::ATTRIB_NONE],
            )
        }
        .map_err(|e| format!("get_platform_display: {e}"))?;
        instance
            .initialize(display)
            .map_err(|e| format!("eglInitialize: {e}"))?;
        *cell.borrow_mut() = Some((instance, display));
        Ok((instance, display))
    })
}

/// Create (or reset) a headless GL surface of `w`×`h` for `id`. Silently no-ops
/// if EGL is unavailable — callers fall back to the JS synthesis.
pub fn create(id: u32, w: u32, h: u32) {
    let (w, h) = (w.clamp(1, 8192) as i32, h.clamp(1, 8192) as i32);
    // On failure there's simply no GL here; the JS layer keeps the stamp.
    if let Ok(surface) = make_surface(w, h) {
        SURFACES.with(|s| {
            s.borrow_mut().insert(id, surface);
        });
    }
}

fn make_surface(w: i32, h: i32) -> Result<GlSurface, String> {
    let (egl_i, display) = egl_display()?;
    let config_attribs = [
        egl::SURFACE_TYPE,
        egl::PBUFFER_BIT,
        egl::RENDERABLE_TYPE,
        egl::OPENGL_ES2_BIT,
        egl::RED_SIZE,
        8,
        egl::GREEN_SIZE,
        8,
        egl::BLUE_SIZE,
        8,
        egl::ALPHA_SIZE,
        8,
        egl::NONE,
    ];
    let config = egl_i
        .choose_first_config(display, &config_attribs)
        .map_err(|e| format!("choose_config: {e}"))?
        .ok_or("no EGL config")?;
    egl_i
        .bind_api(egl::OPENGL_ES_API)
        .map_err(|e| format!("bind_api: {e}"))?;
    let ctx_attribs = [egl::CONTEXT_MAJOR_VERSION, 3, egl::NONE];
    let context = egl_i
        .create_context(display, config, None, &ctx_attribs)
        .map_err(|e| format!("create_context: {e}"))?;
    // Surfaceless: no draw/read surface (EGL_KHR_surfaceless_context, Mesa OK).
    egl_i
        .make_current(display, None, None, Some(context))
        .map_err(|e| format!("make_current: {e}"))?;
    let gl = unsafe {
        glow::Context::from_loader_function(|name| match egl_i.get_proc_address(name) {
            Some(f) => f as *const std::ffi::c_void,
            None => std::ptr::null(),
        })
    };
    // Off-screen RGBA8 target: an FBO with a colour renderbuffer.
    let fbo = unsafe {
        let fbo = gl.create_framebuffer().map_err(|e| e.to_string())?;
        gl.bind_framebuffer(glow::FRAMEBUFFER, Some(fbo));
        let rb = gl.create_renderbuffer().map_err(|e| e.to_string())?;
        gl.bind_renderbuffer(glow::RENDERBUFFER, Some(rb));
        gl.renderbuffer_storage(glow::RENDERBUFFER, glow::RGBA8, w, h);
        gl.framebuffer_renderbuffer(
            glow::FRAMEBUFFER,
            glow::COLOR_ATTACHMENT0,
            glow::RENDERBUFFER,
            Some(rb),
        );
        // A depth buffer too: `getContextAttributes()` reports `depth: true`, and
        // without one `enable(DEPTH_TEST)` silently passes every fragment, so a
        // scene drawn back-to-front reads back in the wrong order.
        let depth = gl.create_renderbuffer().map_err(|e| e.to_string())?;
        gl.bind_renderbuffer(glow::RENDERBUFFER, Some(depth));
        gl.renderbuffer_storage(glow::RENDERBUFFER, glow::DEPTH_COMPONENT24, w, h);
        gl.framebuffer_renderbuffer(
            glow::FRAMEBUFFER,
            glow::DEPTH_ATTACHMENT,
            glow::RENDERBUFFER,
            Some(depth),
        );
        gl.viewport(0, 0, w, h);
        // Pixel transfers cross from JS as tightly packed rows; GL's default
        // 4-byte row alignment would mis-read anything narrower (e.g. a 3-wide
        // RGB upload). Also what the size checks in `tex_image_2d` assume.
        gl.pixel_store_i32(glow::UNPACK_ALIGNMENT, 1);
        gl.pixel_store_i32(glow::PACK_ALIGNMENT, 1);
        fbo
    };
    Ok(GlSurface {
        gl,
        w,
        h,
        fbo,
        _egl: egl_i,
        display,
        context,
    })
}

/// Drop a GL surface and its context.
pub fn destroy(id: u32) {
    SURFACES.with(|s| {
        if let Some(surf) = s.borrow_mut().remove(&id) {
            if let Ok((egl_i, _)) = egl_display() {
                let _ = egl_i.destroy_context(surf.display, surf.context);
            }
        }
    });
}

/// Run `f` with `id`'s GL context made current on this thread (several canvases
/// can share one worker thread, so every op re-binds its own context first).
fn with_surface<R>(id: u32, f: impl FnOnce(&GlSurface) -> R) -> Option<R> {
    SURFACES.with(|s| {
        let map = s.borrow();
        let surf = map.get(&id)?;
        if let Ok((egl_i, display)) = egl_display() {
            let _ = egl_i.make_current(display, None, None, Some(surf.context));
        }
        Some(f(surf))
    })
}

fn with_gl<R>(id: u32, f: impl FnOnce(&glow::Context) -> R) -> Option<R> {
    with_surface(id, |surf| f(&surf.gl))
}

// GL object handles cross the JS boundary as plain `u32` (glow wraps a
// `NonZeroU32`); 0 is the WebGL `null` object.
fn shader_h(v: u32) -> Option<glow::NativeShader> {
    NonZeroU32::new(v).map(glow::NativeShader)
}
fn program_h(v: u32) -> Option<glow::NativeProgram> {
    NonZeroU32::new(v).map(glow::NativeProgram)
}
fn buffer_h(v: u32) -> Option<glow::NativeBuffer> {
    NonZeroU32::new(v).map(glow::NativeBuffer)
}
fn texture_h(v: u32) -> Option<glow::NativeTexture> {
    NonZeroU32::new(v).map(glow::NativeTexture)
}
fn framebuffer_h(v: u32) -> Option<glow::NativeFramebuffer> {
    NonZeroU32::new(v).map(glow::NativeFramebuffer)
}
fn renderbuffer_h(v: u32) -> Option<glow::NativeRenderbuffer> {
    NonZeroU32::new(v).map(glow::NativeRenderbuffer)
}
fn vao_h(v: u32) -> Option<glow::NativeVertexArray> {
    NonZeroU32::new(v).map(glow::NativeVertexArray)
}

/// `gl.clearColor(r,g,b,a); gl.clear(mask)` with straight-alpha input. `mask` is
/// the WebGL bitmask, filtered to the buffers this surface actually has.
pub fn clear(id: u32, rgba: [u8; 4], mask: u32) {
    with_gl(id, |gl| unsafe {
        gl.clear_color(
            rgba[0] as f32 / 255.0,
            rgba[1] as f32 / 255.0,
            rgba[2] as f32 / 255.0,
            rgba[3] as f32 / 255.0,
        );
        gl.clear(mask & (glow::COLOR_BUFFER_BIT | glow::DEPTH_BUFFER_BIT));
    });
}

/// `createShader(type)` → handle (0 on failure). `type` is `VERTEX_SHADER`/`FRAGMENT_SHADER`.
pub fn create_shader(id: u32, shader_type: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_shader(shader_type)
            .map(|s| s.0.get())
            .unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `shaderSource` + `compileShader` in one step.
pub fn compile_shader(id: u32, shader: u32, source: &str) {
    let Some(sh) = shader_h(shader) else { return };
    with_gl(id, |gl| unsafe {
        gl.shader_source(sh, source);
        gl.compile_shader(sh);
    });
}

/// `getShaderParameter(shader, COMPILE_STATUS)`.
pub fn shader_compiled(id: u32, shader: u32) -> bool {
    let Some(sh) = shader_h(shader) else {
        return false;
    };
    with_gl(id, |gl| unsafe { gl.get_shader_compile_status(sh) }).unwrap_or(false)
}

/// `getShaderInfoLog(shader)`.
pub fn shader_info_log(id: u32, shader: u32) -> String {
    let Some(sh) = shader_h(shader) else {
        return String::new();
    };
    with_gl(id, |gl| unsafe { gl.get_shader_info_log(sh) }).unwrap_or_default()
}

/// `createProgram()` → handle (0 on failure).
pub fn create_program(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_program().map(|p| p.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `attachShader(program, shader)`.
pub fn attach_shader(id: u32, program: u32, shader: u32) {
    let (Some(p), Some(sh)) = (program_h(program), shader_h(shader)) else {
        return;
    };
    with_gl(id, |gl| unsafe { gl.attach_shader(p, sh) });
}

/// `linkProgram(program)`.
pub fn link_program(id: u32, program: u32) {
    let Some(p) = program_h(program) else { return };
    with_gl(id, |gl| unsafe { gl.link_program(p) });
}

/// `getProgramParameter(program, LINK_STATUS)`.
pub fn program_linked(id: u32, program: u32) -> bool {
    let Some(p) = program_h(program) else {
        return false;
    };
    with_gl(id, |gl| unsafe { gl.get_program_link_status(p) }).unwrap_or(false)
}

/// `useProgram(program)`.
pub fn use_program(id: u32, program: u32) {
    with_gl(id, |gl| unsafe { gl.use_program(program_h(program)) });
}

/// `getAttribLocation(program, name)` → location, or -1.
pub fn attrib_location(id: u32, program: u32, name: &str) -> i32 {
    let Some(p) = program_h(program) else {
        return -1;
    };
    with_gl(id, |gl| unsafe {
        gl.get_attrib_location(p, name)
            .map(|l| l as i32)
            .unwrap_or(-1)
    })
    .unwrap_or(-1)
}

/// `createBuffer()` → handle (0 on failure).
pub fn create_buffer(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_buffer().map(|b| b.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `bindBuffer(target, buffer)`.
pub fn bind_buffer(id: u32, target: u32, buffer: u32) {
    with_gl(id, |gl| unsafe { gl.bind_buffer(target, buffer_h(buffer)) });
}

/// `bufferData(target, data, usage)` with raw bytes.
pub fn buffer_data(id: u32, target: u32, data: &[u8], usage: u32) {
    with_gl(id, |gl| unsafe {
        gl.buffer_data_u8_slice(target, data, usage)
    });
}

/// `enableVertexAttribArray(index)`.
pub fn enable_vertex_attrib_array(id: u32, index: u32) {
    with_gl(id, |gl| unsafe { gl.enable_vertex_attrib_array(index) });
}

/// `vertexAttribPointer(index, size, type, normalized, stride, offset)` (float attribs).
pub fn vertex_attrib_pointer(
    id: u32,
    index: u32,
    size: i32,
    data_type: u32,
    normalized: bool,
    stride: i32,
    offset: i32,
) {
    with_gl(id, |gl| unsafe {
        gl.vertex_attrib_pointer_f32(index, size, data_type, normalized, stride, offset)
    });
}

/// `drawArrays(mode, first, count)`.
pub fn draw_arrays(id: u32, mode: u32, first: i32, count: i32) {
    with_gl(id, |gl| unsafe { gl.draw_arrays(mode, first, count) });
}

/// `drawElements(mode, count, type, offset)` (indexed draw; ELEMENT_ARRAY_BUFFER
/// must already be bound + filled via `bind_buffer`/`buffer_data`).
pub fn draw_elements(id: u32, mode: u32, count: i32, element_type: u32, offset: i32) {
    with_gl(id, |gl| unsafe {
        gl.draw_elements(mode, count, element_type, offset)
    });
}

// ---- textures ------------------------------------------------------------
// A textured quad is the classic WebGL fingerprint scene, so these are as
// load-bearing as the shader pipeline: with texturing stubbed the sampler reads
// black and every scene collapses to the same readback.

/// `createTexture()` → handle (0 on failure).
pub fn create_texture(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_texture().map(|t| t.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `bindTexture(target, texture)`.
pub fn bind_texture(id: u32, target: u32, texture: u32) {
    with_gl(id, |gl| unsafe {
        gl.bind_texture(target, texture_h(texture))
    });
}

/// `activeTexture(unit)` — `unit` is `TEXTURE0 + i`.
pub fn active_texture(id: u32, unit: u32) {
    with_gl(id, |gl| unsafe { gl.active_texture(unit) });
}

/// `texParameteri(target, pname, param)`.
pub fn tex_parameter_i(id: u32, target: u32, pname: u32, param: i32) {
    with_gl(id, |gl| unsafe {
        gl.tex_parameter_i32(target, pname, param)
    });
}

/// `generateMipmap(target)`.
pub fn generate_mipmap(id: u32, target: u32) {
    with_gl(id, |gl| unsafe { gl.generate_mipmap(target) });
}

/// Bytes per pixel of a WebGL `(format, type)` pair, or `None` when it isn't one
/// we can size. An upload we can't size is allocated but not filled — the driver
/// reads exactly `w*h*bpp` bytes from the pointer we hand it, so a wrong size
/// here is an out-of-bounds read, not a rendering glitch.
fn pixel_size(format: u32, ty: u32) -> Option<usize> {
    // Packed types carry every channel in a single unit.
    match ty {
        0x8363 | 0x8033 | 0x8034 => return Some(2), // 5_6_5 / 4_4_4_4 / 5_5_5_1
        0x84FA => return Some(4),                   // UNSIGNED_INT_24_8
        _ => {}
    }
    let channels = match format {
        0x1906 | 0x1909 | 0x1903 | 0x1902 => 1, // ALPHA / LUMINANCE / RED / DEPTH_COMPONENT
        0x190A | 0x8227 => 2,                   // LUMINANCE_ALPHA / RG
        0x1907 => 3,                            // RGB
        0x1908 => 4,                            // RGBA
        _ => return None,
    };
    let unit = match ty {
        0x1400 | 0x1401 => 1,                   // BYTE / UNSIGNED_BYTE
        0x1402 | 0x1403 | 0x140B | 0x8D61 => 2, // SHORT / UNSIGNED_SHORT / HALF_FLOAT(_OES)
        0x1404..=0x1406 => 4,                   // INT / UNSIGNED_INT / FLOAT
        _ => return None,
    };
    Some(channels * unit)
}

/// Apply the WebGL-only unpack modes, which have no GL equivalent (they're
/// `pixelStorei` parameters the browser implements on the CPU): row-flip for
/// `UNPACK_FLIP_Y_WEBGL` and alpha-premultiply for `UNPACK_PREMULTIPLY_ALPHA_WEBGL`
/// (8-bit RGBA only, the only combination the flag is defined to touch here).
fn unpack(src: &[u8], w: usize, h: usize, bpp: usize, flip_y: bool, premul: bool) -> Vec<u8> {
    let stride = w * bpp;
    let mut out = vec![0u8; stride * h];
    for row in 0..h {
        let sy = if flip_y { h - 1 - row } else { row };
        out[row * stride..row * stride + stride]
            .copy_from_slice(&src[sy * stride..sy * stride + stride]);
    }
    if premul && bpp == 4 {
        for px in out.chunks_exact_mut(4) {
            let a = px[3] as u32;
            for c in &mut px[..3] {
                *c = ((*c as u32 * a + 127) / 255) as u8;
            }
        }
    }
    out
}

/// `texImage2D(target, level, internalFormat, w, h, border, format, type, pixels)`.
/// An empty `pixels` (WebGL `null`) allocates without initializing; so does data
/// too short for the requested rectangle, rather than letting the driver run off
/// the end of it. `flip_y`/`premultiply` carry the WebGL-only unpack modes.
#[allow(clippy::too_many_arguments)]
pub fn tex_image_2d(
    id: u32,
    target: u32,
    level: i32,
    internal_format: i32,
    w: i32,
    h: i32,
    border: i32,
    format: u32,
    ty: u32,
    pixels: &[u8],
    flip_y: bool,
    premultiply: bool,
) {
    let data = upload_slice(w, h, format, ty, pixels, flip_y, premultiply);
    with_gl(id, |gl| unsafe {
        gl.tex_image_2d(
            target,
            level,
            internal_format,
            w,
            h,
            border,
            format,
            ty,
            data.as_deref(),
        )
    });
}

/// `texSubImage2D(target, level, xoff, yoff, w, h, format, type, pixels)`. A
/// rectangle we can't size or that comes up short is dropped (GL has no
/// "allocate only" form of a sub-image update).
#[allow(clippy::too_many_arguments)]
pub fn tex_sub_image_2d(
    id: u32,
    target: u32,
    level: i32,
    x_offset: i32,
    y_offset: i32,
    w: i32,
    h: i32,
    format: u32,
    ty: u32,
    pixels: &[u8],
    flip_y: bool,
    premultiply: bool,
) {
    let Some(data) = upload_slice(w, h, format, ty, pixels, flip_y, premultiply) else {
        return;
    };
    with_gl(id, |gl| unsafe {
        gl.tex_sub_image_2d(
            target,
            level,
            x_offset,
            y_offset,
            w,
            h,
            format,
            ty,
            glow::PixelUnpackData::Slice(&data),
        )
    });
}

/// The exact `w*h` bytes to hand the driver, or `None` when the upload can't be
/// sized or the caller passed too little data (see [`pixel_size`]).
fn upload_slice(
    w: i32,
    h: i32,
    format: u32,
    ty: u32,
    pixels: &[u8],
    flip_y: bool,
    premultiply: bool,
) -> Option<Vec<u8>> {
    if pixels.is_empty() || w <= 0 || h <= 0 {
        return None;
    }
    let bpp = pixel_size(format, ty)?;
    let (w, h) = (w as usize, h as usize);
    let needed = w.checked_mul(h)?.checked_mul(bpp)?;
    if pixels.len() < needed {
        return None;
    }
    Some(unpack(
        &pixels[..needed],
        w,
        h,
        bpp,
        flip_y,
        premultiply && ty == 0x1401,
    ))
}

// ---- framebuffers, renderbuffers, vertex arrays --------------------------

/// `createFramebuffer()` → handle (0 on failure).
pub fn create_framebuffer(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_framebuffer().map(|f| f.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `bindFramebuffer(target, framebuffer)`. `0` (WebGL `null`) means the drawing
/// buffer, which on a surfaceless context is this surface's own FBO — *not*
/// framebuffer 0, which doesn't exist here.
pub fn bind_framebuffer(id: u32, target: u32, framebuffer: u32) {
    with_surface(id, |surf| unsafe {
        let fb = framebuffer_h(framebuffer).unwrap_or(surf.fbo);
        surf.gl.bind_framebuffer(target, Some(fb));
    });
}

/// `framebufferTexture2D(target, attachment, textarget, texture, level)`.
pub fn framebuffer_texture_2d(
    id: u32,
    target: u32,
    attachment: u32,
    tex_target: u32,
    texture: u32,
    level: i32,
) {
    with_gl(id, |gl| unsafe {
        gl.framebuffer_texture_2d(target, attachment, tex_target, texture_h(texture), level)
    });
}

/// `checkFramebufferStatus(target)`.
pub fn check_framebuffer_status(id: u32, target: u32) -> u32 {
    with_gl(id, |gl| unsafe { gl.check_framebuffer_status(target) }).unwrap_or(0)
}

/// `createRenderbuffer()` → handle (0 on failure).
pub fn create_renderbuffer(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_renderbuffer().map(|r| r.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `bindRenderbuffer(target, renderbuffer)`.
pub fn bind_renderbuffer(id: u32, target: u32, renderbuffer: u32) {
    with_gl(id, |gl| unsafe {
        gl.bind_renderbuffer(target, renderbuffer_h(renderbuffer))
    });
}

/// `renderbufferStorage(target, internalFormat, w, h)`.
pub fn renderbuffer_storage(id: u32, target: u32, internal_format: u32, w: i32, h: i32) {
    with_gl(id, |gl| unsafe {
        gl.renderbuffer_storage(target, internal_format, w, h)
    });
}

/// `framebufferRenderbuffer(target, attachment, rbTarget, renderbuffer)`.
pub fn framebuffer_renderbuffer(
    id: u32,
    target: u32,
    attachment: u32,
    rb_target: u32,
    renderbuffer: u32,
) {
    with_gl(id, |gl| unsafe {
        gl.framebuffer_renderbuffer(target, attachment, rb_target, renderbuffer_h(renderbuffer))
    });
}

/// `createVertexArray()` → handle (WebGL 2 / `OES_vertex_array_object`).
pub fn create_vertex_array(id: u32) -> u32 {
    with_gl(id, |gl| unsafe {
        gl.create_vertex_array().map(|v| v.0.get()).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// `bindVertexArray(vao)` (0 = the default vertex array).
pub fn bind_vertex_array(id: u32, vao: u32) {
    with_gl(id, |gl| unsafe { gl.bind_vertex_array(vao_h(vao)) });
}

// ---- deletes + fixed-function state --------------------------------------

/// Which kind of GL object a `delete_object` call refers to; keeps one native
/// binding instead of six near-identical ones.
pub const OBJ_SHADER: u32 = 0;
pub const OBJ_PROGRAM: u32 = 1;
pub const OBJ_BUFFER: u32 = 2;
pub const OBJ_TEXTURE: u32 = 3;
pub const OBJ_FRAMEBUFFER: u32 = 4;
pub const OBJ_RENDERBUFFER: u32 = 5;
pub const OBJ_VERTEX_ARRAY: u32 = 6;

/// `delete{Shader,Program,Buffer,Texture,Framebuffer,Renderbuffer,VertexArray}`.
/// A long-lived context that never freed anything would leak driver memory as a
/// page re-renders.
pub fn delete_object(id: u32, kind: u32, handle: u32) {
    with_gl(id, |gl| unsafe {
        match kind {
            OBJ_SHADER => {
                if let Some(h) = shader_h(handle) {
                    gl.delete_shader(h)
                }
            }
            OBJ_PROGRAM => {
                if let Some(h) = program_h(handle) {
                    gl.delete_program(h)
                }
            }
            OBJ_BUFFER => {
                if let Some(h) = buffer_h(handle) {
                    gl.delete_buffer(h)
                }
            }
            OBJ_TEXTURE => {
                if let Some(h) = texture_h(handle) {
                    gl.delete_texture(h)
                }
            }
            OBJ_FRAMEBUFFER => {
                if let Some(h) = framebuffer_h(handle) {
                    gl.delete_framebuffer(h)
                }
            }
            OBJ_RENDERBUFFER => {
                if let Some(h) = renderbuffer_h(handle) {
                    gl.delete_renderbuffer(h)
                }
            }
            OBJ_VERTEX_ARRAY => {
                if let Some(h) = vao_h(handle) {
                    gl.delete_vertex_array(h)
                }
            }
            _ => {}
        }
    });
}

/// `blendFunc(src, dst)` — without it `enable(BLEND)` blends with GL's default
/// (ONE, ZERO), i.e. not at all, and translucent scenes read back opaque.
pub fn blend_func(id: u32, src: u32, dst: u32) {
    with_gl(id, |gl| unsafe { gl.blend_func(src, dst) });
}

/// `depthFunc(func)`.
pub fn depth_func(id: u32, func: u32) {
    with_gl(id, |gl| unsafe { gl.depth_func(func) });
}

/// `viewport(x, y, w, h)`.
pub fn viewport(id: u32, x: i32, y: i32, w: i32, h: i32) {
    with_gl(id, |gl| unsafe { gl.viewport(x, y, w, h) });
}

/// `enable(cap)` / `disable(cap)` — GL state toggles (e.g. DEPTH_TEST, BLEND).
pub fn enable(id: u32, cap: u32, on: bool) {
    with_gl(id, |gl| unsafe {
        if on {
            gl.enable(cap)
        } else {
            gl.disable(cap)
        }
    });
}

/// `getUniformLocation(program, name)` → location, or -1 if not found.
pub fn uniform_location(id: u32, program: u32, name: &str) -> i32 {
    let Some(p) = program_h(program) else {
        return -1;
    };
    with_gl(id, |gl| unsafe {
        gl.get_uniform_location(p, name)
            .map(|l| l.0 as i32)
            .unwrap_or(-1)
    })
    .unwrap_or(-1)
}

/// `uniform{1,2,3,4}f(location, …)` — dispatched by the number of components.
pub fn uniform_f(id: u32, location: i32, v: &[f32]) {
    if location < 0 {
        return;
    }
    let loc = glow::NativeUniformLocation(location as u32);
    with_gl(id, |gl| unsafe {
        match v.len() {
            1 => gl.uniform_1_f32(Some(&loc), v[0]),
            2 => gl.uniform_2_f32(Some(&loc), v[0], v[1]),
            3 => gl.uniform_3_f32(Some(&loc), v[0], v[1], v[2]),
            _ => gl.uniform_4_f32(Some(&loc), v[0], v[1], v[2], v[3]),
        }
    });
}

/// `uniform1i(location, v)` (samplers / ints).
pub fn uniform_1i(id: u32, location: i32, v: i32) {
    if location < 0 {
        return;
    }
    let loc = glow::NativeUniformLocation(location as u32);
    with_gl(id, |gl| unsafe { gl.uniform_1_i32(Some(&loc), v) });
}

/// `uniformMatrix4fv(location, transpose, values)`.
pub fn uniform_matrix4(id: u32, location: i32, transpose: bool, values: &[f32]) {
    if location < 0 || values.len() < 16 {
        return;
    }
    let loc = glow::NativeUniformLocation(location as u32);
    with_gl(id, |gl| unsafe {
        gl.uniform_matrix_4_f32_slice(Some(&loc), transpose, &values[..16])
    });
}

/// `readPixels(x, y, w, h, RGBA, UNSIGNED_BYTE)` of the *currently bound*
/// framebuffer, as WebGL's own `readPixels` does — so a render-to-texture pass
/// reads back its own target, at its own size, rather than the canvas'.
///
/// `flip` row-flips the result into the canvas' top-left origin (what
/// `toDataURL` wants); left off, rows come back bottom-up exactly as GL and the
/// WebGL `readPixels` contract hand them over.
pub fn read_pixels(id: u32, x: i32, y: i32, w: i32, h: i32, flip: bool) -> Vec<u8> {
    if w <= 0 || h <= 0 || w > 8192 || h > 8192 {
        return Vec::new();
    }
    with_surface(id, |surf| {
        let (uw, uh) = (w as usize, h as usize);
        // Zero-filled, so any part of the rectangle outside the framebuffer reads
        // back transparent-black instead of whatever the driver left there.
        let mut buf = vec![0u8; uw * uh * 4];
        unsafe {
            surf.gl.read_pixels(
                x,
                y,
                w,
                h,
                glow::RGBA,
                glow::UNSIGNED_BYTE,
                glow::PixelPackData::Slice(&mut buf),
            );
        }
        if !flip {
            return buf;
        }
        let stride = uw * 4;
        let mut out = vec![0u8; buf.len()];
        for row in 0..uh {
            let src = (uh - 1 - row) * stride;
            out[row * stride..row * stride + stride].copy_from_slice(&buf[src..src + stride]);
        }
        out
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run for real only where Mesa/EGL is present (the mesa test container);
    // a no-op skip elsewhere so `cargo test --features webgl` is green everywhere.
    #[test]
    fn clear_then_readback_is_the_clear_color() {
        if !available() {
            eprintln!("skip: no headless EGL (run in the mesa container)");
            return;
        }
        create(1, 4, 4);
        clear(1, [10, 200, 30, 255], glow::COLOR_BUFFER_BIT);
        let px = read_pixels(1, 0, 0, 4, 4, true);
        assert_eq!(px.len(), 4 * 4 * 4, "full RGBA readback");
        assert_eq!(
            &px[0..4],
            &[10, 200, 30, 255],
            "readPixels returns the GL clear color"
        );
        destroy(1);
    }

    #[test]
    fn draw_triangle_shows_shaded_pixels() {
        if !available() {
            eprintln!("skip: no headless EGL (run in the mesa container)");
            return;
        }
        const VS: u32 = 0x8B31; // GL_VERTEX_SHADER
        const FS: u32 = 0x8B30; // GL_FRAGMENT_SHADER
        const ARRAY_BUFFER: u32 = 0x8892;
        const STATIC_DRAW: u32 = 0x88E4;
        const FLOAT: u32 = 0x1406;
        const TRIANGLES: u32 = 0x0004;

        create(2, 16, 16);
        clear(2, [0, 0, 0, 255], glow::COLOR_BUFFER_BIT);

        let vs = create_shader(2, VS);
        compile_shader(
            2,
            vs,
            "attribute vec2 p; void main() { gl_Position = vec4(p, 0.0, 1.0); }",
        );
        assert!(
            shader_compiled(2, vs),
            "vertex shader compiles: {}",
            shader_info_log(2, vs)
        );
        let fs = create_shader(2, FS);
        compile_shader(
            2,
            fs,
            "precision mediump float; void main() { gl_FragColor = vec4(0.0, 1.0, 0.0, 1.0); }",
        );
        assert!(
            shader_compiled(2, fs),
            "fragment shader compiles: {}",
            shader_info_log(2, fs)
        );

        let prog = create_program(2);
        attach_shader(2, prog, vs);
        attach_shader(2, prog, fs);
        link_program(2, prog);
        assert!(program_linked(2, prog), "program links");
        use_program(2, prog);

        // A big centered triangle in clip space.
        let verts: [f32; 6] = [-0.8, -0.8, 0.8, -0.8, 0.0, 0.8];
        let bytes: &[u8] = bytemuck_cast(&verts);
        let buf = create_buffer(2);
        bind_buffer(2, ARRAY_BUFFER, buf);
        buffer_data(2, ARRAY_BUFFER, bytes, STATIC_DRAW);
        let loc = attrib_location(2, prog, "p");
        assert!(loc >= 0, "attribute 'p' has a location");
        enable_vertex_attrib_array(2, loc as u32);
        vertex_attrib_pointer(2, loc as u32, 2, FLOAT, false, 0, 0);

        draw_arrays(2, TRIANGLES, 0, 3);

        let px = read_pixels(2, 0, 0, 16, 16, true);
        // Center pixel should be the green fragment color; a corner stays black.
        let center = 4 * (8 * 16 + 8);
        assert_eq!(
            &px[center..center + 4],
            &[0, 255, 0, 255],
            "triangle center is green"
        );
        assert_eq!(&px[0..4], &[0, 0, 0, 255], "corner stays clear-black");
        destroy(2);
    }

    #[test]
    fn textured_quad_samples_the_uploaded_texels() {
        if !available() {
            eprintln!("skip: no headless EGL (run in the mesa container)");
            return;
        }
        const ID: u32 = 3;
        const TEXTURE_2D: u32 = 0x0DE1;
        const RGBA: u32 = 0x1908;
        const UNSIGNED_BYTE: u32 = 0x1401;
        const NEAREST: i32 = 0x2600;
        const CLAMP_TO_EDGE: i32 = 0x812F;
        const TEXTURE_MAG_FILTER: u32 = 0x2800;
        const TEXTURE_MIN_FILTER: u32 = 0x2801;
        const TEXTURE_WRAP_S: u32 = 0x2802;
        const TEXTURE_WRAP_T: u32 = 0x2803;
        const TEXTURE0: u32 = 0x84C0;
        const TRIANGLE_STRIP: u32 = 0x0005;

        create(ID, 8, 8);
        clear(ID, [0, 0, 0, 255], glow::COLOR_BUFFER_BIT);

        let prog = quad_program(ID);
        use_program(ID, prog);

        // 2×2 texels: GL row 0 is the *bottom* of the image in UV space.
        let texels: [u8; 16] = [
            255, 0, 0, 255, // red      (u=0, v=0)
            0, 255, 0, 255, // green    (u=1, v=0)
            0, 0, 255, 255, // blue     (u=0, v=1)
            255, 255, 255, 255, // white(u=1, v=1)
        ];
        let tex = create_texture(ID);
        assert!(tex != 0, "texture allocated");
        active_texture(ID, TEXTURE0);
        bind_texture(ID, TEXTURE_2D, tex);
        tex_image_2d(
            ID,
            TEXTURE_2D,
            0,
            RGBA as i32,
            2,
            2,
            0,
            RGBA,
            UNSIGNED_BYTE,
            &texels,
            false,
            false,
        );
        // No mipmaps uploaded, so the minification filter has to be a non-mip one
        // or the texture is incomplete and samples black.
        tex_parameter_i(ID, TEXTURE_2D, TEXTURE_MIN_FILTER, NEAREST);
        tex_parameter_i(ID, TEXTURE_2D, TEXTURE_MAG_FILTER, NEAREST);
        tex_parameter_i(ID, TEXTURE_2D, TEXTURE_WRAP_S, CLAMP_TO_EDGE);
        tex_parameter_i(ID, TEXTURE_2D, TEXTURE_WRAP_T, CLAMP_TO_EDGE);
        uniform_1i(ID, uniform_location(ID, prog, "t"), 0);

        draw_arrays(ID, TRIANGLE_STRIP, 0, 4);

        let px = read_pixels(ID, 0, 0, 8, 8, true);
        // Readback is top-left origin, so the top half is the v=1 texel row.
        let at = |x: usize, y: usize| {
            let i = 4 * (y * 8 + x);
            [px[i], px[i + 1], px[i + 2], px[i + 3]]
        };
        assert_eq!(
            at(2, 2),
            [0, 0, 255, 255],
            "top-left samples the blue texel"
        );
        assert_eq!(at(5, 2), [255, 255, 255, 255], "top-right is white");
        assert_eq!(at(2, 5), [255, 0, 0, 255], "bottom-left is red");
        assert_eq!(at(5, 5), [0, 255, 0, 255], "bottom-right is green");

        // UNPACK_FLIP_Y_WEBGL turns the image upside down before upload.
        tex_image_2d(
            ID,
            TEXTURE_2D,
            0,
            RGBA as i32,
            2,
            2,
            0,
            RGBA,
            UNSIGNED_BYTE,
            &texels,
            true,
            false,
        );
        draw_arrays(ID, TRIANGLE_STRIP, 0, 4);
        let px = read_pixels(ID, 0, 0, 8, 8, true);
        let i = 4 * (2 * 8 + 2);
        assert_eq!(
            &px[i..i + 4],
            &[255, 0, 0, 255],
            "flip_y puts the red texel row on top"
        );

        destroy(ID);
    }

    #[test]
    fn render_to_texture_then_back_to_the_drawing_buffer() {
        if !available() {
            eprintln!("skip: no headless EGL (run in the mesa container)");
            return;
        }
        const ID: u32 = 4;
        const TEXTURE_2D: u32 = 0x0DE1;
        const RGBA: u32 = 0x1908;
        const UNSIGNED_BYTE: u32 = 0x1401;
        const FRAMEBUFFER: u32 = 0x8D40;
        const COLOR_ATTACHMENT0: u32 = 0x8CE0;
        const FRAMEBUFFER_COMPLETE: u32 = 0x8CD5;
        const NEAREST: i32 = 0x2600;

        create(ID, 4, 4);
        clear(ID, [0, 0, 0, 255], glow::COLOR_BUFFER_BIT);

        // Deliberately smaller than the canvas: a readback of the bound target
        // must use *its* size, not the drawing buffer's.
        let tex = create_texture(ID);
        bind_texture(ID, TEXTURE_2D, tex);
        tex_image_2d(
            ID,
            TEXTURE_2D,
            0,
            RGBA as i32,
            2,
            2,
            0,
            RGBA,
            UNSIGNED_BYTE,
            &[],
            false,
            false,
        );
        tex_parameter_i(ID, TEXTURE_2D, 0x2801, NEAREST);
        tex_parameter_i(ID, TEXTURE_2D, 0x2800, NEAREST);

        let fb = create_framebuffer(ID);
        bind_framebuffer(ID, FRAMEBUFFER, fb);
        framebuffer_texture_2d(ID, FRAMEBUFFER, COLOR_ATTACHMENT0, TEXTURE_2D, tex, 0);
        assert_eq!(
            check_framebuffer_status(ID, FRAMEBUFFER),
            FRAMEBUFFER_COMPLETE,
            "texture-backed framebuffer is complete"
        );
        clear(ID, [7, 8, 9, 255], glow::COLOR_BUFFER_BIT);
        let off = read_pixels(ID, 0, 0, 2, 2, true);
        assert_eq!(
            off.len(),
            2 * 2 * 4,
            "readback is the offscreen target's size"
        );
        assert_eq!(
            &off[0..4],
            &[7, 8, 9, 255],
            "reads back the offscreen target while it is bound"
        );

        // `bindFramebuffer(target, null)` must return to the drawing buffer, which
        // still holds its own clear — not to the (nonexistent) framebuffer 0.
        bind_framebuffer(ID, FRAMEBUFFER, 0);
        assert_eq!(
            &read_pixels(ID, 0, 0, 4, 4, true)[0..4],
            &[0, 0, 0, 255],
            "null framebuffer is the canvas, untouched by the offscreen pass"
        );
        destroy(ID);
    }

    /// A full-viewport textured quad program; `p` is the clip-space position and
    /// `t` the sampler. Shared by the texture tests.
    fn quad_program(id: u32) -> u32 {
        const VS: u32 = 0x8B31;
        const FS: u32 = 0x8B30;
        const ARRAY_BUFFER: u32 = 0x8892;
        const STATIC_DRAW: u32 = 0x88E4;
        const FLOAT: u32 = 0x1406;

        let vs = create_shader(id, VS);
        compile_shader(
            id,
            vs,
            "attribute vec2 p; varying vec2 uv;
             void main(){ uv = p * 0.5 + 0.5; gl_Position = vec4(p, 0.0, 1.0); }",
        );
        assert!(
            shader_compiled(id, vs),
            "vertex shader compiles: {}",
            shader_info_log(id, vs)
        );
        let fs = create_shader(id, FS);
        compile_shader(
            id,
            fs,
            "precision mediump float; uniform sampler2D t; varying vec2 uv;
             void main(){ gl_FragColor = texture2D(t, uv); }",
        );
        assert!(
            shader_compiled(id, fs),
            "fragment shader compiles: {}",
            shader_info_log(id, fs)
        );
        let prog = create_program(id);
        attach_shader(id, prog, vs);
        attach_shader(id, prog, fs);
        link_program(id, prog);
        assert!(program_linked(id, prog), "quad program links");
        use_program(id, prog);

        let verts: [f32; 8] = [-1.0, -1.0, 1.0, -1.0, -1.0, 1.0, 1.0, 1.0];
        let buf = create_buffer(id);
        bind_buffer(id, ARRAY_BUFFER, buf);
        buffer_data(id, ARRAY_BUFFER, bytemuck_cast(&verts), STATIC_DRAW);
        let loc = attrib_location(id, prog, "p");
        assert!(loc >= 0, "attribute 'p' has a location");
        enable_vertex_attrib_array(id, loc as u32);
        vertex_attrib_pointer(id, loc as u32, 2, FLOAT, false, 0, 0);
        prog
    }

    // Minimal f32→bytes without pulling in a dep, for the test only.
    fn bytemuck_cast(v: &[f32]) -> &[u8] {
        unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
    }
}
