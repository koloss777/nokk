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
    match make_surface(w, h) {
        Ok(surface) => SURFACES.with(|s| {
            s.borrow_mut().insert(id, surface);
        }),
        Err(_) => {} // no GL here; JS layer keeps the stamp
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
    unsafe {
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
        gl.viewport(0, 0, w, h);
    }
    Ok(GlSurface {
        gl,
        w,
        h,
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
fn with_gl<R>(id: u32, f: impl FnOnce(&glow::Context) -> R) -> Option<R> {
    SURFACES.with(|s| {
        let map = s.borrow();
        let surf = map.get(&id)?;
        if let Ok((egl_i, display)) = egl_display() {
            let _ = egl_i.make_current(display, None, None, Some(surf.context));
        }
        Some(f(&surf.gl))
    })
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

/// `gl.clearColor(r,g,b,a); gl.clear(COLOR_BUFFER_BIT)` with straight-alpha input.
pub fn clear(id: u32, rgba: [u8; 4]) {
    with_gl(id, |gl| unsafe {
        gl.clear_color(
            rgba[0] as f32 / 255.0,
            rgba[1] as f32 / 255.0,
            rgba[2] as f32 / 255.0,
            rgba[3] as f32 / 255.0,
        );
        gl.clear(glow::COLOR_BUFFER_BIT);
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

/// `viewport(x, y, w, h)`.
pub fn viewport(id: u32, x: i32, y: i32, w: i32, h: i32) {
    with_gl(id, |gl| unsafe { gl.viewport(x, y, w, h) });
}

/// `readPixels(0,0,w,h,RGBA,UNSIGNED_BYTE)` of the whole surface, row-flipped to
/// canvas' top-left origin (GL reads bottom-left).
pub fn read_pixels(id: u32) -> Vec<u8> {
    SURFACES.with(|s| {
        let map = s.borrow();
        let Some(surf) = map.get(&id) else {
            return Vec::new();
        };
        if let Ok((egl_i, display)) = egl_display() {
            let _ = egl_i.make_current(display, None, None, Some(surf.context));
        }
        let (w, h) = (surf.w as usize, surf.h as usize);
        let mut buf = vec![0u8; w * h * 4];
        unsafe {
            surf.gl.read_pixels(
                0,
                0,
                surf.w,
                surf.h,
                glow::RGBA,
                glow::UNSIGNED_BYTE,
                glow::PixelPackData::Slice(&mut buf),
            );
        }
        // Flip vertically: GL origin is bottom-left, canvas is top-left.
        let stride = w * 4;
        let mut out = vec![0u8; buf.len()];
        for row in 0..h {
            let src = (h - 1 - row) * stride;
            out[row * stride..row * stride + stride].copy_from_slice(&buf[src..src + stride]);
        }
        out
    })
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
        clear(1, [10, 200, 30, 255]);
        let px = read_pixels(1);
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
        clear(2, [0, 0, 0, 255]);

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

        let px = read_pixels(2);
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

    // Minimal f32→bytes without pulling in a dep, for the test only.
    fn bytemuck_cast(v: &[f32]) -> &[u8] {
        unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
    }
}
