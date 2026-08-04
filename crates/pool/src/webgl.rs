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

/// `gl.clearColor(r,g,b,a); gl.clear(COLOR_BUFFER_BIT)` with straight-alpha input.
pub fn clear(id: u32, rgba: [u8; 4]) {
    SURFACES.with(|s| {
        if let Some(surf) = s.borrow().get(&id) {
            unsafe {
                surf.gl.clear_color(
                    rgba[0] as f32 / 255.0,
                    rgba[1] as f32 / 255.0,
                    rgba[2] as f32 / 255.0,
                    rgba[3] as f32 / 255.0,
                );
                surf.gl.clear(glow::COLOR_BUFFER_BIT);
            }
        }
    });
}

/// `readPixels(0,0,w,h,RGBA,UNSIGNED_BYTE)` of the whole surface, row-flipped to
/// canvas' top-left origin (GL reads bottom-left).
pub fn read_pixels(id: u32) -> Vec<u8> {
    SURFACES.with(|s| {
        let map = s.borrow();
        let Some(surf) = map.get(&id) else {
            return Vec::new();
        };
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

    // Runs for real only where Mesa/EGL is present (the mesa test container); a
    // no-op skip elsewhere so `cargo test --features webgl` is green everywhere.
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
}
