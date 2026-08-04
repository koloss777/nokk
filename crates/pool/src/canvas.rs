//! Optional real 2D canvas rasterization — the `render` feature.
//!
//! With `--features render`, the JS canvas backs its pixel operations with a real
//! [`tiny_skia`] rasterizer instead of the default JS synthesis, so `getImageData`
//! and `toDataURL` return genuine pixels of what was drawn (see docs/rendering.md).
//!
//! One [`Pixmap`] per canvas id, kept **thread-local** — nokk runs one V8 isolate
//! per worker thread, so a per-thread store needs no locking and can't leak across
//! contexts on other threads. The JS layer calls the `__pt_canvas*` natives that
//! wrap these. Covered here: fills, real glyph text (`fill_text`/`measure_text`
//! via a bundled font), vector paths (`fill_path`/`stroke_path` — the JS side
//! tessellates curves/arcs to a move/line/close verb stream), linear/radial
//! gradients (`fill_path_grad`), and image data put/get. Only `drawImage` still
//! falls back to the JS deterministic stamp; WebGL is a separate phase.

use std::cell::RefCell;
use std::collections::HashMap;

use ab_glyph::{Font, FontRef, PxScale, ScaleFont};
use tiny_skia::{
    Color, FillRule, GradientStop, LinearGradient, Paint, PathBuilder, Pixmap, Point,
    RadialGradient, Rect, Shader, SpreadMode, Stroke, Transform,
};

/// Bundled Liberation Sans (OFL, Arial-metric) — a plausible default sans for a
/// Linux Chrome profile, so `fillText` glyphs are real *and* deterministic.
const FONT_BYTES: &[u8] = include_bytes!("../fonts/LiberationSans-Regular.ttf");

thread_local! {
    static CANVASES: RefCell<HashMap<u32, Pixmap>> = RefCell::new(HashMap::new());
    static FONT: FontRef<'static> =
        FontRef::try_from_slice(FONT_BYTES).expect("bundled font parses");
}

/// Cap per-side pixels so a hostile page can't request an absurd allocation.
const MAX_DIM: u32 = 8192;

/// Create (or reset) a canvas surface of `w`×`h`.
pub fn create(id: u32, w: u32, h: u32) {
    let (w, h) = (w.clamp(1, MAX_DIM), h.clamp(1, MAX_DIM));
    if let Some(pm) = Pixmap::new(w, h) {
        CANVASES.with(|c| {
            c.borrow_mut().insert(id, pm);
        });
    }
}

/// Drop a canvas surface (the JS wrapper was garbage-collected).
pub fn destroy(id: u32) {
    CANVASES.with(|c| {
        c.borrow_mut().remove(&id);
    });
}

/// `fillRect(x, y, w, h)` with a straight-alpha RGBA color.
pub fn fill_rect(id: u32, x: f32, y: f32, w: f32, h: f32, rgba: [u8; 4]) {
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            if let Some(rect) = Rect::from_xywh(x, y, w, h) {
                pm.fill_rect(rect, &paint, Transform::identity(), None);
            }
        }
    });
}

/// `clearRect(x, y, w, h)` — set the region back to transparent.
pub fn clear_rect(id: u32, x: f32, y: f32, w: f32, h: f32) {
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let mut paint = Paint::default();
            paint.set_color_rgba8(0, 0, 0, 0);
            paint.blend_mode = tiny_skia::BlendMode::Source; // overwrite, don't blend
            if let Some(rect) = Rect::from_xywh(x, y, w, h) {
                pm.fill_rect(rect, &paint, Transform::identity(), None);
            }
        }
    });
}

/// Build a [`tiny_skia::Path`] from a flat verb stream: `0,x,y` = moveTo,
/// `1,x,y` = lineTo, `4` = close. Curves and arcs are tessellated to line
/// segments on the JS side, so this stays a simple, robust decoder.
fn path_from_verbs(verbs: &[f32]) -> Option<tiny_skia::Path> {
    let mut pb = PathBuilder::new();
    let mut i = 0;
    while i < verbs.len() {
        match verbs[i].round() as i32 {
            0 if i + 2 < verbs.len() => {
                pb.move_to(verbs[i + 1], verbs[i + 2]);
                i += 3;
            }
            1 if i + 2 < verbs.len() => {
                pb.line_to(verbs[i + 1], verbs[i + 2]);
                i += 3;
            }
            4 => {
                pb.close();
                i += 1;
            }
            _ => break, // unknown/truncated verb — stop rather than misread
        }
    }
    pb.finish()
}

/// `fill()` a tessellated path with a straight-alpha RGBA color. `even_odd`
/// selects the fill rule (canvas `'evenodd'` vs default nonzero winding).
pub fn fill_path(id: u32, verbs: &[f32], even_odd: bool, rgba: [u8; 4]) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            let rule = if even_odd {
                FillRule::EvenOdd
            } else {
                FillRule::Winding
            };
            pm.fill_path(&path, &paint, rule, Transform::identity(), None);
        }
    });
}

/// Decode a flat gradient descriptor into a tiny-skia [`Shader`]:
/// `[type, x0,y0, x1,y1, r0,r1, nstops, (pos,r,g,b,a)×nstops]` — `type` 0 linear,
/// 1 radial; colors are straight-alpha 0..255. Canvas's inner radius `r0` is
/// approximated away (mapped to the focal point), which is invisible for the
/// usual `r0 = 0` fingerprint gradients.
fn shader_from_grad(g: &[f32]) -> Option<Shader<'static>> {
    if g.len() < 8 {
        return None;
    }
    let ty = g[0].round() as i32;
    let (x0, y0, x1, y1, r1) = (g[1], g[2], g[3], g[4], g[6]);
    let n = g[7].max(0.0) as usize;
    let mut raw: Vec<(f32, Color)> = Vec::with_capacity(n);
    let mut idx = 8;
    for _ in 0..n {
        if idx + 5 > g.len() {
            break;
        }
        let pos = g[idx].clamp(0.0, 1.0);
        let color = Color::from_rgba8(
            g[idx + 1] as u8,
            g[idx + 2] as u8,
            g[idx + 3] as u8,
            g[idx + 4] as u8,
        );
        raw.push((pos, color));
        idx += 5;
    }
    if raw.is_empty() {
        return None;
    }
    if raw.len() == 1 {
        raw.push((1.0, raw[0].1)); // tiny-skia needs ≥2 stops; a lone stop → solid
    }
    let stops: Vec<GradientStop> = raw
        .into_iter()
        .map(|(p, c)| GradientStop::new(p, c))
        .collect();
    if ty == 1 {
        RadialGradient::new(
            Point::from_xy(x0, y0),
            Point::from_xy(x1, y1),
            r1.max(0.01),
            stops,
            SpreadMode::Pad,
            Transform::identity(),
        )
    } else {
        LinearGradient::new(
            Point::from_xy(x0, y0),
            Point::from_xy(x1, y1),
            stops,
            SpreadMode::Pad,
            Transform::identity(),
        )
    }
}

/// `fill()` a tessellated path with a linear/radial gradient (see
/// [`shader_from_grad`] for the descriptor layout).
pub fn fill_path_grad(id: u32, verbs: &[f32], even_odd: bool, grad: &[f32]) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    let Some(shader) = shader_from_grad(grad) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let paint = Paint {
                shader,
                anti_alias: true,
                ..Paint::default()
            };
            let rule = if even_odd {
                FillRule::EvenOdd
            } else {
                FillRule::Winding
            };
            pm.fill_path(&path, &paint, rule, Transform::identity(), None);
        }
    });
}

/// `stroke()` a tessellated path with `line_width` and a straight-alpha color.
pub fn stroke_path(id: u32, verbs: &[f32], line_width: f32, rgba: [u8; 4]) {
    let Some(path) = path_from_verbs(verbs) else {
        return;
    };
    CANVASES.with(|c| {
        if let Some(pm) = c.borrow_mut().get_mut(&id) {
            let mut paint = Paint::default();
            paint.set_color_rgba8(rgba[0], rgba[1], rgba[2], rgba[3]);
            paint.anti_alias = true;
            let stroke = Stroke {
                width: line_width.max(0.0),
                ..Stroke::default()
            };
            pm.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
        }
    });
}

/// Composite a coverage-weighted straight-alpha color over one premultiplied pixel.
fn blend_over(data: &mut [u8], i: usize, rgba: [u8; 4], coverage: f32) {
    let sa = (rgba[3] as f32 / 255.0) * coverage.clamp(0.0, 1.0); // src alpha 0..1
    if sa <= 0.0 {
        return;
    }
    // src premultiplied; dst is already premultiplied (tiny-skia).
    let sr = rgba[0] as f32 / 255.0 * sa;
    let sg = rgba[1] as f32 / 255.0 * sa;
    let sb = rgba[2] as f32 / 255.0 * sa;
    let inv = 1.0 - sa;
    let out = |src: f32, dst: u8| {
        ((src + (dst as f32 / 255.0) * inv) * 255.0)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    data[i] = out(sr, data[i]);
    data[i + 1] = out(sg, data[i + 1]);
    data[i + 2] = out(sb, data[i + 2]);
    data[i + 3] = out(sa, data[i + 3]);
}

/// `fillText(text, x, y)` — rasterize real glyphs of the bundled font at `size_px`,
/// `y` being the alphabetic baseline (as canvas specifies), composited into the
/// surface. This is the fingerprint-critical op: real, deterministic text pixels
/// instead of a synthesized pattern.
pub fn fill_text(id: u32, text: &str, x: f32, y: f32, size_px: f32, rgba: [u8; 4]) {
    if size_px <= 0.0 || text.is_empty() {
        return;
    }
    CANVASES.with(|c| {
        let mut map = c.borrow_mut();
        let Some(pm) = map.get_mut(&id) else {
            return;
        };
        let (pw, ph) = (pm.width() as i32, pm.height() as i32);
        let data = pm.data_mut();
        FONT.with(|font| {
            let scale = PxScale::from(size_px);
            let scaled = font.as_scaled(scale);
            let mut caret = x;
            for ch in text.chars() {
                let gid = font.glyph_id(ch);
                let glyph = gid.with_scale_and_position(scale, ab_glyph::point(caret, y));
                if let Some(og) = font.outline_glyph(glyph) {
                    let bb = og.px_bounds();
                    og.draw(|gx, gy, coverage| {
                        let px = bb.min.x as i32 + gx as i32;
                        let py = bb.min.y as i32 + gy as i32;
                        if px < 0 || py < 0 || px >= pw || py >= ph {
                            return;
                        }
                        blend_over(data, ((py * pw + px) * 4) as usize, rgba, coverage);
                    });
                }
                caret += scaled.h_advance(gid);
            }
        });
    });
}

/// `measureText(text).width` for the bundled font at `size_px`.
pub fn measure_text(text: &str, size_px: f32) -> f32 {
    if size_px <= 0.0 {
        return 0.0;
    }
    FONT.with(|font| {
        let scaled = font.as_scaled(PxScale::from(size_px));
        text.chars()
            .map(|ch| scaled.h_advance(font.glyph_id(ch)))
            .sum()
    })
}

/// `putImageData(data, x, y)` — overwrite a `w`×`h` region with straight-alpha
/// RGBA (premultiplying into the surface). Replaces, does not blend, as the spec
/// requires. Pixels outside the surface are dropped.
pub fn put_image_data(id: u32, x: i32, y: i32, w: u32, h: u32, data: &[u8]) {
    CANVASES.with(|c| {
        let mut map = c.borrow_mut();
        let Some(pm) = map.get_mut(&id) else {
            return;
        };
        let (pw, ph) = (pm.width() as i32, pm.height() as i32);
        let out = pm.data_mut();
        for row in 0..h as i32 {
            for col in 0..w as i32 {
                let (dx, dy) = (x + col, y + row);
                if dx < 0 || dy < 0 || dx >= pw || dy >= ph {
                    continue;
                }
                let si = ((row * w as i32 + col) * 4) as usize;
                if si + 3 >= data.len() {
                    continue;
                }
                let a = data[si + 3] as u32;
                let prem = |v: u8| ((v as u32 * a + 127) / 255) as u8;
                let di = ((dy * pw + dx) * 4) as usize;
                out[di] = prem(data[si]);
                out[di + 1] = prem(data[si + 1]);
                out[di + 2] = prem(data[si + 2]);
                out[di + 3] = a as u8;
            }
        }
    });
}

/// Straight (un-premultiplied) RGBA for a `w`×`h` region at `(x, y)` — exactly what
/// canvas `getImageData` returns. Pixels outside the surface read as transparent.
pub fn get_image_data(id: u32, x: u32, y: u32, w: u32, h: u32) -> Vec<u8> {
    CANVASES.with(|c| {
        let map = c.borrow();
        let mut out = vec![0u8; (w as usize) * (h as usize) * 4];
        let Some(pm) = map.get(&id) else {
            return out;
        };
        let (pw, ph) = (pm.width(), pm.height());
        let data = pm.data(); // premultiplied RGBA8
        for row in 0..h {
            for col in 0..w {
                let (sx, sy) = (x + col, y + row);
                if sx >= pw || sy >= ph {
                    continue;
                }
                let si = ((sy * pw + sx) * 4) as usize;
                let di = ((row * w + col) * 4) as usize;
                let a = data[si + 3];
                // tiny-skia stores premultiplied alpha; getImageData is straight.
                let unmul = |v: u8| {
                    if a == 0 {
                        0
                    } else {
                        (((v as u32) * 255 + (a as u32) / 2) / a as u32).min(255) as u8
                    }
                };
                out[di] = unmul(data[si]);
                out[di + 1] = unmul(data[si + 1]);
                out[di + 2] = unmul(data[si + 2]);
                out[di + 3] = a;
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_then_read_is_exact() {
        create(1, 4, 4);
        fill_rect(1, 0.0, 0.0, 4.0, 4.0, [255, 0, 0, 255]);
        let px = get_image_data(1, 0, 0, 1, 1);
        assert_eq!(px, vec![255, 0, 0, 255], "opaque red fill reads back red");
        clear_rect(1, 0.0, 0.0, 4.0, 4.0);
        assert_eq!(
            get_image_data(1, 0, 0, 1, 1),
            vec![0, 0, 0, 0],
            "cleared → transparent"
        );
        destroy(1);
    }

    #[test]
    fn fill_text_draws_real_glyph_pixels() {
        create(2, 40, 40);
        // Baseline near the bottom so a 24px 'H' lands inside the surface.
        fill_text(2, "H", 4.0, 30.0, 24.0, [0, 0, 0, 255]);
        let px = get_image_data(2, 0, 0, 40, 40);
        let opaque = px.chunks_exact(4).filter(|p| p[3] > 0).count();
        assert!(
            opaque > 20,
            "glyph 'H' must cover real pixels, got {opaque}"
        );
        destroy(2);
    }

    #[test]
    fn fill_path_triangle_covers_interior() {
        create(3, 20, 20);
        // A filled triangle: (2,2) (18,2) (10,18).
        let verbs = [0.0, 2.0, 2.0, 1.0, 18.0, 2.0, 1.0, 10.0, 18.0, 4.0];
        fill_path(3, &verbs, false, [0, 0, 255, 255]);
        // Center of mass ~ (10, 7) is inside; a far corner is outside.
        let inside = get_image_data(3, 10, 7, 1, 1);
        let corner = get_image_data(3, 0, 19, 1, 1);
        assert!(
            inside[3] > 0 && inside[2] > 100,
            "interior filled blue, got {inside:?}"
        );
        assert_eq!(corner[3], 0, "outside the triangle stays transparent");
        destroy(3);
    }

    #[test]
    fn linear_gradient_fill_varies_across_the_rect() {
        create(4, 20, 4);
        // Linear red→blue across x=0..20, filling the whole surface via a rect path.
        let grad = [
            0.0, 0.0, 0.0, 20.0, 0.0, 0.0, 0.0, 2.0, // type,x0,y0,x1,y1,r0,r1,nstops
            0.0, 255.0, 0.0, 0.0, 255.0, // stop 0 @0.0 = red
            1.0, 0.0, 0.0, 255.0, 255.0, // stop 1 @1.0 = blue
        ];
        let verbs = [
            0.0, 0.0, 0.0, 1.0, 20.0, 0.0, 1.0, 20.0, 4.0, 1.0, 0.0, 4.0, 4.0,
        ];
        fill_path_grad(4, &verbs, false, &grad);
        let left = get_image_data(4, 1, 2, 1, 1);
        let right = get_image_data(4, 18, 2, 1, 1);
        assert!(
            left[0] > 150 && left[2] < 100,
            "left edge is red-ish, got {left:?}"
        );
        assert!(
            right[2] > 150 && right[0] < 100,
            "right edge is blue-ish, got {right:?}"
        );
        destroy(4);
    }

    #[test]
    fn measure_text_is_positive_and_scales() {
        let w1 = measure_text("nokk", 16.0);
        let w2 = measure_text("nokk", 32.0);
        assert!(w1 > 0.0, "non-empty text has width");
        assert!(
            w2 > w1 * 1.9,
            "2x font size ~doubles advance ({w1} vs {w2})"
        );
        assert_eq!(measure_text("", 16.0), 0.0, "empty text has zero width");
    }
}
