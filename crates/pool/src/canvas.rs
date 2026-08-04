//! Optional real 2D canvas rasterization — the `render` feature.
//!
//! With `--features render`, the JS canvas backs its pixel operations with a real
//! [`tiny_skia`] rasterizer instead of the default JS synthesis, so `getImageData`
//! and `toDataURL` return genuine pixels of what was drawn (see docs/rendering.md).
//!
//! One [`Pixmap`] per canvas id, kept **thread-local** — nokk runs one V8 isolate
//! per worker thread, so a per-thread store needs no locking and can't leak across
//! contexts on other threads. The JS layer calls the `__pt_canvas*` natives that
//! wrap these; this is the raster backend, phase 1 (fills + readback). Text, paths
//! and gradients come next; WebGL is a separate phase.

use std::cell::RefCell;
use std::collections::HashMap;

use tiny_skia::{Paint, Pixmap, Rect, Transform};

thread_local! {
    static CANVASES: RefCell<HashMap<u32, Pixmap>> = RefCell::new(HashMap::new());
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
}
