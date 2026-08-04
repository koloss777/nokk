# Design: optional real rendering (`render` feature)

Status: **Phase 1 landed (canvas 2D); WebGL pending.** Giving nokk *real*
off-screen canvas-2D and WebGL rasterization behind an opt-in Cargo feature, so
the default build stays lightweight (synthesis) and a `--features render` build
produces genuine pixels for harder anti-bot.

Implemented today under `--features render`: 2D fills, **real glyph text**
(`fillText`/`strokeText`/`measureText` via a bundled Liberation Sans, in
[crates/pool/src/canvas.rs](../crates/pool/src/canvas.rs)), and image data
`put`/`get`/`toDataURL` — all backed by `tiny-skia` + `ab_glyph`. Paths and
gradients still fall back to the JS deterministic stamp; WebGL is Phase 2.

## Goal & non-goals

**Goal.** When a page draws to a 2D canvas or a WebGL context, produce **real,
consistent pixels** — so `getImageData` / `toDataURL` / `readPixels` return a true
rasterization instead of a synthesized pattern. This closes the single biggest
*passive* fingerprint tell after Web Workers (canvas/WebGL are differential
probes: draw specific content, hash the pixels).

**Non-goals.** No page layout/compositing/paint. No visible window. This is
**off-screen rasterization of the two contexts fingerprinters read**, nothing
more. It is **necessary but not sufficient** for interactive Turnstile (which also
needs Web Workers, cross-origin iframe execution, and full environment coherence
— see [examples/cf-harvester](../examples/cf-harvester) for the real-browser path).

## The opt-in principle

Default nokk must stay light and dependency-thin. Real rendering pulls in a 2D
rasterizer, font stack, and a GL backend — weight and build cost that most users
(scraping JS apps, passive fingerprinting) don't need.

So it is a **Cargo feature**, off by default:

```toml
# crates/dom/Cargo.toml
[features]
default = []
render = ["dep:tiny-skia", "dep:cosmic-text", "dep:glow", "dep:glutin"]   # etc.
```

- `cargo build --release --bin nokk`                     → light (synthesis, today's behavior)
- `cargo build --release --bin nokk --features render`   → real canvas/WebGL rasterization

Two release artifacts (`nokk` and `nokk-render`), two Docker tags
(`:latest` / `:render`), and — for npm/pip — an env/flag to pick which binary the
launcher downloads. The JS/DOM surface is identical either way; only the pixel
backend differs.

## Where the seam goes

Today canvas/WebGL live as **JavaScript** in the stealth/DOM runtime: the drawing
ops are logged and the readback synthesizes a content-dependent pattern (see the
canvas/WebGL notes in [ROADMAP.md](../ROADMAP.md)). Real rasterization must run in
Rust, so the `render` feature introduces a **native canvas/WebGL backend** bridged
to the JS objects via the `natives.rs` mechanism already used by `crypto.subtle`
([crates/pool/src/natives.rs](../crates/pool/src/natives.rs)).

Shape:

```
  JS canvas object  ──(feature off)──▶  synthesize pixels in JS  (today)
        │
        └──────────(feature on)───────▶  __pt_canvas_* native calls ──▶ Rust backend
                                                                          (tiny-skia / GL)
```

A backend trait keeps the two paths swappable and the call sites clean:

```rust
// crates/dom (or a new crates/render)
pub trait Canvas2d {
    fn fill_rect(&mut self, x: f32, y: f32, w: f32, h: f32, style: Paint);
    fn fill_text(&mut self, text: &str, x: f32, y: f32, font: &Font, style: Paint);
    fn stroke_path(&mut self, path: &Path, style: Paint);
    fn draw_image(&mut self, img: &ImageData, dx: f32, dy: f32);
    fn get_image_data(&self, x: u32, y: u32, w: u32, h: u32) -> Vec<u8>; // RGBA
    fn to_png(&self) -> Vec<u8>;
}
#[cfg(feature = "render")] type Backend = SkiaCanvas;   // real
#[cfg(not(feature = "render"))] type Backend = SynthCanvas; // today's synthesis
```

## Canvas 2D backend (`render`)

- **Rasterizer:** [`tiny-skia`](https://crates.io/crates/tiny-skia) — pure-Rust
  Skia subset: fills, strokes, paths, gradients, blend modes, real anti-aliasing.
- **Text (the fingerprint-critical part):** [`cosmic-text`](https://crates.io/crates/cosmic-text)
  for shaping + [`ab_glyph`](https://crates.io/crates/ab_glyph) / `fontdue` for
  glyph rasterization, drawn into the tiny-skia pixmap. `fillText` then produces
  real glyph pixels — exactly what canvas fingerprinting exploits.
  - **Fonts must be bundled & fixed** (e.g. a pinned set: a sans/serif/mono) so
    output is deterministic across hosts and coherent with the reported platform.
    Do **not** use system fonts (host-dependent → incoherent with the spoofed OS).
- **Readback:** `get_image_data` reads the pixmap; `to_png` encodes natively
  (already done today in Rust).

Effort: **medium.** tiny-skia covers most 2D; text shaping/rasterization + font
bundling is the fiddly part.

## WebGL backend (`render`)

Pick one; trade-offs matter:

| Backend | How | Pro | Con |
|---|---|---|---|
| **glow + glutin/EGL (headless)** | real GL context, host GPU or Mesa software | real `readPixels`, standard Rust GL | output tied to host GPU/driver — must report *that* GPU in `UNMASKED_*` |
| **wgpu (GL/Vulkan)** | modern Rust GPU | portable, maintained | heavier; WebGL-1 semantics need care |
| **SwiftShader (C++ FFI)** | Chrome's own software GL | output matches **headless Chrome** most closely | heavy FFI/build integration |

- WebGL fingerprints are host-varied (real users have many GPUs), so a real,
  consistent GL output plausibly passes — **as long as the reported
  `UNMASKED_VENDOR/RENDERER` and `getParameter` values match the backend actually
  rendering.** Coherence is the rule: don't claim "NVIDIA RTX 3060" while rendering
  on Mesa llvmpipe.
- **SwiftShader** is the gold standard for *matching Chrome* (Chrome falls back to
  it with no GPU), at the cost of a C++ dependency.

Minimum surface: context creation, shader compile/link, buffers/attribs, draw,
`readPixels`, `getParameter`/extensions (already Chrome-shaped today; keep pinned
and coherent with the backend).

Effort: **medium-high** (glow) to **high** (SwiftShader).

## Coherence rules (non-negotiable)

- Rendered output must agree with the **reported** identity: WebGL
  vendor/renderer/params, canvas font metrics, `devicePixelRatio`, color depth —
  all consistent with the spoofed OS/GPU. A real-but-mismatched value is a tell.
- Determinism: bundled fonts + fixed backend → same input hashes the same across
  runs (fingerprint *consistency* is itself checked).
- The `render` build's WebGL `UNMASKED_*` should reflect the real backend (e.g.
  SwiftShader strings, or the host GPU), not the synthesis-era hardcoded strings.

## What it buys / what it doesn't

- ✅ Real, consistent, plausible canvas/WebGL fingerprints → closes the biggest
  passive tell after Workers; helps against FingerprintJS/CreepJS-class detection.
- ❌ Does **not** pass interactive Turnstile alone — still missing Web Workers
  (real threading), cross-origin iframe execution, and the rest of the
  rotating-VM environment surface. Rendering is one piece of that puzzle.
- ⚖️ Exact-Chrome match is hard: tiny-skia ≠ Chrome's Skia; a host GPU ≠ a
  "typical" one. Output is real and consistent (a big step up from synthesis), but
  a probe comparing against Chrome-Skia specifics may still differ. SwiftShader +
  bundled-fonts narrows this most.

## Phasing

1. **Phase 1 — Canvas 2D (`render`). ✅ done.** tiny-skia + ab_glyph + a bundled
   font, wired through `natives.rs` (`__pt_canvas*`) and the JS canvas surface.
   Fills, real glyph text, and image data put/get/toDataURL; biggest bang for the
   buck, no GPU/FFI.
2. **Phase 2 — WebGL (`render`).** glow + headless GL (Mesa software for
   determinism, or host GPU). `readPixels` real; keep params coherent.
3. **Phase 3 — SwiftShader (optional, `render-swiftshader`?).** Closest Chrome
   match, C++ FFI. Only if the Chrome-exactness matters.
4. **Distribution.** Build + release `nokk-render` artifacts / `:render` Docker
   tag; teach the npm/pip launchers to select the render binary on request.

## Related

- Why a from-scratch engine can't beat Turnstile in-engine, and the harvest+replay
  hybrid that does: [examples/cf-harvester/docs/RESEARCH.md](../examples/cf-harvester/docs/RESEARCH.md).
- Native-binding mechanism (first used by `crypto.subtle`):
  [crates/pool/src/natives.rs](../crates/pool/src/natives.rs).
