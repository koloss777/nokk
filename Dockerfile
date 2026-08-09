# syntax=docker/dockerfile:1

# ---- build stage --------------------------------------------------------------
FROM rust:1-bookworm AS build

# BoringSSL (via wreq) is compiled from source, so the build needs cmake + a
# C/C++ toolchain; bindgen needs libclang. With root in the builder these come
# straight from apt (no user-space bootstrap needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build just the binary. The first build compiles BoringSSL (~45s) and downloads
# the prebuilt V8 static library, then links a release binary (stripped).
RUN cargo build --release --bin nokk

# ---- build stage: render variant ----------------------------------------------
# The same binary with the opt-in rasterizers compiled in (docs/rendering.md):
# `render` = tiny-skia/ab_glyph canvas 2D, `webgl` = a real headless GL context.
# Kept a separate stage so the default image stays light and the two builds cache
# independently (they don't share a target dir, but they do share the BoringSSL
# and V8 layers above).
FROM build AS build-render
RUN cargo build --release -p nokk-cli --features render,webgl --bin nokk

# ---- runtime: debian variant (has a shell; easy to exec/debug) ----------------
FROM debian:bookworm-slim AS debian
# ca-certificates: TLS root store for outbound HTTPS. libstdc++6/libgcc: V8 is C++.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/nokk /usr/local/bin/nokk
RUN useradd --system --uid 10001 --user-group nokk
USER nokk
EXPOSE 9222
ENTRYPOINT ["nokk"]
CMD ["--host", "0.0.0.0", "--port", "9222"]

# ---- runtime: render variant (real canvas/WebGL rasterization) ----------------
# Carries the Mesa stack the `webgl` feature dlopen's at runtime (libEGL.so.1 +
# the swrast DRI driver); without it the engine silently falls back to the JS
# synthesis, so the packages are the whole point of this image.
FROM debian:bookworm-slim AS render
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 \
        libegl1 libgl1-mesa-dri libglx-mesa0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-render /src/target/release/nokk /usr/local/bin/nokk
RUN useradd --system --uid 10001 --user-group nokk
USER nokk
EXPOSE 9222
ENTRYPOINT ["nokk"]
CMD ["--host", "0.0.0.0", "--port", "9222"]

# ---- runtime: distroless variant (default; smallest, no shell) ----------------
# glibc + libgcc + libstdc++ + CA certs only — no shell, no package manager.
# This is the LAST stage, so a plain `docker build` produces the small image.
FROM gcr.io/distroless/cc-debian12 AS distroless
COPY --from=build /src/target/release/nokk /usr/local/bin/nokk
# distroless ships a `nonroot` user (uid 65532).
USER nonroot
EXPOSE 9222
ENTRYPOINT ["/usr/local/bin/nokk"]
CMD ["--host", "0.0.0.0", "--port", "9222"]
