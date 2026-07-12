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
# the prebuilt V8 static library, then links a release binary.
RUN cargo build --release --bin nokk

# ---- runtime stage ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: TLS root store for outbound HTTPS (without it every fetch
# fails cert validation). libstdc++6/libgcc: the V8 static lib is C++.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/nokk /usr/local/bin/nokk

# Drop privileges.
RUN useradd --system --uid 10001 --user-group nokk
USER nokk

EXPOSE 9222
# Bind to all interfaces so the container's mapped port is reachable from the
# host; override args freely (e.g. --workers, --max-contexts, or a one-shot mode).
ENTRYPOINT ["nokk"]
CMD ["--host", "0.0.0.0", "--port", "9222"]
