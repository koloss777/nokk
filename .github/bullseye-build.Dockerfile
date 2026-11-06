# Builds the release binary and the Linux wheel in Debian 11 (bullseye, glibc 2.31)
# so they run on a broad range of Linux — RHEL/Alma 9 (2.34), Ubuntu 20.04+,
# Debian 11+ — instead of the runner's glibc. Driven by release.yml and
# python-wheels.yml through `docker build --target <x>-out --output type=local`:
# a `docker run` with apt inside does not work under the runner's docker (apt's
# lock dirs are not writable there), a build does.
#
# bullseye is past its security support and deb.debian.org no longer serves its
# security pool; the image is built from snapshot.debian.org, whose lines sit
# commented in its sources.list, and those still have every package at the exact
# version the image expects (clang pins libc6-i386 to the image's libc). It has
# outages (503 "No healthy backends"), hence the retries.
FROM rust:1-bullseye AS base
RUN grep "^# deb http://snapshot" /etc/apt/sources.list | sed "s/^# //" > /tmp/sources.list \
 && APT="apt-get -o Dir::Etc::SourceList=/tmp/sources.list -o Dir::Etc::SourceParts=/dev/null -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3" \
 && for try in 1 2 3 4 5; do \
      $APT update -qq && $APT install -y --no-install-recommends clang libclang-dev pkg-config python3 python3-pip patchelf && break; \
      [ $try = 5 ] && exit 1; echo "snapshot.debian.org failed, retrying in 60 s"; sleep 60; \
    done \
 && pip3 install --no-cache-dir cmake maturin \
 && ln -s "$(dirname "$(find /usr/lib -name 'libclang.so*' | head -1)")" /opt/libclang \
 && rm -rf /var/lib/apt/lists/*
ENV LIBCLANG_PATH=/opt/libclang
WORKDIR /w
# .dockerignore keeps the host's .cargo/config.toml out, so the prebuilt V8 is
# fetched from the rusty_v8 release like in any fresh checkout.
COPY . .

# The release binary, as `cargo build --release` makes it: the light build
# (no rasterizers; the default features are empty).
FROM base AS bin
# Release version for `nokk --version`, from the tag (empty in a local build).
ARG NOKK_VERSION=
ENV NOKK_VERSION=$NOKK_VERSION
RUN cargo build --release --bin nokk
FROM scratch AS bin-out
COPY --from=bin /w/target/release/nokk /nokk

# The render variant: the opt-in rasterizers compiled in explicitly
# (docs/rendering.md). Chained after `bin` so it reuses that target dir.
FROM bin AS bin-render
RUN cargo build --release -p nokk-cli --features render,webgl --bin nokk
FROM scratch AS bin-render-out
COPY --from=bin-render /w/target/release/nokk /nokk

# The Linux wheel: maturin builds the binary again from python/pyproject.toml
# (it names crates/cli), embeds it and auditwheel-tags the wheel manylinux_2_31.
# The light build, like the binary pip users get; chained after `bin` for its
# target dir, not after the render build, which the wheel does not need.
FROM bin AS wheel
RUN cd python && maturin build --release --out dist
FROM scratch AS wheel-out
COPY --from=wheel /w/python/dist/ /
