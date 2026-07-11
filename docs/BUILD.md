# Building nokk

nokk's fingerprinted transport is backed by BoringSSL (via
[`wreq`](https://crates.io/crates/wreq) / `boring-sys2`), which is compiled from source
on the first build. That step needs a C/C++ toolchain, **CMake**, and **libclang**
(bindgen uses it to parse BoringSSL's headers).

## With root (recommended)

Debian / Ubuntu:

```bash
sudo apt install build-essential cmake clang libclang-dev
cargo build --release
```

Fedora:

```bash
sudo dnf install gcc gcc-c++ cmake clang clang-devel
cargo build --release
```

macOS (Homebrew):

```bash
brew install cmake llvm
cargo build --release
```

The first build compiles BoringSSL (~45s); it is cached afterward.

## Without root (user-space bootstrap)

If you can't install system packages, CMake and libclang can be provided from
user-space `pip` wheels, and clang's builtin headers borrowed from an existing GCC
install. This is exactly how the reference environment builds.

1. **CMake** — `pip install --user cmake` (lands in `~/.local/bin`; make sure it's on `PATH`).
2. **libclang** — `pip install --user libclang` (lands at
   `~/.local/lib/python3.X/site-packages/clang/native/libclang.so`).
3. **clang builtin headers** (`stddef.h`, etc.) — reuse your GCC ones, e.g.
   `/usr/lib/gcc/x86_64-linux-gnu/12/include`.

Wire it up with a repo-local `.cargo/config.toml` (copy from
[`.cargo/config.toml.example`](../.cargo/config.toml.example) and edit the paths):

```toml
[env]
LIBCLANG_PATH = "/home/you/.local/lib/python3.X/site-packages/clang/native"
BINDGEN_EXTRA_CLANG_ARGS = "-isystem /usr/lib/gcc/x86_64-linux-gnu/12/include -isystem /usr/include"
```

> **Keep these values stable between builds.** Changing `LIBCLANG_PATH` /
> `BINDGEN_EXTRA_CLANG_ARGS` forces `boring-sys2` to rebuild from scratch, which is why
> they live in `.cargo/config.toml` rather than ad-hoc shell exports. The file is
> `.gitignore`d because the paths are machine-specific.

## Verifying the build

```bash
cargo test                      # 48 tests, offline (no network)
cargo run --bin nokk -- --fetch https://tls.browserleaks.com/json
```

The `--fetch` call should return a JA3/JA4 that matches current Chrome.
