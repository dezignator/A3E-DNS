# docker/rust-core.Dockerfile
#
# Rust core image. Used by the CI to build and test the a3e_core crate
# in isolation, and by the Python pipeline image as a source of the
# compiled extension. The image is not deployed on its own; it is a
# build-stage dependency.

FROM rust:1.75-bookworm AS builder

WORKDIR /build
COPY rust/a3e_core /build/rust/a3e_core

WORKDIR /build/rust/a3e_core

RUN cargo build --release --features python \
    && cargo test --release

# ------------------------------------------------------------------ #
# Export stage
# ------------------------------------------------------------------ #
FROM scratch AS export

COPY --from=builder /build/rust/a3e_core/target/release/liba3e_core.so /
COPY --from=builder /build/rust/a3e_core/Cargo.toml /Cargo.toml
COPY --from=builder /build/rust/a3e_core/README.md /README.md
