# docker/python-pipeline.Dockerfile
#
# Python pipeline image. Builds the extended experimentation suite and
# exposes it as a gRPC service. The image is deliberately multi-stage:
# the build stage compiles the Rust extension and installs
# build-time-only dependencies, and the runtime stage copies only the
# compiled artifacts.

ARG PYTHON_VERSION=3.11

# ------------------------------------------------------------------ #
# Build stage
# ------------------------------------------------------------------ #
FROM python:${PYTHON_VERSION}-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for the extension build.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain 1.75.0 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY rust/a3e_core /build/rust/a3e_core
COPY extended_experimentation /build/extended_experimentation
COPY sql /build/sql
COPY pyproject.toml /build/pyproject.toml

RUN cargo build --release --manifest-path rust/a3e_core/Cargo.toml --features python \
    && pip install --no-cache-dir --prefix=/install \
        numpy \
        grpcio \
        grpcio-tools \
        protobuf \
        pyyaml \
        prometheus-client \
    && pip install --no-cache-dir --prefix=/install /build

# ------------------------------------------------------------------ #
# Runtime stage
# ------------------------------------------------------------------ #
FROM python:${PYTHON_VERSION}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY --from=builder /build/rust/a3e_core/target/release/liba3e_core.so /usr/local/lib/python3.11/site-packages/

WORKDIR /app
COPY --from=builder /build/extended_experimentation /app/extended_experimentation
COPY --from=builder /build/sql /app/sql

# Run as a non-root user, because the pipeline's output is the
# subject of the thesis's reproducibility claim and a compromised
# pipeline should not be able to write outside its own directory.
RUN useradd --create-home --uid 10001 pipeline \
    && chown -R pipeline:pipeline /app
USER pipeline

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 9443 9091

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)"

ENTRYPOINT ["python3", "-m", "extended_experimentation.grpc_server"]
