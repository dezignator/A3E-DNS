# ============================================================
# A3E-DNS — Dockerfile (CPU-only image)
# Thesis artifact (Chapter 6) · §6.11.2 software stack
# ============================================================
# Base: Ubuntu Server 22.04 LTS (§6.11.1)
# Python: 3.11 (§6.11.2)
# Target: CPU-only reproduction of Tier A and Tier B artifacts
#         (see REPRODUCIBILITY_CHECKLIST.md).

FROM ubuntu:22.04 AS base

LABEL org.opencontainers.image.title="A3E-DNS" \
      org.opencontainers.image.description="Next-Generation Secure and Adaptive Evolutionary Encryption for DoH, DoT and DoQ — thesis artifact (Chapter 6)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ---------- System packages ----------
# Network capture, protocol inspection, observability — matches §6.11.2
RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common \
        build-essential \
        ca-certificates \
        curl \
        wget \
        git \
        gnupg \
        lsb-release \
        pkg-config \
        libssl-dev \
        libffi-dev \
        libgmp-dev \
        libsodium-dev \
        libboost-all-dev \
        libpcap-dev \
        libpcre3-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        graphviz \
        tshark \
        tcpdump \
        wireshark-common \
        openvswitch-common \
        openvswitch-switch \
        iproute2 \
        iputils-ping \
        net-tools \
        socat \
        jq \
        unzip \
        sqlite3 \
        protobuf-compiler \
        libgrpc-dev \
        mininet \
        && rm -rf /var/lib/apt/lists/*

# ---------- Python 3.11 (matches §6.11.2) ----------
RUN add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3.11 \
        python3.11-dev \
        python3.11-venv \
        python3.11-distutils \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python  python  /usr/bin/python3.11 1 \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11

WORKDIR /opt/a3e-dns

# ---------- Python dependencies (pinned) ----------
COPY requirements.txt ./
RUN python3.11 -m pip install --upgrade pip setuptools wheel \
    && python3.11 -m pip install -r requirements.txt

# ---------- Project source ----------
COPY setup.py ./
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY configs/ ./configs/
COPY data/ ./data/
COPY expected_outputs/ ./expected_outputs/
COPY tests/ ./tests/
COPY docs/ ./docs/
COPY notebooks/ ./notebooks/
COPY README.md STATUS.md REPRODUCIBILITY_CHECKLIST.md LIMITATIONS.md ./

# ---------- Editable install (matches quick-start in README) ----------
RUN python3.11 -m pip install -e .

# ---------- Non-root user ----------
RUN useradd --create-home --shell /bin/bash a3e \
    && chown -R a3e:a3e /opt/a3e-dns
USER a3e

# ---------- Environment ----------
ENV A3E_DNS_HOME=/opt/a3e-dns \
    A3E_DNS_MODE=toy \
    PYTHONPATH=/opt/a3e-dns

# ---------- Healthcheck ----------
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3.11 -c "import src; print('ok')" || exit 1

# ---------- Entrypoint ----------
# Default: run the full toy reproduction (Tier A) end-to-end.
ENTRYPOINT ["python3.11", "-m", "src"]
CMD ["--mode", "toy", "--verify"]
