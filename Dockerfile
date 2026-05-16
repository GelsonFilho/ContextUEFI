FROM ubuntu:24.04

ARG GHIDRA_VERSION=12.0.1
ARG GHIDRA_DATE=20260114
ARG BINWALK_VERSION=3.1.0
ARG CHIPSEC_TAG=1.13.20

ENV DEBIAN_FRONTEND=noninteractive
ENV CONTEXTUEFI_HOME=/opt/ContextUEFI
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV CONTEXTUEFI_CHIPSEC_DIR=/opt/ContextUEFI/extractors/chipsec
ENV CONTEXTUEFI_UEFIEXTRACT_PATH=/opt/ContextUEFI/extractors/uefiextract
ENV CONTEXTUEFI_GHIDRA_INSTALL_DIR=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV CONTEXTUEFI_PYGHIDRA_PYTHON_PATH=/opt/contextuefi-venv/bin/python
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/opt/contextuefi-venv/bin:/usr/local/cargo/bin:/opt/ContextUEFI/extractors:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cabextract \
    curl \
    device-tree-compiler \
    file \
    git \
    build-essential \
    libbz2-dev \
    libfontconfig1-dev \
    liblzma-dev \
    lz4 \
    lzop \
    openjdk-21-jdk \
    p7zip-full \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    sleuthkit \
    tar \
    unzip \
    xz-utils \
    zlib1g-dev \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Docker builds generally cannot run "snap install" reliably because snapd
# expects systemd, AppArmor, and privileged mounts. The Snap Store stable channel
# currently publishes Binwalk 3.1.0; this installs the same Binwalk version via
# the upstream Rust package, which is suitable for non-privileged Docker builds.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal \
    && chmod -R a+w "${CARGO_HOME}" "${RUSTUP_HOME}" \
    && cargo install binwalk --version "${BINWALK_VERSION}" --locked \
    && binwalk --version

RUN curl -L \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && java -version \
    && "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" 2>&1 | head -n 1

RUN python3 -m venv /opt/contextuefi-venv \
    && /opt/contextuefi-venv/bin/python -m pip install --upgrade pip \
    && /opt/contextuefi-venv/bin/python -m pip install --no-index \
        -f "${GHIDRA_INSTALL_DIR}/Ghidra/Features/PyGhidra/pypkg/dist" \
        pyghidra \
    && /opt/contextuefi-venv/bin/python - <<'PY'
import pyghidra
print("pyghidra", pyghidra.__version__)
PY

WORKDIR ${CONTEXTUEFI_HOME}
COPY . ${CONTEXTUEFI_HOME}

RUN set -eux; \
    rm -rf \
        "${CONTEXTUEFI_HOME}/extractors/chipsec" \
        "${CONTEXTUEFI_HOME}/extractors/uefiextract" \
        "${CONTEXTUEFI_HOME}/extractors/UEFIExtract.exe"; \
    mkdir -p "${CONTEXTUEFI_HOME}/extractors"; \
    git clone --depth 1 --branch "${CHIPSEC_TAG}" \
        https://github.com/chipsec/chipsec.git \
        "${CONTEXTUEFI_HOME}/extractors/chipsec"; \
    curl -L \
        "https://github.com/LongSoft/UEFITool/releases/download/A74/UEFIExtract_NE_A74_x64_linux.zip" \
        -o /tmp/uefiextract.zip; \
    mkdir -p /tmp/uefiextract; \
    unzip -q /tmp/uefiextract.zip -d /tmp/uefiextract; \
    uefiextract_bin="$(find /tmp/uefiextract -type f \( -iname '*uefiextract*' -o -perm /111 \) | head -n 1)"; \
    if [ -z "${uefiextract_bin}" ]; then \
        echo "Could not find the UEFIExtract binary inside the downloaded archive. Archive contents:" >&2; \
        find /tmp/uefiextract -maxdepth 3 -type f -print >&2; \
        exit 1; \
    fi; \
    install -m 0755 "${uefiextract_bin}" "${CONTEXTUEFI_HOME}/extractors/uefiextract"; \
    ln -sf "${CONTEXTUEFI_HOME}/extractors/uefiextract" /usr/local/bin/uefiextract; \
    rm -rf /tmp/uefiextract /tmp/uefiextract.zip

COPY docker-entrypoint.sh /usr/local/bin/contextuefi-docker-entrypoint
RUN chmod +x /usr/local/bin/contextuefi-docker-entrypoint \
    && python -m py_compile \
        contextuefi.py \
        ghidra_backend/__init__.py \
        ghidra_backend/analyser.py \
        ghidra_backend/bootstrap.py \
        ghidra_backend/context_log.py \
        ghidra_backend/guid_db.py \
        ghidra_backend/known_guids.py \
        ghidra_backend/run_module.py \
        ghidra_backend/tables.py \
        ghidra_backend/utils.py

ENTRYPOINT ["contextuefi-docker-entrypoint"]
CMD ["--help"]
