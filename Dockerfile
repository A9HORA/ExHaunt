# =========================================================
# ExHaunt — Binary-only image via Nuitka
# GLIBC-safe: builder/runtime pinned by codename
# YAML-resilient: defaults embedded + runtime copies + overrideable
# =========================================================
ARG DEBIAN_CODENAME=bookworm      # switch both stages together (e.g., trixie)
ARG PYTHON_VER=3.13

# ---------------------------
# Stage 1: Build the binary
# ---------------------------
FROM python:${PYTHON_VER}-slim-${DEBIAN_CODENAME} AS builder
ARG DEBIAN_CODENAME
ARG PYTHON_VER

ENV PIP_NO_CACHE_DIR=1
WORKDIR /src

# Toolchain for Nuitka/C extensions + patchelf (required for --onefile on Linux)
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential python3-dev ca-certificates patchelf \
  && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt /src/requirements.txt
RUN pip install --no-cache-dir -r /src/requirements.txt \
  && pip install --no-cache-dir nuitka

# App sources (flat layout at repo root)
COPY . /src

# Build native onefile binary; embed YAMLs at bundle root
# Using relative paths since WORKDIR=/src
RUN python -m nuitka \
    --onefile \
    --follow-imports \
    --output-filename=exhaunt \
    --include-data-files=fingerprints.yaml=fingerprints.yaml \
    --include-data-files=providers.yaml=providers.yaml \
    exhaunt.py

# ---------------------------
# Stage 2: Runtime (no source code)
# ---------------------------
FROM debian:${DEBIAN_CODENAME}-slim
ARG DEBIAN_CODENAME

# Minimal runtime libs; keep distro in lockstep with builder (GLIBC match)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Writable working dir for inputs/outputs
WORKDIR /workspace

# Non-root for safety
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /workspace
USER appuser

# Ship runtime copies of YAMLs (data, not code) for guaranteed availability
COPY --from=builder /src/providers.yaml    /providers.yaml
COPY --from=builder /src/fingerprints.yaml /fingerprints.yaml

# Default providers file path to eliminate warnings
ENV EXHAUNT_PROVIDERS_FILE=/providers.yaml

# Copy ONLY the native binary produced by Nuitka (no .py in final image)
COPY --from=builder /src/exhaunt /usr/local/bin/exhaunt

# Default entry; flags after image name go to the binary
ENTRYPOINT ["exhaunt"]
CMD ["--help"]
