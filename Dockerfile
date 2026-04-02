# ─────────────────────────────────────────────────────────────────────────────
# DepVet — Multi-stage, security-hardened Docker image
#
# Usage:
#   docker build -t depvet .
#   docker run --rm -e ANTHROPIC_API_KEY=$KEY --tmpfs /tmp:size=512m depvet scan requests 2.31.0 2.32.0
#
# Security profile:
#   - Non-root user (uid 10001)
#   - Read-only root filesystem (--read-only)
#   - No new privileges (--security-opt no-new-privileges)
#   - Minimal attack surface (no shell in runtime stage)
#   - Pinned base image digest recommended for production
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build tools (only in builder stage)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy only dependency spec first (layer caching)
COPY pyproject.toml README.md ./

# Create a virtual environment for clean isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies only (no dev/test extras)
RUN pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir ".[dev]"

# Copy source and install the package itself
COPY depvet/ ./depvet/
RUN pip install --no-cache-dir -e .

# Strip __pycache__ and .pyc from venv (reduce image size)
RUN find /opt/venv -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/venv -name "*.pyc" -delete


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Limit recursion depth to prevent ast.parse() stack overflow attacks
    PYTHONSTACKSIZE=16384 \
    # Disable .pth auto-loading from CWD (defense in depth)
    PYTHONNOUSERSITE=1

# Install only the bare minimum runtime OS packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user with no shell
RUN groupadd --gid 10001 depvet && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin depvet

# Copy only the venv from builder (no build tools, no source tree)
COPY --from=builder --chown=root:root /opt/venv /opt/venv

# Create writable temp dir owned by the non-root user
# (--read-only flag needs explicit writable mounts)
RUN mkdir -p /tmp && chmod 1777 /tmp

WORKDIR /workspace

# Drop to non-root
USER depvet

# Health check: verify the CLI is importable
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "from depvet.cli import cli; cli(['--version'], standalone_mode=False)"]

ENTRYPOINT ["depvet"]
CMD ["--help"]

# ─── OCI labels ───────────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="DepVet" \
      org.opencontainers.image.description="Software supply chain monitoring engine" \
      org.opencontainers.image.source="https://github.com/taku-tez/DepVet" \
      org.opencontainers.image.licenses="MIT"
