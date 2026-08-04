# ============================================================
# AGENT ANONMUSK — Multi-Stage Production Dockerfile
# ============================================================

# --- Builder Stage ---
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Final Stage ---
FROM python:3.12-slim

# Install system dependencies for external tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash anonmusk

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Set ownership
RUN chown -R anonmusk:anonmusk /app

# Switch to non-root user
USER anonmusk

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import core; print('ok')" || exit 1

# Entry point
ENTRYPOINT ["python", "AnonMusk_agent.py"]
