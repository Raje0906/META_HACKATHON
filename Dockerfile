# ─── Runtime image ────────────────────────────────────────────────────────
FROM python:3.11-slim

# Labels
LABEL maintainer="SOC Simulator Team"
LABEL description="AI Cybersecurity Incident Response Environment — OpenEnv compliant"
LABEL version="1.0.0"

# ─── System deps ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ─── Create non-root user (HF Spaces requirement) ─────────────────────────
RUN useradd -m -u 1000 appuser

# ─── Working directory ────────────────────────────────────────────────────
WORKDIR /app

# ─── Install Python dependencies ───────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ─── Copy project ──────────────────────────────────────────────────────────
COPY . .

# Create outputs directories
RUN mkdir -p outputs/logs outputs/evals && \
    chown -R appuser:appuser /app

# ─── Switch to non-root ────────────────────────────────────────────────────
USER appuser

# ─── Environment variables ─────────────────────────────────────────────────
ENV PORT=7860
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENABLE_WEB_INTERFACE=true

# ─── Healthcheck ───────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:${PORT}/health || exit 1

# ─── Expose port ───────────────────────────────────────────────────────────
EXPOSE 7860

# ─── Entry point ───────────────────────────────────────────────────────────
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
