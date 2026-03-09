# syntax=docker/dockerfile:1.6

# Kakadu runtime image (contains /opt/kakadu)
FROM lrosenth/kakadu-base:latest AS kakadu-base

# --- Stage 1: export Python deps from Poetry (runs on a stable Python version) ---
# IMPORTANT: This Dockerfile expects the *build context* to be the repository root
# (the directory that contains `pyproject.toml` / `poetry.lock`).
# Build from repo root like:
#   docker build -f mediaserver/Dockerfile -t <tag> .
FROM python:3.12-slim AS requirements

WORKDIR /build

# Only needed to run `poetry export` during build
RUN pip install --no-cache-dir "poetry>=2" "poetry-plugin-export>=1.8"

# Copy only the dependency manifests first (maximizes Docker layer cache hits)
COPY pyproject.toml poetry.lock ./

# Export runtime deps only
RUN poetry export --only main -f requirements.txt --without-hashes -o requirements.txt \
 && awk 'BEGIN{IGNORECASE=1} !/^virtualenv==/ && !/^poetry==/ && !/^poetry-core==/ && !/^poetry-plugin-export==/ {print}' requirements.txt > requirements.runtime.txt \
 && mv requirements.runtime.txt requirements.txt


# --- Stage 2: final runtime image ---
FROM python:3.14-slim

# Bring Kakadu runtime in
COPY --from=kakadu-base /opt/kakadu /opt/kakadu
ENV LD_LIBRARY_PATH=/opt/kakadu/lib
ENV PATH="/opt/kakadu/bin:${PATH}"

WORKDIR /app

# System deps
# - libvips42: runtime library for pyvips
# - ffmpeg: audio/video conversions
# Add a couple of apt retries (helps with flaky mirrors)
RUN apt-get update -o Acquire::Retries=5 \
 && apt-get install -y --no-install-recommends \
      libvips42 \
      ffmpeg \
 && rm -rf /var/lib/apt/lists/*

# Python deps (installed via pip from exported requirements)
COPY --from=requirements /build/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Your Flask app (mediaserver is a subdir; paths are relative to repo-root build context)
COPY mediaserver/app.py /app/app.py
COPY mediaserver/oldap_client.py /app/oldap_client.py
COPY mediaserver/__init__.py /app/__init__.py
COPY mediaserver/Makefile /app/Makefile

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Default command (can be overridden in docker-compose.yml for env-specific tuning)
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
