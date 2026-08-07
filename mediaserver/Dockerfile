# syntax=docker/dockerfile:1.6

# --- Stage 1: export Python deps from Poetry (runs on a stable Python version) ---
# IMPORTANT: This Dockerfile expects the *build context* to be the repository root
# (the directory that contains `pyproject.toml` / `poetry.lock`).
# `mediaserver/Dockerfile.dockerignore` keeps that root context limited to the
# dependency manifests and the media helper source files.
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

# Copy only the architecture-neutral veraPDF application from the official,
# production-tagged image. The final stage supplies its native Debian JRE.
FROM --platform=linux/amd64 verapdf/cli:v1.30.2@sha256:d5ee329657cf9bc4b2400392dd54c7d0a0ce9980ff6fa2da5590eebeec007cdb AS verapdf


# --- Stage 2: final runtime image ---
FROM python:3.14-slim

ARG MEDIAHELPER_VERSION

LABEL org.opencontainers.image.title="OLDAP Mediahelper"
LABEL org.opencontainers.image.description="Upload and asset authorization service for OLDAP media"
LABEL org.opencontainers.image.version="${MEDIAHELPER_VERSION}"

WORKDIR /app

# System deps
# - libvips42: runtime library for pyvips
# - ffmpeg: audio/video conversions
# - poppler-utils: first-page rendering for PDF thumbnails via pdf2image
# Add a couple of apt retries (helps with flaky mirrors)
RUN apt-get update -o Acquire::Retries=5 \
 && apt-get install -y --no-install-recommends \
      libvips42 \
      ffmpeg \
      poppler-utils \
      qpdf \
      libseccomp2 \
      default-jre-headless \
 && rm -rf /var/lib/apt/lists/*

# The API-aware worker stays root only so its spawned parser child can enter a
# fixed different UID/GID. The child receives no credentials and cannot regain
# privileges after its seccomp boundary is active.
RUN groupadd --system --gid 65532 oldap-parser \
 && useradd --system --uid 65532 --gid 65532 --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin oldap-parser

COPY --from=verapdf /opt/verapdf /opt/verapdf
RUN ln -s /opt/verapdf/verapdf /usr/local/bin/verapdf

# Python deps (installed via pip from exported requirements)
COPY --from=requirements /build/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Your Flask app (mediaserver is a subdir; paths are relative to repo-root build context)
COPY mediaserver/app.py /app/app.py
COPY mediaserver/config.py /app/config.py
COPY mediaserver/derivatives.py /app/derivatives.py
COPY mediaserver/ingest_auth.py /app/ingest_auth.py
COPY mediaserver/ingest_callback.py /app/ingest_callback.py
COPY mediaserver/import_records.py /app/import_records.py
COPY mediaserver/import_assets.py /app/import_assets.py
COPY mediaserver/content_validation.py /app/content_validation.py
COPY mediaserver/ingest_service.py /app/ingest_service.py
COPY mediaserver/ingest_worker.py /app/ingest_worker.py
COPY mediaserver/parser_sandbox.py /app/parser_sandbox.py
COPY mediaserver/media.py /app/media.py
COPY mediaserver/oldap_client.py /app/oldap_client.py
COPY mediaserver/quarantine.py /app/quarantine.py
COPY mediaserver/storage.py /app/storage.py
COPY mediaserver/storage_capacity.py /app/storage_capacity.py
COPY mediaserver/zip_validation.py /app/zip_validation.py
COPY mediaserver/validation_documents.py /app/validation_documents.py
COPY mediaserver/__init__.py /app/__init__.py
COPY mediaserver/VERSION /app/VERSION

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV MEDIAHELPER_VERSION="${MEDIAHELPER_VERSION}"

EXPOSE 8000

# Default command (can be overridden in docker-compose.yml for env-specific tuning)
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
