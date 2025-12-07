# uploader-api/Dockerfile

FROM lrosenth/kakadu-base:latest AS kakadu-base

# Final image
FROM python:3.14-slim

# Bring Kakadu runtime in
COPY --from=kakadu-base /opt/kakadu /opt/kakadu
ENV LD_LIBRARY_PATH=/opt/kakadu/lib
ENV PATH="/opt/kakadu/bin:${PATH}"

WORKDIR /app

# System deps: libvips for pyvips
RUN apt-get update && apt-get install -y \
    libvips \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Your Flask app
COPY app.py .
COPY oldap_client.py .
COPY __init__.py .

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# You can also use flask run if you prefer, but gunicorn is nicer for prod
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]