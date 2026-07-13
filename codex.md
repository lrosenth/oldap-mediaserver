# oldap-mediaserver Codex Context

## Purpose
`oldap-mediaserver` provides the media infrastructure around OLDAP. It combines a Flask upload/auth helper, Caddy for public asset delivery, and Cantaloupe/Kakadu for IIIF image delivery.

## Current Architecture
- `mediaserver/app.py` contains the Flask app. It validates uploads, stores originals and derivatives, registers `shared:MediaObject` resources through `oldap-api`, and resolves `/asset/...` requests for Caddy.
- `mediaserver/oldap_client.py` wraps the OLDAP API calls used by upload and asset resolution.
- `Caddyfile` and `ansible/templates/Caddyfile.j2` route `/iiif/*` to Cantaloupe and `/asset/*` through Flask `forward_auth` before serving static files from the shared media volume.
- `imageserver/` contains the Cantaloupe image server configuration and bundled runtime assets.
- `mediaserver/Dockerfile` builds the upload helper runtime and installs `ffmpeg` for audio/video derivatives, `libvips` for image derivatives, and Poppler for first-page PDF previews.
- `mediaserver/Dockerfile.dockerignore` keeps media-helper builds small even though the Dockerfile uses the repository root context for `pyproject.toml` and `poetry.lock`; only the dependency manifests and helper source files should enter that build context.

## Storage Model
Assets are stored below the media root as:

```text
<projectShortName>/<media_type>/<optional/sub/path>/<assetId>/
    original/
        <uploaded filename>
    derived/
        <delivery derivative>
```

Images are served through IIIF derivatives. Video, audio, and PDF documents use HTTP delivery through Caddy and keep originals under `original/` with access copies under `derived/`. Video uses `web.mp4`; audio defaults to `web.mp3` and may use `web.m4a` when `targetFormat=m4a` is explicitly requested. Documents are currently PDF-only, use the stable derivative name `document.pdf`, and provide square `thumb128.jpg` and `thumb256.jpg` previews rendered from the first page.

## Development Conventions
- Keep originals bit-identical to the uploaded file where possible.
- Treat asset identifiers as bounded URL-safe path segments, reject storage paths that resolve outside the media root, and claim new asset directories atomically; uploads must never overwrite an existing asset directory, and failed storage/conversion/registration must release its reserved directory.
- Store delivery files in `derived/` and record the selected filename in `shared:derivativeName`.
- Use `shared:protocol = "iiif"` for images and `"http"` for media served by Caddy.
- PDF document uploads are stored as `mediaType=document`, `dcterms:type = dcmitype:Text`, `shared:protocol = "http"`, and `shared:derivativeName = "document.pdf"`; frontends should render them via `assetUrl` rather than IIIF.
- PDF rendering uses Poetry-managed `pdf2image`/Pillow with native `poppler-utils` supplied by the Docker runtime; Docker hosts do not need a separate Poppler installation.
- `/asset/<assetId>/original` may serve authorized originals for both HTTP and IIIF media. IIIF derived delivery remains blocked on `/asset/<assetId>` and `/asset/<assetId>/derived`; those derivatives are served through Cantaloupe.
- Use `download=1` on original asset URLs when callers need `Content-Disposition: attachment`; otherwise originals remain inline.
- For audio delivery, prefer MP3 as the default derivative because it is the broadest browser-compatible serving format.
- Prefer explicit helpers for conversion logic and keep public functions/classes documented with concise docstrings.
- Update `CODEX_LOG.md` after relevant code changes.

## Roadmap / Next Steps
- Add focused automated tests for media type detection, target format validation, and asset path resolution.
- Verify audio/video conversion behavior in the Docker runtime where `ffmpeg` and `ffprobe` are installed.
- Keep README and OpenAPI aligned with media derivative naming and delivery behavior.
