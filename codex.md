# oldap-mediaserver Codex Context

## Purpose
`oldap-mediaserver` provides the media infrastructure around OLDAP. It combines a Flask upload/auth helper, Caddy for public asset delivery, and Cantaloupe/Kakadu for IIIF image delivery.

## Current Architecture
- `mediaserver/app.py` contains the Flask app. It validates uploads, stores originals and derivatives, registers `shared:MediaObject` resources through `oldap-api`, and resolves `/asset/...` requests for Caddy.
- `mediaserver/oldap_client.py` wraps the OLDAP API calls used by upload and asset resolution.
- `Caddyfile` and `ansible/templates/Caddyfile.j2` route `/iiif/*` to Cantaloupe and `/asset/*` through Flask `forward_auth` before serving static files from the shared media volume.
- `imageserver/` contains the Cantaloupe image server configuration and bundled runtime assets.
- `imageserver/VERSION` is the single source for the independently released
  OLDAP imageserver version. `imageserver/Makefile` derives the `v<version>`
  Docker tag, passes both imageserver and Cantaloupe versions into the build,
  and records the component version as OCI image metadata.
- `mediaserver/Dockerfile` builds the upload helper runtime and installs `ffmpeg` for audio/video derivatives, `libvips` for image derivatives, and Poppler for first-page PDF previews.
- `mediaserver/Dockerfile.dockerignore` keeps media-helper builds small even though the Dockerfile uses the repository root context for `pyproject.toml` and `poetry.lock`; only the dependency manifests and helper source files should enter that build context.
- Media delivery and upload authentication are separate trust domains. Asset
  and IIIF query capabilities use `typ=media`, audience `oldap-api-media`, and
  `OLDAP_MEDIA_JWT_SECRET`; upload Bearer credentials use `typ=access`, audience
  `oldap-api`, and `OLDAP_ACCESS_JWT_SECRET`. The values must match the
  corresponding API deployment keys but must be distinct from one another.
- Deployment renders the media key into `mediaserver.env` for the Flask helper
  and Cantaloupe, and the access key into `mediahelper-access.env` for the Flask
  helper only. Secrets come from ignored Ansible vars or Vault and are never
  stored in `group_vars/all.yml`.
- The repository-root `Makefile` obtains the imageserver tag from
  `imageserver/VERSION` and passes it explicitly as `oldap_imageserver_tag` to
  production or test Ansible deployments. Ansible has no independent default
  for this tag, preventing build/deployment version drift.

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
- Treat published component image tags as immutable and deploy pinned versions,
  not `latest`. Use component-specific Git tags such as
  `imageserver-v<version>` if release commits are tagged.

## Roadmap / Next Steps
- Add focused automated tests for media type detection, target format validation, and asset path resolution.
- Verify audio/video conversion behavior in the Docker runtime where `ffmpeg` and `ffprobe` are installed.
- Keep README and OpenAPI aligned with media derivative naming and delivery behavior.
