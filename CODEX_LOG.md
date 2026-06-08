# CODEX_LOG

### Update 2026-06-08 17:13
- Decisions: Allow authorized `/asset/<assetId>/original` downloads for IIIF media while keeping IIIF derived delivery blocked on `/asset`; reuse the configured CORS origin list instead of opening asset delivery to arbitrary origins.
- Implementation: Updated Flask asset auth to allow IIIF originals, emit attachment disposition for `download=1`, and pass a checked CORS origin to Caddy; updated Caddy and Ansible templates for OPTIONS preflight, final asset CORS headers, and request-header spoofing protection; documented curl checks and added focused pytest coverage.
- Open: End-to-end browser/fetch verification still needs the deployed stack or local Docker Compose with real OLDAP-issued tokens and media files.
- Risks/Assumptions: Caddy `forward_auth` continues to be the authorization gate for GET/HEAD asset delivery; OPTIONS only returns CORS preflight metadata and does not expose files.

### Update 2026-05-31 23:35
- Decisions: Pin the production mediahelper deployment to the released `v0.0.12` image instead of relying on a mutable local `latest` tag.
- Implementation: Updated Ansible defaults and deployment documentation to use `lrosenth/oldap-mediahelper:v0.0.12`.
- Open: Production still needs to be redeployed or force-pulled so `/status` reports `v0.0.12`.
- Risks/Assumptions: Docker Hub shows `v0.0.12` and `latest` share the new digest; the observed production `v0.0.11` is assumed to be a stale local image/tag on the host.

### Update 2026-05-16 00:30
- Decisions: Created the required project context files before substantial code changes.
- Implementation: Added stable repository context in `codex.md` and initialized this technical work log.
- Open: Audio upload behavior still needs implementation cleanup and verification.
- Risks/Assumptions: Existing uncommitted repository changes are assumed to be user-owned and are left untouched.

### Update 2026-05-16 00:32
- Decisions: Use MP3 as the default browser-delivery derivative for audio, with optional M4A/AAC when explicitly requested.
- Implementation: Updated audio target-format validation, added ffprobe stream validation, added an MP3 ffmpeg helper, renamed audio derivatives to `web.mp3`/`web.m4a`, and synchronized README/OpenAPI/context docs.
- Open: End-to-end upload and Caddy range-request testing still needs the Docker runtime or a local system with `ffmpeg`, `ffprobe`, and `libvips`.
- Risks/Assumptions: Debian's `ffmpeg` package in the runtime image is assumed to include `ffprobe`, AAC encoding, and `libmp3lame`.
