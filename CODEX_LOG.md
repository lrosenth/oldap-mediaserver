# CODEX_LOG

### Update 2026-07-15 23:36
- Decisions: Version the imageserver independently from Cantaloupe and other media-stack images, using `imageserver/VERSION` as the single source and a derived `v<version>` Docker tag; require explicit tag propagation into deployment.
- Implementation: Added imageserver version `0.1.6`, reusable Make image/version variables and inspection targets, OCI build metadata, a repository-root Make deployment entry point, an Ansible tag assertion without a duplicated default, and synchronized release/deployment documentation and project context.
- Open: Build and push `lrosenth/oldap-imageserver:v0.1.6` before deploying it; apply the same component-version pattern to mediahelper and Kakadu only when their release workflows are addressed.
- Risks/Assumptions: Published version tags are immutable; `latest` remains a build convenience alias but is never selected by the documented deployment flow.

### Update 2026-07-15 17:56
- Decisions: Separate upload authentication from media delivery capabilities: uploads accept only OLDAP access tokens, while `/asset` and IIIF query tokens accept only independently signed media tokens.
- Implementation: Replaced legacy raw JWT/UserData parsing with strict `oldaplib` token decoding, migrated media-helper tests to minimal access authorization claims, added cross-purpose rejection coverage, hardened the Cantaloupe delegate with algorithm/type/issuer/audience validation without cross-request payload caching, split access and media environment files by container need, added automatic ignored/Vault vars loading plus secret validation/examples, and documented both local and deployed API/media-server key sharing.
- Open: Supply matching `oldap_access_jwt_secret` and `oldap_media_jwt_secret` values through ignored Ansible vars or Vault and deploy alongside the API change.
- Risks/Assumptions: Query-string media capabilities can appear in logs and browser history; their one-hour default lifetime bounds but does not eliminate that exposure.

### Update 2026-07-14 00:35
- Decisions: Treat every asset identifier as a bounded URL-safe filesystem segment and atomically reserve each asset directory before writing; duplicate identifiers are conflicts rather than overwrite requests.
- Implementation: Added NanoID-compatible URL-safe identifier validation to upload/auth/delete paths, reject symlink-resolved upload paths outside the media root, return `409 Conflict` for existing asset directories, clean failed storage/conversion/registration and partial directory initialization for all media types, closed Poppler-rendered images on all conversion exits, and added traversal/URL/collision/I/O regression tests plus API documentation.
- Open: None for the identifier and collision invariants.
- Risks/Assumptions: Existing clients that intentionally reused an `assetId` must now delete the old asset first or submit a new identifier; legacy non-traversing identifiers remain addressable through auth/delete even when they do not meet the stricter new-upload character set.

### Update 2026-07-13 23:56
- Decisions: Reuse the video thumbnail contract for PDFs; manage `pdf2image` and Pillow through Poetry while supplying native Poppler only inside the Docker runtime.
- Implementation: Rendered the first PDF page at bounded size and timeout, generated square `thumb128.jpg`/`thumb256.jpg` derivatives, returned existing thumbnail fields for documents, added cleanup/error coverage, installed `poppler-utils` in the image, and synchronized README/OpenAPI/project context.
- Open: FasnachtsPage still needs to consume `thumb256Url` (or construct the equivalent authorized derivative URL) in document overview cards.
- Risks/Assumptions: PDF thumbnail generation remains synchronous; unusually complex PDFs may hit the 30-second render timeout and be rejected without creating an OLDAP object.

### Update 2026-07-13 14:34
- Decisions: Preserve any pre-existing asset directory when rejecting an invalid PDF upload that reuses an `assetId`.
- Implementation: Limited invalid-PDF cleanup to asset directories created by the current upload attempt and added a regression test for existing-asset preservation.
- Open: None for this cleanup fix.
- Risks/Assumptions: Existing upload semantics still allow callers to provide explicit identifiers; this change only prevents the new reject path from deleting prior files.

### Update 2026-07-01 18:44
- Decisions: Keep the media-helper Dockerfile on the repository-root context for Poetry manifest access, but make the effective context whitelist-only for this Dockerfile.
- Implementation: Added `mediaserver/Dockerfile.dockerignore` to send only `pyproject.toml`, `poetry.lock`, and media-helper source files; documented the tiny-context build path in Dockerfile, Makefile, README, and project context.
- Open: Full image build/push still depends on Docker Hub/base-image availability and the existing Python dependency install.
- Risks/Assumptions: Docker BuildKit/buildx honors Dockerfile-specific ignore files; the root `.dockerignore` remains as a broader fallback for older build flows.

### Update 2026-07-01 11:02
- Decisions: Treat documents as PDF-only assets for now; keep the original bit-identical and expose a stable `derived/document.pdf` HTTP access copy instead of involving IIIF or accepting arbitrary office formats.
- Implementation: Added lightweight PDF validation, canonical document derivative naming, normalized PDF MIME metadata, upload response fields for `dctermsType`/`protocol`, focused PDF upload/auth tests, and synchronized README/OpenAPI/project context for FasnachtsPage integration.
- Open: End-to-end browser rendering in FasnachtsPage still needs a frontend integration pass and deployed media-server verification with real OLDAP-issued access tokens.
- Risks/Assumptions: PDF validation is an upload gate based on header/EOF markers, not full PDF repair or sanitization; richer document formats should wait for an explicit conversion/security design.

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
