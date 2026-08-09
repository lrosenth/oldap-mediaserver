# oldap-mediaserver Codex Context

## Purpose
`oldap-mediaserver` provides the media infrastructure around OLDAP. It combines a Flask upload/auth helper, Caddy for public asset delivery, and Cantaloupe for IIIF delivery of pyramidal TIFF images.

## Current Architecture
- `mediaserver/app.py` contains the Flask app. It validates uploads, stores originals and derivatives, registers `shared:MediaObject` resources through `oldap-api`, and resolves `/asset/...` requests for Caddy.
- `mediaserver/config.py` parses environment-backed mediahelper settings without
  filesystem or network side effects and freezes the approved ZIP/worker
  security limits. `mediaserver/storage.py` provides the Flask-independent
  storage boundary shared with future ZIP ingest: path validation, exclusive
  asset reservation, isolated operation workspaces, and bit-identical original
  copying with SHA-256 generation.
- `mediaserver/media.py` separates untrusted legacy MIME/filename routing hints
  from typed content-derived audio/PDF probe facts. `mediaserver/derivatives.py`
  owns reusable libvips, FFmpeg, and Poppler processing and returns a typed
  inventory of created delivery files. Neither module imports Flask or an OLDAP
  client; `app.py` composes them and remains responsible for rollback.
- `mediaserver/zip_validation.py` is the network-free Phase 4 structure
  boundary. It parses conventional ZIP central/local metadata before
  decompression, rejects unsafe paths, entry types, optional features and
  portable/NFC collisions, and performs individual streamed all-or-nothing
  extraction with CRC, SHA-256, actual-size and compression-ratio evidence.
- `mediaserver/content_validation.py` sequentially classifies extracted files
  from signatures and enforces the frozen image/audio/video/PDF-A/UTF-8 matrix.
  Pillow, FFprobe, pdfinfo, qpdf, and veraPDF produce bounded evidence;
  external tools receive a sanitized environment, deadlines, and kernel-limited
  output files. `validation_documents.py` projects complete READY and INVALID
  v1 records from structural and content evidence.
- `mediaserver/ingest_service.py` and `ingest_worker.py` implement the strict
  import-service claim/heartbeat/result boundary and the sequential private
  process. `import_records.py` owns immutable RFC 8785/checksum-bound retained
  records outside temporary ingest; Flask serves them only through the
  import-records JWT boundary. Caddy exposes only the exact read-only retained
  report path required by oldap-api; every other `/internal` route remains
  unrouted.
- `mediaserver/parser_sandbox.py` separates hostile parser code from the
  API-aware parent. Production parser children receive no client/claim/secret,
  clear inherited environment, drop to UID/GID 65532 with zero capabilities,
  deny network syscalls through inherited libseccomp, and access only their
  current SIP/workspace until the parent revokes access after exit.
- `mediaserver/oldap_client.py` wraps the OLDAP API calls used by upload and asset resolution.
- `Caddyfile` and `ansible/templates/Caddyfile.j2` route `/iiif/*` to Cantaloupe, `/asset/*` through Flask `forward_auth`, direct ZIP ingress to its bounded PUT handler, and only the JWT-protected retained-report GET from the internal import surface.
- `imageserver/` contains the Cantaloupe image server configuration and bundled runtime assets. It uses the built-in Java2D processor and has no proprietary image-codec dependency. Its whitelist-based `.dockerignore` sends only the Cantaloupe JAR plus OLDAP configuration/delegate files to the builder.
- `imageserver/VERSION` is the single source for the independently released
  OLDAP imageserver version. `imageserver/Makefile` derives the `v<version>`
  Docker tag, passes both imageserver and Cantaloupe versions into the build,
  and records the component version as OCI image metadata.
- `mediaserver/Dockerfile` builds the upload helper runtime and installs `ffmpeg` for audio/video derivatives, `libvips` for image derivatives, and Poppler for first-page PDF previews.
- `mediaserver/VERSION` independently versions the Flask mediahelper component.
  `mediaserver/Makefile` derives its `v<version>` Docker tag, while the
  Dockerfile records the raw semantic version in OCI metadata and exports it to
  the runtime status endpoints. This version is distinct from `pyproject.toml`.
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
- The repository-root `Makefile` obtains the imageserver and mediahelper tags
  from their component `VERSION` files and passes them explicitly as
  `oldap_imageserver_tag` and `oldap_mediahelper_tag` to production or test
  Ansible deployments. Ansible has no independent defaults for these tags,
  preventing build/deployment version drift.
- Both media deployment targets default to the shared encrypted
  `$HOME/ProgDev/OLDAP/auth/auth.vault.yml` and prompt for its Vault password;
  `AUTH_SECRETS_FILE` and `ANSIBLE_VAULT_ARGS` remain overridable.
- Production and home media targets are separate hosts. Production serves
  `media.oldap.org` with public ACME TLS and calls `https://api.oldap.org`;
  the home target serves `media.home.org` with Caddy's internal CA and calls
  the separate API VM at `http://api.home.org`. Home containers rely on local
  DNS rather than fixed `extra_hosts` addresses. The Make targets apply both
  explicit play host expressions and inventory limits.
- Ansible waits for Compose to report running services, flushes pending Caddy
  handlers, and then verifies the public media `/health` response including the
  requested mediahelper version. A tokenless public IIIF probe must also reach
  Cantaloupe and return `401`. Rollback suppresses Caddy handlers because the
  stack has intentionally been removed.
- Normal Ansible deployments enable the `zip-import-validation` profile and
  verify exactly one running ingest worker. `zip_import_worker_enabled=false`
  is the explicit maintenance/incident switch. Deployment also refuses to
  create media/ingest paths unless `/data` is an active mountpoint.

## Storage Model
Assets are stored below the media root as:

```text
<projectShortName>/<media_type>/<optional/sub/path>/<assetId>/
    original/
        <uploaded filename>
    derived/
        <delivery derivative>
```

Images are served through the canonical pyramidal TIFF IIIF derivative `master.tif`; TIFF is the default and only accepted image target format. Video, audio, and PDF documents use HTTP delivery through Caddy and keep originals under `original/` with access copies under `derived/`. Video uses `web.mp4`; audio defaults to `web.mp3` and may use `web.m4a` when `targetFormat=m4a` is explicitly requested. Documents are currently PDF-only, use the stable derivative name `document.pdf`, and provide square `thumb128.jpg` and `thumb256.jpg` previews rendered from the first page.

## Development Conventions
- Keep originals bit-identical to the uploaded file where possible.
- Store the lower-case SHA-256 digest of each newly uploaded original in
  `shared:checksum`; expose the same digest as the additive `checksum` response
  field. Integrity metadata is server-managed and multipart metadata must never
  override it.
- Treat asset identifiers as bounded URL-safe path segments, reject storage paths that resolve outside the media root, and claim new asset directories atomically; uploads must never overwrite an existing asset directory, and failed storage/conversion/registration must release its reserved directory.
- Store delivery files in `derived/` and record the selected filename in `shared:derivativeName`.
- Normalize all image uploads to a tiled pyramidal BigTIFF named `master.tif`; reject other image target formats explicitly.
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
  `imageserver-v<version>` or `mediahelper-v<version>` if release commits are
  tagged.

## Roadmap / Next Steps
- Use `ZIP_IMPORT_PLAN.md` as the living cross-repository plan and progress
  record for the secure, project-neutral ZIP-to-staging import. Its seven phases (0–6) cover contract
  definition, Mediahelper foundations, API-owned jobs and quotas, quarantined
  upload, isolated validation, confirmed `shared:StagingFolder` batch import,
  and lifecycle operations. The MVP deliberately uses one sequential ingest
  worker, existing GraphDB state, the existing ext4 data volume, and no new
  database, broker, resumable protocol, or administration UI. Import email is
  sent only by `api.oldap.org` through its proven SMTP path; polling remains
  authoritative and mail-delivery state never controls ImportJob state. Every
  ZIP upload starts from an existing selected `shared:StagingFolder`, which is
  the import root: root-level files attach directly to it, root-level ZIP
  directories become new children, and no ZIP-name wrapper is created. This
  makes large hierarchies incrementally buildable through independent small
  imports without implicit folder merging or overwrites. Canonical-equivalent
  existing child folders block an import, while same-named existing media are
  allowed with a report warning because technical asset IDs are independent.
  Phases 0 and 1 are complete. The mediahelper now has reusable configuration,
  frozen policy limits, storage, typed probe, and derivative boundaries plus
  per-operation temporary directories and SHA-256 original storage. Phase 2 is
  complete in `oldap-api`/`oldaplib`: API-owned jobs, authorization, quota,
  scoped capabilities, the sequential lease protocol, validation outcomes,
  reports, notifications, cursor pagination, and redacted audit events are in
  place. Phase 3 is complete: mediahelper verifies the dedicated upload
  capability, streams into a random partial directory under a separately
  mounted private ingest root, enforces the 500 MB limit independently of
  Content-Length, calculates SHA-256, and atomically finalizes an immutable SIP
  plus receipt. Caddy exposes only the bounded PUT route and neither Caddy nor
  Cantaloupe mounts quarantine storage. The persisted SIP event is delivered
  with a purpose-specific import-service JWT; only an API acknowledgement marks
  it DELIVERED, while exact PUT replay and a bounded periodic loop retry the
  same retained event. The stale partial/UPLOADING ownership boundary is now
  fixed: Mediahelper removes only recognizable, non-symlink
  `.part-<importId>-*` directories after 24 hours, at most 100 per 60-second
  pass, and never age-deletes finalized UUID directories. Stale UPLOADING state,
  quota release, and finalized payload cleanup remain API-claim-owned Phase 6
  work. FasnachtsPage creates the API-owned job from the
  currently selected StagingFolder IRI, uploads the ZIP directly with the
  short-lived media capability, and shows progress without offering premature
  confirmation. Phase 4 is complete: the bounded structural ZIP
  inspection and safe extraction core, leased single worker, structural INVALID
  records, deletion-before-publication, crash replay, and restricted container
  are implemented. Content probes and READY/content-INVALID projection are now
  complete. API-owned claim-bound preflight now compares explicit and implicit
  ZIP-root children with current direct staging children using NFC/portable
  keys. Parser-heavy analysis now runs in a spawned Unix process group under a
  parent-enforced fixed six-hour deadline. Timeout kills the group, retains a
  bounded `VALIDATION_TIMEOUT` FAILED report without inventing a manifest, and
  deletes quarantine before API publication; exact report/result replay is
  crash-safe. Parser credential, UID, capability, network, and job-workspace
  isolation are now implemented and verified in the Linux image. The worker
  remains behind an explicit Compose profile while Phase 6 lifecycle operations
  and pilot-readiness work remain open; this is an activation choice, not a missing
  parser safety control.
  Phase 5 is complete. The commit boundary loads the exact retained
  READY manifest against the API claim digest, derives deterministic UUIDv5
  technical asset IDs, prepares originals and derivatives in a job-owned
  same-filesystem workspace, and promotes complete asset directories with
  Linux `renameat2(RENAME_NOREPLACE)`. Original checksums and closed delivery
  facts are reverified, exact interrupted attempts are replayable, unrelated
  assets are never replaced, and compensation removes only directories carrying
  the matching import/manifest/entry owner marker. The API transactional
  hierarchy commit is now complete: it atomically reauthorizes, rechecks target
  and collisions, creates every staging resource with the default role, and
  records IMPORTED plus a relative-path replay mapping. The sequential worker
  now claims IMPORT as well as VALIDATE, synthesizes omitted parent folders,
  prepares/promotes complete assets, and invokes that batch. Definitive commit
  rejection is compensated before payload deletion and persisted as a
  replayable terminal-failure receipt; ambiguous API outcomes retain marked
  assets for deterministic retry. FasnachtsPage presents a two-step,
  state-version-bound READY confirmation, reloads authoritative state after a
  conflict, prevents duplicate submission, and polls IMPORTING through IMPORTED
  or compensated FAILED. Phase 6 is in progress: the same sequential worker now
  consumes API-selected CLEANUP claims for stale UPLOADING, expired READY,
  CANCELLED, and IMPORTED jobs. It deletes only canonical temporary ingest data,
  retains immutable records/final assets, and posts idempotent proof before the
  API finalizes EXPIRED or clears cleanupPending; IMPORTING is never eligible.
  Recovery now also covers durable SIP callback replay, expired task leases,
  deterministic owner-marked import replay/compensation, incomplete cleanup,
  and bounded API-owned email retry. Failed/PENDING mail receives at most three
  API submissions at five-minute spacing during idle worker polls; media never
  receives SMTP configuration. Physical disk admission now protects UPLOAD,
  VALIDATE extraction, and IMPORT asset preparation with a mandatory 20%
  filesystem reserve plus an optional higher absolute reserve. Upload pressure
  returns stable HTTP 507; later worker pressure is retryable and emits only
  non-sensitive structured capacity facts. The Phase 6 automated matrix covers
  the complete API lifecycle, quota/claim/confirmation races, and retained
  validation/import/cleanup recovery boundaries, with production-scale and
  destructive checks reserved for pilots. The cross-service operations runbook
  now defines immutable deployment/rollback, critical-versus-temporary backup
  scope, restore order, implemented retention, incident playbooks, and pilot
  gates. API-owned 30-/90-day record pruning, durable feature activation, and
  pilot rollout remain.
  The confirmed lean envelope accepts only conventional single-disk
  stored/deflated ZIPs, caps the archive at 500,000,000 bytes and extracted
  originals at 3,000,000,000 bytes, and permits at most two audio channels.
  Accepted audio is WAV integer PCM 8/16/24/32-bit at 8–192 kHz, FLAC
  8/16/24-bit at 8–192 kHz, or MP3 at 8–48 kHz. Accepted video is MP4 with one
  H.264 8-bit 4:2:0 Baseline/Main/High stream through level 5.2 and optional
  mono/stereo AAC-LC. Text must be detected specifically as `text/plain` and
  decode as strict UTF-8; detected structured or script formats remain
  unsupported. Empty and packaging-artifacts-only archives are invalid.
  Authorization requires user `ADMIN_CREATE` plus effective role `DATA_UPDATE`
  on the containing `shared:StagingArea`. PDF acceptance is limited to validated
  PDF/A-1 or PDF/A-2 with independent rejection of active content and every
  embedded file. Strict Draft 2020-12 manifest/report contracts live in
  `docs/zip-import/v1/`; they use stable issue codes, bounded inventories, and
  immutable validation evidence, leaving import-time mappings to a later
  separate receipt. The same directory contains separate validated OpenAPI 3.1
  contracts for API-owned job/state operations and direct media ingress, plus a
  documented state machine with optimistic public actions, idempotent internal
  events, leased worker tasks, and purpose-specific credentials. The v1 threat
  model and fixture catalogue in the same directory use a four-tier safe testing
  strategy: small deterministic hostile archives by default, real capacity,
  antivirus, backup, and destructive failure tests only in disposable
  operator-controlled environments. The single worker handles archive entries
  sequentially under hard cgroup ceilings of 4 vCPUs, 6 GiB RAM, and 128 PIDs.
  The exact staging-area quota ontology property is deliberately assigned to
  Phase 2. The lean MVP has no application-integrated malware scanner; the VM
  owner has asked university IT whether Defender covers Linux `/data`, and the
  operational answer must be recorded before a pilot.
- Add focused automated tests for media type detection, target format validation, and asset path resolution.
- Verify audio/video conversion behavior in the Docker runtime where `ffmpeg` and `ffprobe` are installed.
- Keep README and OpenAPI aligned with media derivative naming and delivery behavior.
