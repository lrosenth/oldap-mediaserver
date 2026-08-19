# Secure ZIP Import Plan

## Document Purpose

This is the living implementation and progress document for importing complete
ZIP directory structures into an OLDAP staging area. It covers the coordinated
work in `oldap-mediaserver`, `oldap-api`, `oldaplib`, and `FasnachtsPage`.

Update this document whenever scope, contracts, decisions, risks, phase status,
or implementation progress changes. Record detailed code changes in the
`CODEX_LOG.md` of each affected repository.

Last updated: 2026-08-05

## Status Legend

| Status | Meaning |
| --- | --- |
| `NOT STARTED` | No implementation work has started. |
| `IN PROGRESS` | Work is active and the exit criteria are not yet satisfied. |
| `BLOCKED` | Progress requires a recorded decision or external dependency. |
| `DONE` | Exit criteria are satisfied and verified. |

## Current Overall Status

- Overall: `IN PROGRESS`
- Architecture discovery: `DONE`
- Phase 0 security and product contracts: `DONE`
- Phases 1 through 5: `DONE`
- Current activity: Phase 6 cleanup, reconciliation, operations, and pilot readiness
- Implementation: the complete create/upload/validate/review/confirm/import
  path is implemented across API, media worker, and FasnachtsPage, including
  create-only deterministic assets, one-transaction staging hierarchy commit,
  compensation, replay, and terminal user feedback. Automated lifecycle
  cleanup, operational reconciliation, and physical disk admission are active;
  operations runbooks and pilot rollout remain.

## Goal

Authorized users can upload a ZIP file directly to the Swiss-hosted OLDAP media
infrastructure as a temporary Submission Information Package (SIP). The design
is project-neutral; `fasnacht` is the first enabled project, not a hard-coded
domain assumption. The archive is quarantined, inspected, safely extracted,
fully analyzed, and presented as an import report. Files and
`shared:StagingFolder` resources are created below the selected existing
`shared:StagingFolder` only after explicit user confirmation.

## Agreed Architecture and Invariants

- FasnachtsPage creates an import job through `oldap-api`.
- ZIP bytes go directly to `oldap-mediaserver`, never through `oldap-api`.
- `oldap-api` remains authoritative for authentication, authorization, quotas,
  job state, confirmation, and creation of OLDAP staging resources.
- Every import starts from one explicitly selected, existing
  `shared:StagingFolder`. Its IRI is stored as the immutable target root of the
  import job; the ZIP filename does not create an additional wrapper folder.
- Files at the ZIP root become new `shared:StagingMediaObject` resources
  directly in the selected target root. Directories at the ZIP root become new
  child `shared:StagingFolder` resources, and their descendants reproduce the
  ZIP hierarchy below them.
- Job creation and confirmation require the authenticated user to have
  `oldap:ADMIN_CREATE` and the user's effective role permission on the containing
  `shared:StagingArea` to be at least `DATA_UPDATE`. The API remains the only
  authority for this decision and verifies that the selected target folder
  belongs to that staging-area container.
- The selected target root is never recreated, renamed, moved, or replaced.
  Existing directory hierarchies are not merged implicitly; each ZIP import is
  an independent, create-only addition below its selected root.
- ZIP directories become `shared:StagingFolder` resources. They do not become
  `shared:ArchiveUnit` resources; staging and the permanent archival hierarchy
  remain separate workflows.
- The ZIP and extracted content remain outside the final media tree until the
  import has been validated and confirmed.
- Existing files, asset directories, and OLDAP resources are never overwritten.
- Original display names are independent from generated technical asset IDs.
- Names are normalized to Unicode NFC; raw and normalized names and all
  collisions remain traceable in the report and manifest.
- Quota usage is based on actual extracted size.
- Cleanup must never claim or delete a job in `IMPORTING`.
- The existing synchronous single-file `/upload` workflow remains compatible
  while the ZIP workflow is introduced incrementally.

### Target-root mapping example

If the user starts an import from the existing folder `BMG/Photographs` and the
ZIP contains:

```text
notes.txt
2024/
  parade.jpg
2025/
  preparations/
    workshop.tif
```

the resulting staging hierarchy is:

```text
BMG/Photographs/                 existing selected folder; identity unchanged
  notes.txt                      new staging media object
  2024/                          new staging folder
    parade.jpg                   new staging media object
  2025/                          new staging folder
    preparations/                new staging folder
      workshop.tif               new staging media object
```

There is no additional folder derived from the ZIP filename. A later ZIP can be
started from any permitted existing staging folder, making a large hierarchy
buildable through several bounded import jobs.

## MVP Format Policy

The Phase 0 contracts freeze the following machine-readable content and codec
allowlist:

- Images: JPEG, single-page TIFF, PNG, single-image HEIF/HEIC
- Audio: WAV integer PCM at 8/16/24/32 bits and 8–192 kHz; FLAC at 8/16/24
  bits and 8–192 kHz; MP3 at 8–48 kHz; mono or stereo only. The same
  two-channel ceiling applies to AAC audio inside accepted video.
- Video: MP4 with one 8-bit 4:2:0 H.264/AVC video stream using Baseline, Main,
  or High profile up to level 5.2, plus zero or one mono/stereo AAC-LC stream.
- Documents: PDF/A-1 or PDF/A-2 under the policy below, and content detected
  specifically as `text/plain` with strict UTF-8 decoding; ASCII is valid UTF-8.
  Detected HTML, SVG, XML, JSON, CSV, and executable script formats are not
  accepted as generic text.
- Unsupported: AVI, Word, Excel, and all other unapproved formats
- Encrypted or password-protected content is rejected
- Type decisions are based on content, not filename or client MIME type
- The import is all-or-nothing: any unsupported content rejects the complete SIP.
- Known packaging artifacts such as `.DS_Store`, `Thumbs.db`, `desktop.ini`,
  `__MACOSX`, and AppleDouble entries are reported and deliberately omitted.
- Empty ZIPs and ZIPs containing only ignored packaging artifacts are rejected
  with `NO_IMPORTABLE_CONTENT`.
- Nested archives are unsupported and reject the complete SIP.
- Multi-page TIFF files and multi-image HEIF collections are rejected.
- Videos are limited to one H.264 video stream, zero or one AAC audio stream,
  no subtitle/data/attachment streams, at most 4K, 60 fps, and two hours.
- UTF-8 text files are limited to 1 MiB.

Unsupported files always appear in the report and invalidate the complete SIP.

## Standard ZIP Subset

The MVP accepts a deliberately small, interoperable ZIP subset:

- one ordinary, single-disk `.zip` archive;
- compression method `0` (stored) or `8` (deflate) only;
- standard CRC-32 must match for every file;
- ASCII names or names unambiguously encoded as UTF-8;
- no encryption, password protection, ZIP64, split/multi-volume archives,
  self-extracting preamble, nested archives, or unsupported compression methods;
- regular files and directories only, subject to all path, link, name, depth,
  count, size, and compression-ratio rules.

The 500 MB upload, 10,000-entry, and 3 GB extracted-size ceilings remove any
MVP need for ZIP64. The subset corresponds to conventional stored/deflated ZIP
files produced by common operating-system tools, rather than every optional
feature in the full PKWARE APPNOTE specification.

## Confirmed PDF/A Policy

PDF/A materially reduces the permitted PDF feature set but is not a malware
scanner or a substitute for isolated parsing. The confirmed MVP profile is:

- accept PDF/A-1 or PDF/A-2 at any defined conformance level, validated with
  veraPDF rather than trusting the document's self-declaration;
- reject PDF/A-3 and PDF/A-4;
- additionally reject encryption, JavaScript, launch actions, rich media, and
  all embedded or attached files;
- retain the submitted PDF/A original bit-identically and create only the
  existing bounded preview/access derivatives.

PDF/A forbids encryption, and PDF/A-1/2/3 prohibit JavaScript actions. PDF/A-3,
however, permits arbitrary embedded non-PDF content; PDF/A-2 permits embedded
PDF/A files, which this MVP would also reject. References:
[PDF Association FAQ](https://pdfa.org/pdfa-faq/),
[PDF/A external references](https://pdfa.org/pdf-a-and-external-references/), and
[veraPDF validation profiles](https://docs.verapdf.org/cli/validation/).

## Versioned Manifest and Report Contracts

The Phase 0 v1 contracts are stored in `docs/zip-import/v1/`:

- `common.schema.json` contains the shared policy-limit snapshot, staging target
  snapshot, probe facts, validation summary, and stable issue-code catalogue;
- `manifest.schema.json` defines the complete bounded technical validation
  evidence used later by the importer and retained audit record;
- `report.schema.json` defines the protected user-facing projection consumed by
  FasnachtsPage;
- `examples/` contains validated READY and INVALID contract fixtures.

All schemas use JSON Schema Draft 2020-12, close objects against unknown fields,
and carry semantic `schemaVersion: 1.0.0`. A manifest records raw ZIP name bytes,
decoded source names, NFC-normalized destination names, checksums, probe facts,
issues, and planned create-only staging resources without exposing host paths.
The report uses stable issue codes and localization keys rather than retained
translated prose.

Reports remain bounded under hostile input. `inventoryComplete: false` records
that a hard scan limit stopped enumeration; the validator is not required to
materialize an attacker-controlled number of report entries. READY always
requires a complete inventory. READY and INVALID reports bind to their immutable
manifest through SHA-256 over RFC 8785 canonical JSON. A technical FAILED report
does not claim a manifest hash when trustworthy validation evidence could not be
completed. Import-time resource/asset mappings will use a separate Phase 5
receipt and never mutate the validation manifest.

## Versioned Public and Internal API Contracts

The Phase 0 OpenAPI 3.1 contracts are stored beside the JSON schemas:

- `docs/zip-import/v1/oldap-api.openapi.yaml` defines public ImportJob creation,
  listing, polling, report retrieval, confirmation, cancellation, and capability
  reissue plus internal media/worker events, claims, validation results, batch
  commit, failure, and cleanup operations;
- `docs/zip-import/v1/media-ingest.openapi.yaml` defines the direct immutable ZIP
  PUT and internal SIP/record metadata reads;
- `docs/zip-import/v1/api-contracts.md` freezes trust boundaries, transition
  preconditions, quota reservation, leases, idempotency, cleanup semantics, and
  the transactional batch-commit boundary.

Public job/report actions use the existing OLDAP access JWT. ZIP bytes use a
short-lived single-job upload capability accepted only by media ingress.
Internal API and retained-record calls use dedicated service credentials and
are not exposed through public Caddy routing. The browser never receives an
internal token, and media ingress never accepts an OLDAP access or delivery JWT.

Every mutable public action carries `expectedStateVersion`. Internal events are
idempotent by `eventId` and worker results also bind to a renewable `claimId`.
Cleanup cannot claim `IMPORTING`; cleanup failure after an imported job does not
rewrite its successful lifecycle state. The first finalized SIP PUT is immutable
and replay returns its persisted receipt without replacement.

## Threat Model and Test Fixture Catalogue

The Phase 0 security analysis is documented in:

- `docs/zip-import/v1/THREAT_MODEL.md`, covering assets, actors, trust
  boundaries, P0/P1/P2 risks, mandatory controls, verification, residual risk,
  and the confirmed resource/sandbox profile;
- `docs/zip-import/v1/TEST_ZIP_CATALOG.md`, defining accepted, rejected,
  malformed, resource-boundary, authorization, race, crash, cleanup, and
  operator-only fixtures with stable expected results.

Normal tests generate small deterministic ZIP structures and valid synthetic
media. Rejected formats come from controlled generators or provenance-reviewed
upstream corpora; the user does not need to collect them. Production-size
500-MB/3-GB, disk-pressure, kill/restart, backup, and EICAR tests are isolated
operator-only tests and never run in normal CI or against production roots.

The worker processes one job and one archive entry at a time. Four vCPUs are a
hard cgroup ceiling, not permission for four simultaneous untrusted parser jobs.
Tool-internal pools are smaller and bounded. The worker has a hard 6-GiB memory
limit, an equal memory-plus-swap ceiling where supported, and a PID limit of 128.

## Lifecycle

```text
UPLOADING -> VALIDATING -> READY -> IMPORTING -> IMPORTED
     |           |          |
     |           +--------> INVALID
     +--------------------> CANCELLED
                 +--------> FAILED
                            EXPIRED
```

- `INVALID`: delete ZIP, extracted data, and work data immediately; retain the
  bounded report for the agreed audit period.
- `READY`: retain validated data for seven days by default and expose `expiresAt`.
- `IMPORTED`: delete ZIP and temporary data only after the complete import has
  succeeded; retain report, manifest, and checksums.
- `EXPIRED`: delete all temporary data.
- `FAILED`: represent retryable or operator-visible infrastructure/software
  failure; never misclassify it as invalid user content.
- `CANCELLED`: represent an explicit user cancellation and delete temporary
  payload data immediately.
- State transitions must be atomic, idempotent, auditable, and owned by the API.

## Recommended Storage Boundaries

```text
/data/images/                     final media assets
/data/ingest/<importId>/          quarantined SIP and bounded work data
/data/import-records/<importId>/  retained report, manifest, and checksums
```

Caddy and Cantaloupe must only mount `/data/images` read-only. Validation workers
must not receive the final media volume or general OLDAP credentials.

## Lean MVP Boundary

The first implementation deliberately avoids a general distributed ingest
platform:

- one additional non-public ingest worker container handles validation, import,
  cleanup, and reconciliation sequentially;
- at most one validation/import job runs at a time globally;
- the existing ext4 volume hosts final, ingest, and retained-record directories
  through separate restricted bind mounts;
- GraphDB stores durable import-job state; no new database is introduced;
- no message broker or general job framework is introduced;
- the worker polls/updates the API using one dedicated scoped service identity;
- upload uses one idempotent streaming PUT and is not resumable in the MVP;
- FasnachtsPage polling remains the authoritative status channel; the API also
  sends completion/action email notifications without WebSockets;
- reports are JSON plus the existing web UI, not generated PDF documents;
- operations begin with structured logs and a small idempotent admin CLI rather
  than a new administration application.

This boundary may be expanded only in response to measured operational need.

## Import Notification Contract

Import email is owned and sent exclusively by `api.oldap.org`:

- the media worker reports durable validation/import outcomes to `oldap-api` and
  never receives SMTP configuration or credentials;
- the API commits the ImportJob state before attempting notification;
- SMTP failure never changes or rolls back the import state;
- FasnachtsPage always exposes the authoritative job list and report even when
  no email is delivered;
- email links open an authenticated FasnachtsPage job view and never embed a
  bearer token or perform confirmation/deletion directly;
- READY, INVALID, IMPORTED, and terminal FAILED are the only MVP notification
  templates; CANCELLED and EXPIRED remain visible in the UI without email;
- INVALID/FAILED messages contain a concise summary and a protected report link,
  not full filenames or sensitive validation details;
- notification submission status, attempt count, last error, and sent timestamp
  are recorded separately from the import state;
- failed submissions use a small bounded retry schedule. The single ingest
  worker may trigger an internal API retry operation, but SMTP execution remains
  inside the API process.

The existing password-reset SMTP path is verified in production through the
University of Basel relay (`smtp.unibas.ch:25`, STARTTLS, host-trusted relay).
Before import notification code is added, its transport logic should move from
the password-reset view into one small reusable `oldap-api` mail module. Password
reset and import notifications then provide only subject and multipart content.

## Confirmed Deployment Envelope

- Production media VM: 8 vCPUs and 16 GiB RAM.
- Worker CPU ceiling: 4 vCPUs; the RAM ceiling remains to be confirmed.
- Storage: `/dev/mapper/sysvg-datalv`, ext4 mounted at `/data`.
- Capacity: approximately 1 TB, currently about 10% used, estimated growth
  around 100 GB per year, and the logical volume can be extended.
- A separate ingest disk is possible but requires a lengthy university request;
  it is not required for the initial MVP.
- Current representative maximum video size is about 160 MB.
- Production data is backed up every 24 hours to a separate system; temporary
  ingest data must be excluded where operationally possible.
- Storage is not encrypted at rest.
- The API and media VM can communicate bidirectionally.
- Additional containers and dedicated Vault-managed service secrets are allowed.
- A separate database is explicitly undesired.
- A representative test environment exists in the local home network.

## Confirmed MVP Limits

| Limit | Value |
| --- | ---: |
| Compressed ZIP | 500 MB (500,000,000 bytes) |
| Total extracted bytes | 3 GB (3,000,000,000 bytes) |
| Individual extracted file | 3 GB (bounded by total extracted bytes) |
| ZIP entries | 10,000 |
| Compression ratio per file | 100:1 |
| Aggregate compression ratio | 50:1 |
| ZIP directory levels below selected staging root | 5 (selected root excluded) |
| UTF-8 bytes per path segment | 255 |
| UTF-8 bytes per relative path | 1,024 |
| Image size | 100 megapixels and 30,000 pixels per axis |
| UTF-8 text file | 1 MiB |
| Audio | WAV PCM 8/16/24/32-bit at 8–192 kHz; FLAC 8/16/24-bit at 8–192 kHz; MP3 at 8–48 kHz; max. 2 channels |
| Video | 4K, 60 fps, 2 hours |
| Validation wall time | 6 hours |
| Concurrent validation/import jobs | 1 globally |
| Required free disk reserve | max(20% of volume, configured absolute reserve) |

The product quota is based on extracted original bytes. Physical admission also
accounts for estimated derivatives and the required free-disk reserve.

## Phase Summary

| Phase | Name | Status | Primary repositories |
| --- | --- | --- | --- |
| 0 | Security and product contracts | `DONE` | all |
| 1 | Mediahelper foundations and shared processing | `DONE` | oldap-mediaserver |
| 2 | Import jobs, authorization, and quotas | `DONE` | oldap-api, oldaplib |
| 3 | Direct upload and quarantine | `DONE` | oldap-mediaserver, FasnachtsPage |
| 4 | Isolated validation and import report | `DONE` | oldap-mediaserver, oldap-api, FasnachtsPage |
| 5 | Confirmed staging import and batch commit | `DONE` | oldap-mediaserver, oldap-api, oldaplib, FasnachtsPage |
| 6 | Cleanup, reconciliation, UI completion, and operations | `NOT STARTED` | all |

## Phase 0: Security and Product Contracts

Status: `DONE`

### Objective

Freeze the externally visible behavior and the security limits before parsing
untrusted archives or introducing persistent job state.

### Work Items

- [x] Define hard limits for compressed upload size, entry count, individual
  extracted size, total extracted size, path length, compression ratios, image
  pixels, validation duration, and concurrent jobs.
- [x] Define allowed ZIP features and compression methods, including ZIP64.
- [x] Define the product-level image, audio, video, PDF, and text policy.
- [x] Confirm the exact PDF/A profile in D-017.
- [x] Decide how unsupported files affect the complete import.
- [x] Define NFC normalization, raw-name retention, ambiguous ZIP encodings,
  case-insensitive collisions, reserved names, and selected-root behavior.
- [x] Decide whether empty directories must be preserved.
- [x] Define the versioned import manifest and report JSON schemas.
- [x] Define lifecycle states, expiry periods, and high-level retry semantics.
- [x] Define public and internal API contracts in OpenAPI form.
- [x] Complete a threat model covering ZIP Slip, ZIP bombs, parser exploits,
  resource exhaustion, replay, quota races, and partial commits.
- [x] Keep an application-integrated malware scanner outside the lean MVP. The
  VM owner has asked university IT whether Microsoft Defender already scans
  writes to Linux `/data`; that operational answer remains required before a
  pilot but does not block Phase 4 validation or report delivery.

### Deliverables

- Approved security-limit table
- Approved MIME/container/codec matrix
- Versioned manifest and report schemas
- API and state-machine contract
- Threat model and test-fixture catalogue (`docs/zip-import/v1/THREAT_MODEL.md`
  and `docs/zip-import/v1/TEST_ZIP_CATALOG.md`)

### Exit Criteria

- Every item in the MVP policy has a machine-testable acceptance rule.
- Every lifecycle transition has one owner and explicit preconditions.
- Decisions D-001 through D-018 are resolved or deliberately deferred with an
  owner and target phase.

## Phase 1: Mediahelper Foundations and Shared Processing

Status: `DONE`

### Objective

Create maintainable internal boundaries without changing the behavior of the
existing single-file upload API.

### Work Items

- [x] Split configuration and limit parsing from the Flask application module;
  freeze the agreed ZIP and worker limits in typed runtime settings and prevent
  drift from the v1 JSON contract through an automated test.
- [x] Extract asset-path validation and exclusive reservation primitives.
- [x] Extract legacy media classification and existing content probes behind
  explicit typed results; distinguish request hints from content evidence.
- [x] Extract derivative generation from HTTP request handling.
- [x] Make checksum generation a shared storage operation and write the SHA-256
  digest to `shared:checksum` for the existing single-file upload.
- [x] Replace the global temporary filename convention with per-operation work
  directories to prevent cross-project or concurrent collisions.
- [x] Preserve `/upload`, `/asset`, and deletion behavior through regression tests;
  the upload response gains only the additive `checksum` field.
- [x] Document each module's responsibilities, inputs, outputs, and side effects.

### Deliverables

- Modular mediahelper package
- Shared media inspection and derivative interfaces
- Regression suite for the current upload and delivery contract

### Exit Criteria

- Existing endpoint tests pass without semantic changes.
- ZIP-specific code can reuse storage, inspection, and derivative primitives
  without invoking Flask request handlers.

## Phase 2: Import Jobs, Authorization, and Quotas

Status: `DONE`

### Objective

Make `oldap-api` the durable and authoritative owner of import jobs.

### Work Items

- [x] Implement the import-job persistence model and optimistic state version.
- [x] Implement atomic allowed state transitions.
- [x] Add `POST /imports`, `GET /imports/{id}`, report retrieval, confirmation,
  and optional cancellation endpoints.
- [x] Store the selected existing `shared:StagingFolder` IRI as the immutable
  target root and verify that it belongs to the requested staging area.
- [x] Require user permission `oldap:ADMIN_CREATE`, effective role permission of
  at least `DATA_UPDATE` on the containing staging-area container, and an
  available staging-area quota at job creation and confirmation.
- [x] Atomically reserve quota for concurrent jobs and reconcile it after validation.
- [x] Issue short-lived, audience-bound, single-job upload capabilities.
- [x] Define a separate service-to-service authorization path for validator and
  importer events; never persist a user's access token.
- [x] Add audit fields and redact sensitive claims and filenames from logs.
- [x] Extract the proven SMTP transport into a reusable API mail module and keep
  password reset on the same transport contract.
- [x] Persist import-notification submission state independently from ImportJob
  lifecycle state and add READY, INVALID, IMPORTED, and terminal FAILED content.
- [x] Add API tests for cross-user access, replay, expiry, quota races, and
  invalid transitions.

### Deliverables

- Persistent ImportJob model
- Public import-management API
- Scoped upload capability
- Atomic quota reservation and reconciliation

### Exit Criteria

- An authorized user can create and read only permitted jobs.
- A capability is usable only for its job and intended operation.
- Concurrent requests cannot exceed the configured extracted-size quota.

## Phase 3: Direct Upload and Quarantine

Status: `DONE`

### Objective

Receive a ZIP directly and durably without exposing it to the final media tree.

### Work Items

- [x] Add an idempotent streaming endpoint such as `PUT /imports/{id}/sip`.
- [x] Enforce the compressed-byte limit independently of `Content-Length`.
- [x] Stream into a random `.part` file while calculating SHA-256.
- [x] Atomically finalize the SIP only after a complete successful request.
- [x] Reject non-ZIP content and expired, replayed, or mismatched capabilities.
- [x] Add a dedicated Caddy route, CORS policy, body limit, and timeout.
- [x] Add a separate ingest volume to local and Ansible Compose definitions.
- [x] Ensure Caddy and Cantaloupe cannot read the ingest volume.
- [x] Deliver and reconcile the durable idempotent `sip-stored` callback to
  `oldap-api`, changing the receipt notification from PENDING to DELIVERED.
- [x] Define stale `UPLOADING` and abandoned `.part` cleanup behavior.
- [x] Start FasnachtsPage job creation from the currently selected staging
  folder, submit its IRI as the target root, and show ZIP upload progress without
  confirmation.

### Deliverables

- Direct ZIP upload endpoint
- Isolated quarantine storage
- Upload progress and durable `UPLOADING -> VALIDATING` handoff

### Exit Criteria

- Interrupted uploads never appear as complete SIPs.
- Oversized uploads stop while streaming and leave no unbounded data behind.
- The uploaded SIP is not reachable through `/asset` or IIIF.

## Phase 4: Isolated Validation and Import Report

Status: `DONE`

### Objective

Analyze and safely extract the full SIP before any final asset or staging
resource is created.

### Work Items

- [x] Add one non-public ingest worker with restricted mounts, no general OLDAP
  credentials, a 4-vCPU ceiling, and the agreed RAM ceiling.
- [x] Inspect the central directory before extraction.
- [x] Reject encryption, symlinks, special files, absolute paths, drive/UNC
  paths, `..`, NULs, duplicate paths, and file/directory conflicts.
- [x] Enforce depth, count, size, path, and compression-ratio limits using
  actual streamed bytes rather than trusting ZIP metadata.
- [x] Enforce the worker CPU, memory/swap, and PID limits at the container
  boundary.
- [x] Enforce the total validation wall-clock deadline inside the worker. Run
  parser-heavy analysis in a spawned process group, kill that complete group at
  the fixed six-hour limit, retain a bounded `VALIDATION_TIMEOUT` FAILED report,
  and delete quarantine data before result publication.
- [x] Extract entries individually without `extractall()` and without following
  filesystem links.
- [x] Normalize names to NFC and detect normalized and portable collisions.
- [x] Carry the API-resolved selected target snapshot in every worker claim and
  include its IRI and display name in structural INVALID records.
- [x] Preflight the ZIP's top-level names against the target root: an existing
  canonical-equivalent child folder or a file/directory type conflict blocks the
  import. Canonical-equivalent existing media names are reported as warnings
  because every imported file receives an independent technical asset ID.
- [x] Probe all extracted files sequentially against the approved content and
  codec matrix using content signatures, Pillow, FFprobe, pdfinfo, qpdf, and
  veraPDF. Bound parser time and kernel-limit external-tool output.
- [x] Isolate hostile parsers from the API-aware worker: pass no client, claim,
  or credential; scrub the child environment; drop permanently to fixed UID/GID
  65532 with zero capabilities; deny network socket syscalls through inherited
  seccomp; grant access only to one job workspace; and revoke SIP access as soon
  as analysis exits.
- [x] Generate the complete versioned manifest and user-facing report for the
  full content-validation pipeline, including READY and content-driven INVALID.
- [x] Delete ZIP and extracted work data before publishing structural `INVALID`,
  including crash-safe replay from retained result metadata.
- [x] Reconcile actual extracted quota through the existing API result boundary
  and set the seven-day `READY` expiry.
- [x] Add a protected FasnachtsPage email destination with authoritative status
  polling plus report, tree, warning, error, checksum, and expiry views. Render
  large complete inventories progressively and keep confirmation side effects
  out of Phase 4.

### Deliverables

- Resource-limited validator worker
- Manifest and report generation
- `VALIDATING -> READY|INVALID` workflow
- Review UI without import confirmation side effects

The worker service remains deliberately Compose-profile-gated for explicit
operator opt-in until the Phase 5 commit workflow and pilot-readiness checks are
finished. The validation runtime safety boundary is implemented: parser code
has no API credential or network access, runs as a separate zero-capability UID,
and remains under the hard process-group deadline and container resource limits.

### Exit Criteria

- The malicious ZIP test corpus is rejected with stable report codes.
- For a complete bounded inventory, every archive entry appears exactly once in
  the report. A hard inventory limit instead produces bounded evidence with
  `inventoryComplete: false` and a blocking aggregate issue.
- `READY` implies all content is safe under the agreed MVP rules and its actual
  extracted size is reserved.
- `INVALID` retains no SIP or extracted payload.

## Phase 5: Confirmed Staging Import and Batch Commit

Status: `DONE`

### Objective

After explicit confirmation, create new media assets and reproduce the complete
directory structure as OLDAP staging resources without overwriting data.

### Work Items

- [x] Implement atomic `READY -> IMPORTING` confirmation in `oldap-api`
  (delivered with the Phase 2 job state machine and re-audited at Phase 5 start).
- [x] Generate an independent deterministic technical asset ID for every file.
- [x] Prepare all originals and derivatives in isolated job work directories.
- [x] Preserve raw names in the manifest and use the agreed NFC canonical name
  for `shared:originalName`.
- [x] Create final asset directories exclusively and recheck filesystem
  ownership/collisions without replacement.
- [x] Verify copied assets against the retained manifest and its checksums.
- [x] Recheck target-root existence, staging-area membership, authorization, and
  direct-child collisions immediately before import; abort before side effects
  if the target changed after validation.
- [x] Add an API batch-commit operation that creates the complete new
  `StagingFolder` tree and all `StagingMediaObject` resources in one GraphDB
  transaction.
- [x] Attach ZIP-root files directly to the selected existing target root and
  ZIP-root directories as its new children, without creating a wrapper folder
  or changing the selected folder's identity or metadata.
- [x] Include checksum, detected MIME type, staging area, folder, role, status,
  storage path, protocol, and derivative name in created resources. Keep the
  complete codec/probe facts in the retained immutable manifest rather than
  widening the closed `StagingMediaObject` ontology during this MVP.
- [x] Implement filesystem compensation that removes only assets carrying the
  exact failed job/manifest/entry ownership marker.
- [x] Make asset promotion, API commit, compensated failure publication, and
  crash recovery idempotent.
- [x] Transition to `IMPORTED` only in the same transaction that completes the
  full staging-resource commit.
- [x] Add a two-step FasnachtsPage confirmation action bound to the currently
  rendered state version, prevent duplicate/stale submission, and continue
  authoritative polling through `IMPORTING` to `IMPORTED` or `FAILED`.

### Current Progress

- The retained RFC 8785 manifest is loaded only against the checksum carried by
  the IMPORT claim. Preparation repeats that canonical digest check before any
  work directory is created.
- Technical asset IDs use UUIDv5 over `importId + entryIndex`, making retries
  deterministic without deriving storage identity from original names.
- Complete per-asset directories are prepared under a same-filesystem,
  job-owned work root. Linux production promotion requires
  `renameat2(RENAME_NOREPLACE)`; exact job-owned results from an interrupted
  attempt can be verified and reused, while unrelated directories are never
  replaced.
- Original SHA-256 and the closed MIME/delivery mapping are rechecked during
  preparation. UTF-8 text now produces the agreed `document.txt` derivative.
- The API batch boundary is now complete. It validates deterministic UUIDv5
  asset/resource identities and the closed delivery mapping, reauthorizes the
  original user, resolves the staging default role, rechecks target/root
  collisions, inserts the complete folder/media hierarchy, and persists
  IMPORTED plus its replay mapping in one GraphDB transaction. Relative paths
  identify mappings so synthesized implicit ZIP parent folders can reuse a
  descendant source entry index without ambiguity.
- The sequential worker now claims both VALIDATE and IMPORT tasks. IMPORT reads
  the exact claim-bound manifest, preserves explicit empty folders, synthesizes
  omitted parents, prepares/promotes every asset, and calls the atomic API
  batch. Deterministic events and owner markers recover ambiguous responses.
- A definite API rejection compensates only job-owned assets, deletes the
  temporary payload, durably records that ordering, and publishes terminal
  FAILED. If failure publication is interrupted, the retained receipt is
  replayed without requiring the deleted payload. Transport/5xx ambiguity at
  commit deliberately keeps assets for deterministic commit replay.
- FasnachtsPage now gates confirmation on matching READY job/report state and
  unexpired report evidence, shows the exact selected target before the final
  action, submits the rendered optimistic state version, reloads authoritative
  state after conflicts, and distinguishes successful and compensated-failure
  terminal outcomes. Lifecycle policy tests cover the complete
  `UPLOADING -> VALIDATING -> READY -> IMPORTING -> IMPORTED` polling and
  confirmation sequence.
- Phase 5 is complete. The worker profile remains operator-gated until the
  Phase 6 lifecycle cleanup, operations checks, and pilot readiness work are
  complete.

### Deliverables

- Explicit confirmation endpoint
- Importer worker
- Transactional staging-resource batch commit
- Verified no-overwrite compensation workflow
- Finished confirmation and terminal-state user flow

### Exit Criteria

- A successful import reproduces every agreed directory, including empty ones
  if D-006 requires them.
- No OLDAP resource refers to a missing final asset after recovery completes.
- Retrying any import step cannot duplicate or overwrite assets or resources.
- A READY user action is concurrency-bound to the reviewed state and the UI
  follows the authoritative job to one terminal import outcome.

## Phase 6: Cleanup, Reconciliation, UI Completion, and Operations

Status: `IN PROGRESS`

### Objective

Complete lifecycle safety, operational visibility, and the end-user workflow.

### Work Items

- [x] Implement an idempotent periodic cleanup worker using API compare-and-set
  claims rather than filesystem age alone.
- [x] Expire stale `UPLOADING` jobs 24 hours after creation through an API-owned
  cleanup claim; only the accepted cleanup result may release lifecycle state
  and quota. Media filesystem age must never expire a finalized job.
- [x] Expire `READY` jobs after seven days and delete all temporary payloads.
- [x] Prove that cleanup cannot claim `IMPORTING` jobs.
- [x] Remove SIP and temporary work data after fully successful import while
  retaining report, manifest, and checksums.
- [x] Add reconciliation for worker crashes, failed callbacks, orphaned work
  directories, unregistered final assets, and incomplete cleanup.
- [x] Trigger bounded retries for pending API-owned email submissions without
  exposing SMTP configuration to the ingest worker.
- [x] Complete FasnachtsPage polling, confirmation, progress, retry guidance,
  expiry display, and terminal-state UX.
- [x] Add structured audit logs, disk-capacity checks, and owner-visible error
  reporting compatible with available university logging; defer dashboards.
- [x] Add end-to-end, concurrency, quota-race, crash, retry, and cleanup tests.
- [x] Document deployment, backup, retention, incident response, and recovery.
- [ ] Roll out behind a feature flag, then conduct test and production pilots.

### Deliverables

- Complete automated lifecycle cleanup
- Reconciliation and observability
- Finished FasnachtsPage ZIP-import workflow
- Deployment and operational runbooks

### Exit Criteria

- Lifecycle invariants hold under concurrent jobs and injected process failures.
- A pilot import can be traced from job creation through retained audit records.
- Temporary storage remains bounded without manual intervention.

## Decision Register

| ID | Decision | Recommendation | Status | Owner/Target |
| --- | --- | --- | --- | --- |
| D-001 | Security and resource limits | Use the confirmed table above, including 500 MB compressed and 3 GB extracted; never increase without test evidence. | Decided | Phase 0 |
| D-002 | Container and codec matrix | Probe content explicitly. Accept JPEG/PNG/single-page TIFF/single-image HEIF or HEIC; WAV integer PCM 8/16/24/32-bit at 8–192 kHz, FLAC 8/16/24-bit at 8–192 kHz, and MP3 at 8–48 kHz, all mono/stereo; MP4 H.264 8-bit 4:2:0 Baseline/Main/High through level 5.2 with optional mono/stereo AAC-LC; strict UTF-8 content detected specifically as `text/plain`; PDF follows D-017. | Decided | Phase 0 |
| D-003 | Handling unsupported files | Reject the complete SIP; report every entry; omit only known packaging artifacts. Reject empty and artifacts-only archives with `NO_IMPORTABLE_CONTENT`. | Decided | Phase 0 |
| D-004 | Existing folder/name collisions | Never merge implicitly. A canonical-equivalent existing child folder or file/directory conflict blocks the import. An existing medium with the same canonical original name is a report warning, not an overwrite, because the new asset has an independent ID. | Decided | Phase 0 |
| D-005 | ZIP root mapping | The selected existing `shared:StagingFolder` is the import root. ZIP-root files attach directly to it and ZIP-root directories become its children; create no ZIP wrapper. The selected root does not count toward the five-level ZIP depth limit. | Decided | Phase 0 |
| D-006 | Empty directories | Preserve them as staging folders. | Decided | Phase 0 |
| D-007 | Original-name semantics | Retain raw name in manifest; store NFC canonical name on the resource. | Decided | Phase 0 |
| D-008 | Operational states | Add `FAILED` and `CANCELLED`; do not treat infrastructure failure as `INVALID`. | Decided | Phase 0/2 |
| D-009 | Quota strategy | Require positive integer `shared:stagingQuotaBytes` per staging area; reserve `min(3 GB, declared compressed bytes * 50)` at creation, reconcile to actual extracted originals, and enforce separate physical capacity guards. | Confirmed | oldap-api/oldaplib, Phase 2 |
| D-010 | Malware scanning | Do not add an application-integrated scanner to the lean MVP. Before a pilot, the VM owner and university IT verify Defender coverage for Linux `/data` and record any required operational control. | MVP decided; operational reply pending | VM owner/University IT, before pilot |
| D-011 | Retention | INVALID/FAILED 90 days; EXPIRED/CANCELLED 30 days; IMPORTED records follow the retained staging/archive record. | Decided | Phase 0/6 |
| D-012 | Resumable uploads | Do not implement in the MVP; use one idempotent streaming PUT. | Decided | Phase 0/3 |
| D-013 | Directory resource class | ZIP directories create `shared:StagingFolder`, never `shared:ArchiveUnit`. | Decided | Phase 0/5 |
| D-014 | Authorization | Require user permission `ADMIN_CREATE` and effective role permission of at least `DATA_UPDATE` on the containing `shared:StagingArea`; recheck at creation and confirmation and verify target-folder membership. | Decided | Phase 0/2 |
| D-015 | Worker resource ceiling | Process entries sequentially under hard cgroup limits of 4 vCPUs, 6 GiB RAM, an equal memory-plus-swap ceiling where supported, and 128 PIDs; use smaller per-tool thread pools. | Decided | Phase 0/4 |
| D-016 | Import notification ownership | Send mail only from `api.oldap.org`; keep UI polling authoritative, links authenticated, mail state independent, and SMTP credentials off the media VM. | Decided | Phase 0/2/6 |
| D-017 | PDF acceptance profile | Require validated PDF/A-1 or PDF/A-2 and independently reject encryption, JavaScript, launch actions, rich media, and all embedded files; reject PDF/A-3 and PDF/A-4. | Decided | Phase 0 |
| D-018 | API/trust boundaries | Keep API job/state/report authority, direct immutable media PUT, purpose-specific public/upload/internal credentials, leased worker claims, idempotent events, and transactional create-only commit as separate contracts. | Decided | Phase 0 |
| D-019 | Abandoned upload cleanup | Remove only recognizable `.part-<importId>-*` directories older than 24 hours, never symlinks or finalized UUID directories, with at most 100 removals per pass. Stale `UPLOADING` jobs use the same 24-hour deadline but remain API-owned and require a cleanup claim/result in Phase 6; filesystem age never changes job state or quota. | Decided | Phase 3/6 |

## Cross-Repository Component Map

| Repository/component | Planned responsibility |
| --- | --- |
| `oldap-mediaserver/mediaserver` | Direct upload ingress, shared media processing, validator/importer/cleanup workers |
| `oldap-mediaserver/Caddyfile` and deployment | Dedicated import routing and isolated volume/container policy |
| `oldap-api` | ImportJob state, authorization, quota, confirmation, events, transactional resource commit |
| `oldaplib` | Ontology/schema support and transaction-capable staging batch operations where required |
| `FasnachtsPage` | Job creation, direct upload, report review, confirmation, progress and expiry UX |

## Verification Matrix

| Area | Required evidence |
| --- | --- |
| Archive safety | Malicious fixture suite for traversal, bombs, links, encryption, duplicates, malformed metadata |
| Content policy | Positive and negative fixture for every permitted and rejected MIME/codec combination |
| Authorization | Cross-user, cross-project, expired capability, replay, wrong audience, and wrong job tests |
| Quotas | Concurrent reservation and reconciliation tests using actual extracted bytes |
| Consistency | Failure injection before and after asset promotion and GraphDB commit |
| Cleanup | Expiry and orphan tests plus an explicit invariant test for `IMPORTING` |
| Compatibility | Existing single-file upload, asset delivery, deletion, IIIF, audio/video, and PDF tests |
| User flow | Browser-level create, upload, report, confirm, import, invalid, and expired scenarios |

## Progress Log

Add new entries at the top.

### 2026-08-05 — Phase 6 operations runbook complete

- Deployment: documented immutable-version test-first rollout, Ansible gates,
  health/authorization verification, explicit profiled-worker activation,
  maintenance stop, post-deploy smoke checks, and version rollback without
  touching GraphDB or bind-mounted data.
- Backup/recovery: classified final media, retained records, GraphDB, temporary
  ingest, Caddy state, configuration, and secrets. The runbook records the
  current daily university backup and resulting 24-hour RPO, requests ingest
  exclusion where supported, defines planned consistency windows, requires a
  pre-pilot restore drill, and gives a safe restore order with the worker held.
- Retention: documented every implemented temporary-payload boundary and the
  agreed 30-/90-day record policy. An explicit pre-pilot gap remains: API job
  and retained-record pruning is not automated, so indefinite retention is the
  safe current behavior and age-based manual deletion is forbidden.
- Incidents: added SEV-1/2/3 ownership, first-response evidence rules, and
  playbooks for disk pressure, stuck IMPORTING, API/callback outage, cleanup
  acknowledgement loss, suspected parser compromise, email failure, VM restart,
  and inconsistent restore evidence. No playbook permits state reset,
  filename-based reconciliation, or overwriting an asset.
- Checklist: named contacts, university backup/exclusion, Defender reply,
  central logging, RTO, restore proof, pruning disposition, feature gate, test
  cases, and pilot stop criteria must be recorded before production activation.

### 2026-08-05 — Phase 6 automated lifecycle and recovery matrix complete

- End-to-end: a service-level test now drives the authoritative API lifecycle
  from creation and SIP receipt through VALIDATE/READY, reviewed confirmation,
  IMPORT commit, IMPORTED, and deletion-proof cleanup. It verifies retained
  validation/import/cleanup events, resource mapping, and imported quota.
- Concurrency/quota: synchronized threads prove atomic staging quota admission,
  one global worker claim, and one authoritative winner for simultaneous READY
  confirmation. Existing validation reconciliation and commit transaction tests
  cover actual-size quota and create-only resources.
- Crash/retry: media tests now explicitly recover cleanup after payload deletion
  with a lost API acknowledgement and a reclaimed claim. Ambiguous import commit
  failure retains assets and succeeds on deterministic retry. Existing retained
  validation-result, timeout, callback, notification, and compensation replay
  tests complete the matrix.
- Scope: `docs/zip-import/v1/PHASE6_TEST_MATRIX.md` maps every automated invariant
  to its cross-repository evidence. Production-sized archives, disposable-volume
  pressure, real native-conversion kills, backup/restore, authenticated deployed
  browser flow, and any university-required EICAR check remain operator-only
  pilot exercises.
- Verification: all 137 mediahelper tests pass with one expected Linux-only host
  skip; all 51 focused oldap-api import/authentication tests pass. Focused Black
  and whitespace checks pass. Existing FasnachtsPage lifecycle tests are mapped;
  they were not rerun because this workspace currently has no installed `tsx`
  dependency.

### 2026-08-05 — Phase 6 physical disk admission and operational errors

- Policy: each upload, validation extraction, and confirmed asset-preparation
  phase checks its destination filesystem immediately before writing. The
  effective untouched reserve is `max(20% of total capacity, configured
  absolute reserve)`. The API's extracted-byte quota remains a separate logical
  control.
- Admission: upload accounts for the SIP plus the frozen worst permitted 50:1
  validation expansion. Validation repeats the current expansion check. Import
  reserves two times actual extracted bytes for the original copy and estimated
  derivatives; the mandatory volume reserve remains additional headroom.
- Failure semantics: a browser upload that cannot maintain the reserve returns
  HTTP 507 with stable `IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT` and retains no
  partial SIP. Exact replay of an already finalized SIP remains available. A
  later worker capacity block occurs before extraction or asset preparation,
  stays retryable, and is never mislabeled content INVALID.
- Operations: privacy-safe structured log events include import ID, phase,
  required bytes, current free bytes, and reserve bytes, never filenames or
  parser content. `OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES` is wired through local
  Compose and Ansible; `0` means the mandatory 20% rule alone, not no reserve.
- Verification: all 135 mediahelper tests pass with one expected Linux-only
  host skip. Focused formatting passes for every new/modified module except the
  already non-Black-conforming legacy `app.py`; compilation and whitespace
  checks pass. The production image builds and imports the capacity guard.

### 2026-08-05 — Phase 6 bounded reconciliation and email retry

- Reconciliation audit: SIP callbacks already use durable PENDING receipts and
  a bounded reconciler. IMPORT recovery uses expired-lease reclaim,
  deterministic UUIDv5 identities, exact owner markers, complete-manifest
  replay, and create-only commit. Prepared work roots are reset only with the
  matching job marker; promoted-but-unregistered assets are reused or exactly
  compensated. CLEANUP deletion is idempotent and reclaims after lease expiry.
  No heuristic orphan deletion was added.
- Email gap closed: API jobs now persist the last notification-attempt time.
  Failed/PENDING notifications receive at most three submissions with at least
  five minutes between attempts. One due retry is attempted only during an idle
  worker poll, so SMTP cannot consume a freshly leased VALIDATE/IMPORT/CLEANUP
  task. The media worker only triggers the API route and receives no SMTP
  settings or recipient data.
- Delivery semantics: SMTP submission remains bounded at-least-once because a
  process failure after server acceptance but before result persistence is
  inherently ambiguous. Email state remains independent from ImportJob
  lifecycle and never blocks validation, import, cleanup, or polling.
- Verification: all 50 focused oldap-api import/authentication tests and all 129
  mediahelper tests pass, with one expected Linux-only host skip. Formatting,
  compilation, and whitespace checks pass.

### 2026-08-05 — Phase 6 started: API-claimed lifecycle cleanup

- Status: Phase 6 is in progress. The existing global sequential worker now
  claims CLEANUP after VALIDATE and IMPORT; no broker, second worker, or
  filesystem-age authority was introduced.
- API selection: UPLOADING becomes cleanup-eligible exactly 24 hours after job
  creation, READY at its persisted seven-day expiry, and CANCELLED/IMPORTED
  through `cleanupPending`. IMPORTING and every unexpected intermediate state
  are explicitly ineligible. Claim creation increments stateVersion and global
  lease exclusion remains authoritative.
- Deletion/result ordering: media deletes only the canonical claimed ingest
  directory, never the separate immutable record directory or final assets,
  then posts a closed idempotent cleanup result. EXPIRED and quota release occur
  only after that proof. IMPORTED keeps its extracted-byte quota because the
  staged originals continue to consume the StagingArea allocation.
- Races/recovery: an active cleanup claim blocks upload-capability reissue and a
  late SIP callback. User cancellation invalidates an active claim cleanly.
  Deletion is idempotent, so a crash/API outage after deletion is recovered by
  lease expiry and a new API claim without requiring the removed payload.
- Verification: all 129 mediahelper tests pass with one expected Linux-only
  host skip; all 48 focused oldap-api import/authentication tests pass. Python
  compilation, YAML parsing, formatting, and whitespace checks pass.

### 2026-08-05 — Phase 5 complete: confirmed atomic staging import

- Status: Phase 5 is complete across oldap-api, oldap-mediaserver, and
  FasnachtsPage. READY confirmation is optimistic-concurrency bound, IMPORT is
  handled by the existing global sequential worker, and IMPORTED is committed
  atomically with the complete StagingFolder/StagingMediaObject hierarchy.
- Storage and recovery: deterministic UUIDv5 assets are prepared and verified
  in a same-filesystem job workspace, promoted without replacement, and reused
  on exact replay. Definite commit rejection compensates only exact job-owned
  assets before publishing terminal FAILED; ambiguous outcomes retain evidence
  for deterministic commit replay.
- User flow: the protected report view uses a deliberate two-step action that
  repeats the selected target, submits the reviewed stateVersion, blocks
  duplicate/stale action, refreshes authoritative state after conflicts, polls
  IMPORTING, and distinguishes IMPORTED from compensated FAILED.
- Boundary: successful temporary-payload cleanup, lifecycle expiry claims,
  reconciliation, disk admission, operations documentation, and pilot rollout
  remain Phase 6. The worker profile stays operator-gated until those checks are
  ready.
- Verification: all 127 mediahelper tests pass with one expected Linux-only
  host skip; all 42 focused oldap-api import/authentication tests pass; all 96
  FasnachtsPage domain tests and targeted ESLint pass; both OpenAPI contracts
  validate; and the frontend production build succeeds. Project-wide
  svelte-check remains at its unchanged 22-error/37-warning baseline without a
  ZIP-import diagnostic.

### 2026-08-05 — Phase 4 complete: protected FasnachtsPage report review

- Status: Phase 4 is complete. FasnachtsPage now exposes the authenticated,
  token-free `/imports/{importId}` email destination, polls OLDAP as the
  authoritative state source, and loads the protected immutable v1 report only
  when the job advertises it.
- Review UX: the page represents every lifecycle state, READY expiry, summary
  counts, global and entry issues with stable German copy, normalized hierarchy,
  MIME evidence, ZIP/manifest checksums, and large inventories in progressive
  batches. The Staging upload result links directly to the same view; login
  safely returns only to a UUID-shaped import route.
- Boundary: no confirmation or staging mutation was added. Phase 5 owns the
  fresh authorization/target/collision checks and atomic import commit.
- Malware disposition: no application-integrated scanner is part of the lean
  MVP. The VM owner has asked university IT whether Defender covers Linux
  `/data`; the answer is a pre-pilot operational check, not a Phase 4 blocker.
- Verification: six focused frontend ZIP tests and targeted ESLint pass; the
  production build succeeds; project-wide Svelte diagnostics remain at the
  documented 22-error/37-warning baseline with no ZIP-import finding. The
  browser smoke test verified the protected email route and UUID-preserving
  login handoff; an authenticated live-stack run remains pre-pilot work.

### 2026-08-05 — Phase 4 parser credential and privilege isolation

- Status: the parser isolation work item is complete; Phase 4 remains
  `IN PROGRESS` for the FasnachtsPage report/review UI and the already deferred
  Defender/malware-scanning disposition before a pilot. The worker remains an
  explicit Compose profile and is not silently activated by this change.
- Trust split: SIP checksum verification, API target preflight, report
  projection, retained records, cleanup, heartbeat, and result publication stay
  in the trusted parent. The spawned child receives only parser objects, the SIP
  path, its job-local extraction path, and a fixed sandbox policy.
- Credentials: the API client is deliberately unpicklable in worker tests and
  never crosses the process boundary. The child clears the inherited environment
  before parsing and retains only fixed PATH/locale/HOME values.
- Privileges: production starts the parent with only CHOWN, DAC_OVERRIDE,
  FOWNER, KILL, SETGID, and SETUID capabilities plus container-level
  no-new-privileges. The child drops supplementary groups and permanently enters
  UID/GID 65532; Linux confirms its effective capability mask is zero.
- Network/files: a no-new-privileges libseccomp filter denies socket creation and
  network I/O for the parser and all decoder descendants. The child can traverse
  but not list the ingest root, can read only its temporarily group-readable SIP,
  and writes only `.parser-work`; the parent revokes SIP access immediately and
  promotes READY extraction by an atomic same-filesystem rename.
- Deadline: the child returns parser evidence only. API preflight and document
  projection consume the same remaining fixed six-hour budget; the preflight
  request timeout is reduced to the remaining wall time.
- Verification: host unit/regression tests prove secret scrubbing, absence of
  client pickling, parent-owned preflight, deadlines, cleanup, and replay. The
  Linux image verifies UID/GID drop, zero child capabilities, socket denial,
  low-privilege extraction, and FFprobe/qpdf/veraPDF execution under seccomp.
  All 117 media tests pass with one Linux-only skip; all 37 focused oldap-api
  import/boundary tests, both authoritative OpenAPI specs, Compose rendering,
  Ansible syntax, compilation, focused Black, and whitespace checks pass.

### 2026-08-05 — Phase 4 hard validation wall-clock deadline

- Status: the total validation deadline work item is complete; Phase 4 remains
  `IN PROGRESS` for parser privilege isolation and the FasnachtsPage review UI.
- Isolation: every parser-heavy validation runs in a fresh spawned process and
  Unix process group. The sequential parent keeps the API claim heartbeat and
  enforces the frozen six-hour deadline with a monotonic clock.
- Timeout: the parent kills the complete analysis process group, including
  decoder children, stores a schema-valid immutable FAILED report with stable
  `VALIDATION_TIMEOUT`, deletes ZIP and extracted data, and only then publishes
  the claim-bound result to oldap-api. No technical manifest is fabricated.
- Recovery: retained FAILED report bytes, digest, summary, cleanup fact, and
  failure code are create-only and allow exact replay after API interruption.
- Policy: deployment cannot raise the six-hour ceiling through an environment
  variable; tests may inject a shorter deadline without changing production
  acceptance policy.
- Residual boundary: the spawned analysis currently inherits the import-service
  client needed for target preflight and runs under the worker UID. Phase 4 must
  remove parser access to that credential and review the UID boundary before
  enabling the Compose profile.
- Verification: all 113 media tests pass with one Linux-only skip; all 37
  focused oldap-api import/boundary tests and both authoritative OpenAPI specs
  pass. Compose rendering, Ansible syntax, compilation, focused Black,
  whitespace, production image build, and in-image worker/`setsid` checks pass.

### 2026-08-05 — Phase 4 API-owned target-root preflight

- Status: the target-root preflight work item is complete; Phase 4 remains
  `IN PROGRESS` for total wall-clock enforcement, parser privilege isolation,
  and the FasnachtsPage review UI.
- Boundary: after successful content validation, the worker derives all
  explicit and implicit ZIP-root children and sends only their entry index,
  NFC name, and file/directory type through a current VALIDATE claim. It never
  receives GraphDB credentials or a user token.
- API: `POST /internal/import-claims/{claimId}/target-preflight` verifies worker,
  lease, state version, and target IRI; reads at most 10,000 current direct
  `shared:inStagingFolder` children; and applies the ZIP validator's NFC,
  trailing-dot/space, and case-folded portable collision key.
- Findings: a missing/renamed/moved target emits blocking `TARGET_CHANGED`;
  canonical-equivalent names involving a folder emit blocking
  `TARGET_FOLDER_COLLISION`; media/media equivalence emits non-blocking
  `TARGET_MEDIA_NAME_COLLISION`. Findings are included in the immutable v1
  manifest/report and participate in READY/INVALID projection.
- Race boundary: validation preflight is not import authorization. Phase 5
  rechecks target identity, permission, and collisions inside the create-only
  batch commit because the hierarchy can change after READY.
- Verification: 109 media tests pass with one Linux-only skip; all 29 focused
  oldap-api import tests pass; both authoritative OpenAPI contracts validate.
- Next: enforce the hard total validation wall-clock deadline and publish a
  bounded FAILED result after payload deletion.

### 2026-08-05 — Phase 4 content matrix and READY projection

- Status: Phase 4 remains `IN PROGRESS`; content validation and complete
  READY/content-INVALID records are implemented. The worker remains behind the
  `zip-import-validation` profile pending target-root preflight, total deadline
  enforcement, and parser privilege isolation review.
- Detection: classify from byte signatures rather than filenames. Validate
  JPEG/PNG/single-page TIFF with Pillow, single-image HEIF/HEIC with
  libvips/libheif, the frozen WAV/FLAC/MP3 and H.264/AAC
  matrices with FFprobe, and strict UTF-8 plain text while rejecting detected
  XML, HTML, SVG, JSON, CSV, scripts, nested archives, and unsupported binary
  formats. Packaging artifacts remain visible as ignored warnings.
- PDF: combine pdfinfo encryption evidence, recursive qpdf active-content and
  attachment inspection, and veraPDF automatic PDF/A conformance. Accept only
  compliant PDF/A-1 or PDF/A-2 at levels a, b, or u.
- Bounds: process entries sequentially; apply per-tool deadlines and sanitized
  environments; cap stdout and stderr at the kernel file-size boundary rather
  than collecting unbounded pipes. The Docker runtime includes pinned veraPDF
  1.30.2 plus qpdf, Poppler, FFmpeg, and a Debian JRE.
- Records: every structural entry receives exactly one manifest/report entry.
  READY retains quarantine data, reserves actual extracted bytes through the
  API result boundary, and exposes a seven-day expiry. Content INVALID retains
  immutable evidence and deletes all temporary payload before publication.
- Verification: 105 host tests pass (one Linux-only output-bound test skipped),
  the production image builds, and its complete parser runtime plus kernel
  output cap pass in-container. Compose, Ansible syntax, compilation, focused
  formatting, and whitespace checks pass.
- Next: implement API-owned target-child preflight and the hard total validation
  deadline, then resolve parser privilege isolation before enabling the profile.

### 2026-08-05 — Phase 4 leased worker and immutable record boundary

- Status: Phase 4 remains `IN PROGRESS`; claim/heartbeat execution, retained
  records, structural INVALID publication, and container resource isolation are
  implemented. The worker stays behind the `zip-import-validation` Compose
  profile until content/codec validation is present.
- API claim: the existing atomic single-worker queue now supplies immutable job
  creation/requester/original-name/compressed-size facts in addition to target
  and SIP checksum. The worker accepts only strict VALIDATE claims and renews
  the lease on a dedicated heartbeat thread.
- Records: RFC 8785-canonical manifests and exact compact reports are published
  create-only under `/data/import-records/<importId>`, separately from temporary
  ingest data. Reports bind to the manifest checksum; oldap-api reads exact
  bytes through a dedicated import-records JWT endpoint that remains absent
  from Caddy's public routes.
- Failure ordering: structural INVALID records are retained first, the complete
  quarantine directory is then deleted, and only afterwards is INVALID sent to
  oldap-api. Durable result metadata permits safe publication after a crash or
  API outage without restoring the deleted SIP.
- Isolation: the worker has no port, no user/media/upload/record-read secret,
  only ingest and record mounts, a read-only root filesystem, a noexec tmpfs,
  and limits of 4 CPUs, 6 GiB memory plus equal swap, and 128 PIDs.
- Verification: 97 media repository tests and 25 focused oldap-api import tests
  pass; all three OpenAPI contracts validate.
- Next: implement bounded file-content MIME/codec/PDF-A/text analysis and READY
  manifest/report projection, then remove the worker profile gate.

### 2026-08-05 — Phase 4 structural ZIP validation core

- Status: Phase 4 is `IN PROGRESS`; the network-free structural inspection and
  all-or-nothing extraction boundary is implemented before the worker/API and
  content-probe layers are added.
- Inspection: parse bounded EOCD, central-directory, local-header, extra-field,
  and optional data-descriptor structures directly. Accept only one-disk,
  non-ZIP64 stored/deflated archives; reject encryption, self-extracting
  preambles, unsupported flags/methods, malformed ranges, mismatched headers,
  and directory payload ambiguity.
- Names and paths: preserve raw filename bytes, require ASCII or explicitly
  flagged strict UTF-8, normalize to NFC, treat both slash forms as separators,
  and reject traversal, absolute/drive/UNC paths, NUL/control/bidi/reserved
  names, excessive depth/length, duplicates, portable case collisions, NFC
  collisions, file/directory conflicts, symlinks, and special files.
- Extraction: create a new mode-0700 work root, open every entry individually,
  stream SHA-256 and CRC evidence, enforce actual per-file/aggregate bytes and
  compression ratios while reading, and remove the complete work root on any
  rejection. `extractall()` is never used.
- Verification: 24 focused deterministic structural cases and all 90 repository
  tests pass. Targeted Black, compilation, whitespace, the production Docker
  build, and in-image validator import pass.
- Next: add the non-public single-worker claim/heartbeat boundary and map this
  inventory into the immutable v1 manifest before layering MIME/codec probes.

### 2026-08-05 — Phase 3 complete with selected-folder browser upload

- Status: Phase 3 is `DONE`; the direct quarantine boundary now runs from the
  selected FasnachtsPage StagingFolder through API job creation to durable SIP
  finalization and `VALIDATING` notification.
- Frontend: FasnachtsPage snapshots the currently selected existing
  `shared:StagingFolder` IRI in `targetRootFolderIri`, validates the `.zip` and
  500,000,000-byte browser envelope, and sends the File directly to the issued
  media capability URL with a UUID upload request ID and visible progress.
- Security boundary: the OLDAP access token is used only for job creation; the
  media PUT uses only the short-lived upload capability. The UI offers no
  confirmation before validation, and the media receipt identity and SHA-256
  shape are checked before success is shown.
- Verification: all 90 FasnachtsPage domain tests and targeted ESLint pass; the
  production build succeeds. Project-wide Svelte checking remains at its known
  22-error/37-warning baseline without ZIP-flow diagnostics. The protected
  route guard was smoke-tested; an authenticated end-to-end upload still needs
  reachable local API/media services.
- Next: Phase 4 implements isolated extraction, full security/content analysis,
  validation records, report production, polling, and report presentation.

### 2026-08-05 — Phase 3 abandoned upload cleanup

- Status: the Mediahelper/API backend work of Phase 3 is complete. Phase 3
  remains `IN PROGRESS` only for the FasnachtsPage selected-folder upload flow;
  lifecycle expiry execution remains correctly assigned to Phase 6.
- Partial cleanup: the existing 60-second maintenance loop removes at most 100
  directories per pass and only when the name exactly matches
  `.part-<canonical UUID>-*`, the entry is a real directory rather than a
  symlink, and its directory mtime is more than 24 hours old.
- Safety boundary: finalized `<importId>` directories, SIPs, receipts, recent
  partial uploads, files, symlinks, and unknown names are never selected by
  age. The 24-hour grace is 96 times the supported 15-minute ingress timeout.
- Job lifecycle: D-019 assigns the same 24-hour stale deadline to UPLOADING but
  reserves state transition, cleanup authorization, and quota release to an
  API compare-and-set cleanup claim/result in Phase 6. Media never infers a job
  transition from filesystem age.
- Verification: all 66 tests pass, including old/recent partials, finalized SIP
  preservation, symlink/outside-root protection, unknown-name preservation,
  and the 100-item pass bound. Formatting, compilation, whitespace, Ansible
  syntax, and the production Docker build pass.
- Next: connect the FasnachtsPage upload action to the selected existing
  `shared:StagingFolder`. Before pilot rollout, Phase 6 adds the API-owned stale
  UPLOADING transition and the physical free-space admission guard.

### 2026-08-05 — Phase 3 durable API callback reconciliation

- Status: Phase 3 remains `IN PROGRESS`; the durable `UPLOADING -> VALIDATING`
  handoff is complete. Stale upload/partial cleanup and the FasnachtsPage flow
  remain open.
- Callback: retain one immutable event UUID inside `receipt.json`, create a new
  60-second `typ=import-service` JWT for every delivery attempt, and POST the
  exact storedAt, size, SHA-256, and upload request UUID to the existing
  idempotent API endpoint. Validate the acknowledgement's import identity and
  reject an acknowledgement that remains UPLOADING.
- Delivery state: only an accepted API response atomically changes the local
  receipt from PENDING to DELIVERED. Failures never remove or rewrite the SIP,
  never invent a new event, and never turn a durable upload into an HTTP error.
  An exact PUT replay retries PENDING immediately.
- Reconciliation: one small daemon loop per configured mediahelper process scans
  at most 100 PENDING receipts every 60 seconds. The MVP deployment retains one
  Gunicorn worker; API event idempotency and atomic receipt replacement also
  make duplicate attempts harmless.
- Secrets: media deployment now receives the same dedicated import-service key
  as the API in addition to the separate upload key. Ansible requires all four
  media-side JWT purposes to be distinct and at least 32 bytes.
- Verification: all 64 tests pass, including exact callback payload/JWT claims,
  PENDING retention, same-event retry, acknowledgement persistence, periodic
  reconciliation behavior, and deployment wiring. Compilation, formatting,
  whitespace checks, Ansible syntax, the production Docker build, and in-image
  callback-module imports pass.
- Next: implement bounded stale `.part` cleanup and decide/implement the stale
  UPLOADING expiry transition before integrating FasnachtsPage.

### 2026-08-05 — Phase 3 atomic quarantine ingress

- Status: Phase 3 is `IN PROGRESS`; direct SIP ingress and deployment isolation
  are implemented, while API callback reconciliation, stale cleanup, and the
  FasnachtsPage upload flow remain open.
- Authorization: mediahelper accepts only a dedicated `typ=ingest-upload`,
  `aud=oldap-media-ingest` JWT signed with the separate upload key. It requires
  import ID, subject, JTI, issuer, times, and a bounded `maxBytes`; expired,
  wrong-purpose, malformed, cross-job, and key-reuse cases fail closed.
- Storage: stream to a random mode-0700 `.part-<importId>-*` directory while
  calculating exact SHA-256 and enforcing the capability limit independently
  of Content-Length. Require the declared/actual size match and the restrictive
  ZIP signature, fsync the SIP and receipt, then atomically rename the complete
  directory to `<ingestRoot>/<importId>`. Interrupted and rejected requests
  remove partial state; exact request-ID replay returns the receipt without
  reading or replacing the SIP, while another request ID conflicts.
- Isolation: local and Ansible Compose mount a distinct ingest host directory
  only into mediahelper. Caddy and Cantaloupe retain only the delivery mount;
  Ansible rejects an ingest root nested below the delivery root. Caddy exposes
  only the UUID-shaped PUT/OPTIONS route with a 500 MB body ceiling and 15-minute
  proxy timeouts.
- Verification: all 59 repository tests pass, including streamed oversize,
  interruption, non-ZIP, expired/mismatched capability, replay, deployment
  mount, and delivery-tree isolation cases. Both media OpenAPI contracts and
  the local Caddy configuration validate; the production mediahelper image
  builds and imports both ingest modules successfully.
- Next: add the durable service-token callback/retry path and stale `.part` /
  stale-UPLOADING cleanup policy before connecting the FasnachtsPage flow.

### 2026-08-05 — Phase 2 complete

- Status: Phase 2 is `DONE`; all work items and exit criteria are implemented
  and covered by focused verification.
- Public contract: added stable newest-first cursor pagination to `GET /imports`;
  cursors are bounded and opaque, remain scoped to the caller and active state
  filter, and invalid or stale cursors fail closed.
- Audit/privacy: lifecycle records retain actor, timestamps, immutable target,
  state version, and idempotency facts. Operational audit logging uses a strict
  whitelist of event, import ID, state, version, and sanitized request ID; it
  excludes filenames, target display names, user/service/capability tokens,
  claim IDs, checksums, and report contents.
- Boundary coverage: cross-user reads are indistinguishable from missing jobs;
  SIP and validation result replay is idempotent only when identical; expired
  READY jobs cannot be confirmed; invalid and stale transitions fail; and a
  synchronized two-request race proves staging quota cannot be overreserved.
- Verification: 33 focused import/report/notification/password-mail tests and all 8
  authentication-boundary tests pass, as do 7 shared staging/archive ontology
  tests. Python compilation, Black, authoritative OpenAPI validation, and
  repository whitespace checks pass.
- Next: Phase 3 implements the media-owned direct SIP endpoint, immutable
  quarantine storage, capability enforcement, and the durable SIP-stored
  callback. Import and cleanup completion events remain with their later
  execution/lifecycle phases, not Phase 2.

### 2026-08-05 — Phase 2 protected reports and import notifications

- Status: Phase 2 remains `IN PROGRESS`; public report authorization and the
  notification submission contract are implemented on the API side.
- Reports: authorize the caller as job owner, issue a five-minute
  `typ=import-records` API-to-media token with its own key/audience, retrieve the
  retained report with bounded time/size, verify the exact SHA-256 and import
  identity/outcome, and return it as `private, no-store`. The internal token is
  never exposed to the browser. Media-side record serving remains Phase 3/4.
- Mail: extract the proven console/STARTTLS SMTP transport from password-reset
  code into one reusable module without changing reset content or semantics.
- Notifications: persist PENDING/SENT/FAILED, target lifecycle state, attempt
  count, and sent time separately from lifecycle state. READY, INVALID, FAILED,
  and IMPORTED templates contain only an authenticated job link and bounded
  status prose, never filenames, report details, or bearer credentials.
- Failure behavior: commit lifecycle state before SMTP submission; failure is
  recorded by exception class only, never rolls back the import, and is retried
  at most three times on idempotent result replay.
- Verification: 24 focused import, report, notification, SMTP, authentication,
  and repository tests pass; authoritative OpenAPI validation and compilation
  pass.
- Next: complete Phase 2 audit/log review and boundary tests. Import and cleanup
  completion events belong to the later execution/lifecycle phases.

### 2026-08-04 — Phase 2 sequential worker queue and validation outcome

- Status: Phase 2 remains `IN PROGRESS`; the single-worker queue from the lean
  architecture is now implemented in the API-owned job model.
- Queue: atomically claim one `VALIDATE`, `IMPORT`, or `CLEANUP` task globally;
  reject a second claim while any lease is active; allow expired-lease reclaim;
  and renew leases only for the matching worker and state version. Claiming
  increments the optimistic version, while heartbeat renewal does not.
- Validation: bind READY/INVALID/FAILED results to the active VALIDATE claim,
  event UUID, result digest, report/manifest hashes, and current state version.
  Identical replay succeeds and conflicting replay fails. READY requires a
  complete error-free inventory and retains payload for seven days; INVALID and
  FAILED require prior payload deletion.
- Quota: reconcile the conservative reservation to actual extracted original
  bytes for READY, and release it for INVALID/FAILED. A result cannot exceed the
  reservation derived from the accepted compressed size and 50:1 aggregate
  ratio.
- Verification: 17 focused import/authentication/repository tests, Python
  compilation, and authoritative OpenAPI validation pass.
- Next: add retained report retrieval, notification delivery state, and the
  remaining internal import/cleanup completion events.

### 2026-08-04 — Phase 2 quota vocabulary and SIP handoff

- Status: Phase 2 remains `IN PROGRESS`; direct media-to-API handoff is now
  represented without implementing the media upload endpoint from Phase 3.
- Ontology: Shared ontology 0.6.0 requires exactly one positive integer
  `shared:stagingQuotaBytes` on every `shared:StagingArea`; SHACL and OWL
  structural tests cover the contract.
- Security: add a dedicated `typ=import-service`, audience-bound internal JWT
  boundary with a signing key distinct from all user/upload/media/reset keys.
  Internal GraphDB access uses a dedicated service identity and does not issue
  or persist an OLDAP access token.
- Workflow: add idempotent `sip-stored` receipt validation and atomic
  `UPLOADING -> VALIDATING`, binding event UUID, upload request UUID, exact
  declared byte size, stored time, and lower-case SHA-256 to the job. Identical
  concurrent replay succeeds; conflicting replay returns a stable `409`.
- Verification: 12 focused OLDAP API tests, seven Shared ontology/archive
  structural tests, and authoritative OpenAPI validation pass.
- Next: implement single-worker claims/leases and validation-result publication,
  including actual extracted-byte quota reconciliation.

### 2026-08-04 — Phase 2 public ImportJob core

- Status: Phase 2 is `IN PROGRESS`; its public workflow core is implemented.
- Implementation: add immutable ImportJob lifecycle types, optimistic versions,
  GraphDB-backed canonical persistence, atomic staging-area quota reservation,
  ADMIN_CREATE plus effective DATA_UPDATE target authorization, purpose-specific
  direct-upload JWT capabilities, and authenticated create/list/read/reissue/
  cancel/confirm routes in `oldap-api`.
- Contract: merge the implemented public routes and schemas into the
  authoritative OLDAP OpenAPI file. Unauthorized cross-user job IDs remain
  indistinguishable from missing IDs, and capability responses are `no-store`.
- Verification: nine focused domain/HTTP/authentication-boundary tests, Python
  compilation, dependency locking, and authoritative OpenAPI validation pass.
- Next: define `shared:stagingQuotaBytes` in shared ontology/SHACL, then add the
  internal import-service identity, idempotent SIP/validation events, worker
  claims/leases, actual quota reconciliation, report access, and mail status.

### 2026-08-04 — Phase 1 completed

- Status: Phase 1 is `DONE`; all exit criteria and deliverables are satisfied.
- Implementation: extract typed legacy upload classification, typed ffprobe
  audio facts, bounded PDF structure facts, and reusable libvips/FFmpeg/Poppler
  derivative orchestration from Flask. Add frozen typed ZIP/worker policies and
  a schema-drift test. Keep request routing, stored layouts, derivatives,
  metadata, cleanup, and response semantics compatible.
- Architecture: request MIME/filename classification is explicitly untrusted
  routing information; content-derived facts have separate types. Storage,
  inspection, and derivative modules import neither Flask nor OLDAP clients.
- Verification: all 51 unit/regression tests pass; module compilation,
  repository checks, and the production Docker build/import smoke test pass.
- Next: start Phase 2 only when requested; it introduces API-owned ImportJob
  persistence, transitions, authorization, quota reservation, and capabilities.

### 2026-08-04 — Phase 1 storage foundation and normal-upload checksums

- Status: Phase 1 is `IN PROGRESS`; the storage/configuration slice is complete,
  while typed content inspection and derivative extraction remain.
- Implementation: add side-effect-free environment settings; reusable path
  validation and exclusive asset reservation; unique per-operation workspaces;
  bounded bit-identical original copying with SHA-256; `shared:checksum` on the
  existing MediaObject; and additive `checksum` upload response/OpenAPI fields.
- Security: existing destinations are never replaced, partial copies are
  removed, symlink escapes remain blocked, temporary names cannot collide, and
  client multipart metadata cannot override the server-computed checksum.
- Verification: storage/config unit tests and all existing upload, asset,
  deletion, and deployment regressions pass (44 tests); the production
  Dockerfile builds and the new modules import inside the resulting image.
- Next: extract typed media inspection/probing and derivative generation from
  Flask request handling, add the ZIP-limit settings, and then close Phase 1.

### 2026-08-04 — Phase 0 completed

- Status: Phase 0 is `DONE`; all exit criteria and deliverables are satisfied.
- Decisions: confirm the exact audio, video, strict-text, empty/archive, and
  4-vCPU/6-GiB worker policies. Deliberately defer only the exact staging-area
  quota ontology property to Phase 2 and the Defender/integrated-scanner
  decision to Phase 4, with named owners and required timing before a pilot.
- Verification: schemas and READY/INVALID examples, both OpenAPI 3.1 contracts,
  threat model, and fixture catalogue are mutually aligned and validated.
- Next: start Phase 1 only when requested; no ZIP-import runtime code exists yet.

### 2026-08-04 — Threat model and safe fixture catalogue v1

- Status: the Phase 0 threat model/test-catalogue deliverable is complete;
  several explicitly listed policy/operations choices remain before Phase 0 can
  be marked DONE.
- Decisions: use cgroups rather than thread count as the resource boundary;
  process one job and one entry sequentially; cap CPU at 4 vCPUs; generate small
  hostile ZIPs deterministically; separate default, integration, scaled, and
  operator-only test tiers; never store real malware or huge expanded fixtures.
- Coverage: 24 threat classes and accepted, malformed ZIP, path/name, bomb,
  content/codec, authorization, race, crash, commit, cleanup, malware, and
  capacity scenarios are mapped to expected controls/results.
- Next: confirm 6-GiB RAM, empty/artifacts-only ZIP handling, precise audio
  bit-depth/sample-rate rules, structured-text treatment, malware deferral, and
  the staging-area quota ontology property.

### 2026-08-04 — Public and internal OpenAPI contracts v1

- Status: the Phase 0 API/state-machine contract deliverable and D-018 are
  complete; Phase 0 remains in progress for threat modelling and remaining
  operational decisions.
- Decisions: split API authority from direct media ingress; use purpose-specific
  credentials, optimistic public actions, idempotent internal events, renewable
  worker leases, immutable first-wins SIP PUT, API-proxied reports, and one
  transactional create-only staging commit. Cleanup failure never rewrites an
  `IMPORTED` result.
- Verification: both standalone OpenAPI 3.1 documents and all external schema
  references pass full specification validation.
- Next: complete the threat model/test-fixture catalogue, then resolve or
  deliberately defer quota ontology, worker RAM, Defender/malware scanning, and
  the remaining machine-level audio constraints.

### 2026-08-04 — Manifest and report JSON contracts v1

- Status: the Phase 0 manifest/report schema deliverable and D-017 are complete;
  Phase 0 remains in progress for API contracts and threat modelling.
- Decisions: use strict JSON Schema Draft 2020-12 contracts with shared v1 types,
  immutable validation manifests, bounded user reports, stable issue codes, and
  RFC 8785/SHA-256 report-to-manifest binding. Keep import results in a later
  separate receipt rather than mutating validation evidence.
- Verification: both schemas pass meta-schema checks; READY and INVALID manifest
  and report examples validate with format checking.
- Next: derive public/internal API and state-transition contracts from these
  documents, then complete the threat model and malicious-fixture catalogue.

### 2026-08-04 — Lean ZIP, size, audio, and authorization scope

- Status: the standard ZIP subset, final payload limits, audio channel ceiling,
  and authorization rule are decided; PDF/A profile confirmation remains open.
- Decisions: accept only single-disk stored/deflated non-ZIP64 archives; limit
  uploads to 500,000,000 bytes and extracted originals to 3,000,000,000 bytes;
  permit at most two audio channels; require user `ADMIN_CREATE` plus effective
  role `DATA_UPDATE` on the containing `shared:StagingArea`.
- Recommendation: accept only validated PDF/A-1 or PDF/A-2 and independently
  reject active content and every embedded file; PDF/A alone is not treated as
  a security sandbox.
- Next: obtain D-017 confirmation, then define versioned manifest/report and API
  contracts plus the bounded threat-fixture catalogue.

### 2026-08-04 — Target-root collision policy confirmed

- Status: D-004 is decided; no implementation work has started.
- Decisions: existing canonical-equivalent child folders and file/directory
  conflicts block the complete import. Existing media with the same canonical
  original name remain permitted and appear as explicit warnings because every
  imported medium receives an independent technical asset ID.
- Next: express both outcomes as stable machine-readable report codes in the
  Phase 0 report and manifest contracts.

### 2026-08-04 — Existing staging folder is the ZIP import root

- Status: Phase 0 target-root semantics are decided; implementation has not
  started.
- Decisions: every upload starts from a concrete existing
  `shared:StagingFolder`; no ZIP-name wrapper is created; ZIP-root files attach
  directly to that folder and ZIP-root directories become new children. The
  selected folder is excluded from the five-level ZIP depth limit.
- Collisions: existing canonical-equivalent child folders and file/directory
  conflicts block the all-or-nothing import. Same-named existing media are
  warnings because technical asset IDs remain independent and nothing is
  overwritten.
- Next: encode the immutable target-root IRI, authorization rechecks, collision
  preflight, and target snapshot in the API, manifest, and report contracts.
- Risks: the target hierarchy can change between validation and confirmation;
  the importer must recheck it before any filesystem or GraphDB side effects.

### 2026-08-04 — API email prerequisite verified

- Status: the production password-reset email path works and is suitable as the
  transport foundation for later import notifications.
- Verified: API mail uses the University of Basel SMTP relay with STARTTLS and
  no credentials on the media VM; focused URL, multipart, and SMTP diagnostic
  tests pass in `oldap-api`.
- Decisions: `api.oldap.org` exclusively owns SMTP delivery; ImportJob state is
  committed before mail is attempted; FasnachtsPage polling remains
  authoritative; email delivery state and retries remain independent.
- Next: during API import-job work, extract the password-reset-specific SMTP
  transport into a small reusable module and add four import templates.
- Risks: SMTP server acceptance does not guarantee inbox delivery, so import
  actions must never depend exclusively on receiving an email.

### 2026-08-04 — Phase 0 product and deployment decisions

- Status: Phase 0 in progress; most product and safety policies are decided.
- Completed: confirmed project-neutral scope, staging authorization direction,
  create-only attachment below an existing target folder, `shared:StagingFolder`
  directory mapping, all-or-nothing import, restrictive media rules, lifecycle
  states and retention, provisional limits, and the production deployment
  envelope.
- Decisions: use one sequential ingest worker, existing GraphDB and ext4
  storage, no new database/broker, no resumable upload, polling UI, JSON reports,
  and no separate administration UI in the MVP.
- Next: define the quota property/API representation, exact authorization check,
  manifest/report schemas, service contracts, and threat-model fixtures.
- Open: verify Microsoft Defender coverage of Linux `/data` writes and choose
  the worker memory limit.
- Risks: storage is not encrypted at rest; daily backups must exclude temporary
  payloads where possible, and derivative expansion needs a physical admission
  guard beyond the user-facing extracted-byte quota.

### 2026-08-04 — Planning baseline

- Status: architecture discovery complete; implementation not started.
- Completed: documented the current synchronous Mediahelper upload, storage,
  authentication, media detection, OLDAP integration, staging ontology, and
  cleanup gaps.
- Decisions: retained the agreed API/media-server responsibility split and
  consolidated the work into seven implementation phases.
- Next: resolve the Phase 1 decision register and approve manifest, report,
  state-machine, limit, and codec contracts.
- Risks: the currently agreed lifecycle lacks a distinct operational failure
  state; exact limits and codec rules are not yet defined.
