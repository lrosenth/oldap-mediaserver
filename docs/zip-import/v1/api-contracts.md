# ZIP Import API Contracts v1

## Contract files

- `oldap-api.openapi.yaml` defines public ImportJob operations and internal
  worker/media operations owned by `api.oldap.org`.
- `media-ingest.openapi.yaml` defines direct immutable SIP upload and internal
  retained-record reads owned by `media.oldap.org`.
- `manifest.schema.json` and `report.schema.json` remain the source contracts
  for validation records referenced by both OpenAPI documents.

These are Phase 0 contracts. They do not add deployed routes. During Phases 2
and 3, the agreed operations are merged into the repositories' authoritative
OpenAPI files together with their implementations and contract tests.

## Trust boundaries

| Credential | Accepted by | Purpose |
| --- | --- | --- |
| OLDAP access JWT | Public `api.oldap.org` import operations | User identity, `ADMIN_CREATE`, visibility, and staging authorization |
| Upload capability JWT | `PUT media.oldap.org/imports/{importId}/sip` only | One import, one immutable SIP, short expiry, maximum bytes |
| Import service token | Internal `api.oldap.org` import operations only | Media notification, worker claims, validation results, commit, cleanup |
| Import records token | Exact retained-report operation on `media.oldap.org` | API retrieval of the immutable validation report |

Tokens are purpose-specific and never accepted across rows. Caddy routes only
the exact GET report operation from the media internal surface; all worker,
claim, result, commit, cleanup, manifest, and other `/internal` operations stay
unrouted. Tokens, service exception text, and host filesystem paths never appear
in ImportJobs, manifests, reports, email, or normal structured logs.

## Public workflow

1. FasnachtsPage calls `POST /imports` with the project, containing staging area,
   selected target-root folder, ZIP filename, and browser-known byte size.
2. The API checks the user has `ADMIN_CREATE`, their effective role permission
   on the `shared:StagingArea` is at least `DATA_UPDATE`, the target folder
   belongs to that area, quota is reservable, and physical admission is open.
3. The response contains the authoritative `ImportJob` and a short-lived upload
   capability. Capability responses use `Cache-Control: no-store`.
4. The browser streams `application/zip` directly to the capability URL.
5. FasnachtsPage polls `GET /imports/{importId}`. Email is supplementary only.
6. `GET /imports/{importId}/report` is authorized and proxied by the API; the
   browser never receives the internal records token.
7. Confirmation and cancellation contain `expectedStateVersion`. A stale UI gets
   `409` and must refresh rather than repeating an action against changed state.

The upload token is returned only by create/reissue responses and never by job
list/read responses. Reissue is allowed only while the job is `UPLOADING` and no
finalized SIP exists.

## State transition contract

| Current | Trigger | Next | Required preconditions |
| --- | --- | --- | --- |
| none | public create | `UPLOADING` | authorization, target membership, quota reservation, physical admission |
| `UPLOADING` | idempotent `sip-stored` event | `VALIDATING` | immutable receipt matches job, size limit and capability |
| `VALIDATING` | validation READY result | `READY` | complete inventory, immutable manifest/report, no blocking issue, payload retained, actual quota reconciled |
| `VALIDATING` | validation INVALID result | `INVALID` | manifest/report retained, temporary payload already deleted |
| `VALIDATING` | validation infrastructure failure | `FAILED` | bounded FAILED report retained, temporary payload already deleted, no fabricated manifest |
| `READY` | public confirmation | `IMPORTING` | stateVersion, not expired, authorization, target membership/existence, collision and quota recheck |
| expired `READY` | successful cleanup | `EXPIRED` | confirmation already blocked by `expiresAt`, temporary payload deleted |
| `UPLOADING` or `READY` | public cancellation | `CANCELLED` | stateVersion; cleanup is queued and visible through `cleanupPending` |
| `IMPORTING` | atomic batch commit | `IMPORTED` | active claim, matching manifest, verified assets, fresh target/collision checks, one GraphDB transaction |
| `IMPORTING` | import failure | `FAILED` | promoted assets compensated and temporary payload deleted |

`VALIDATING` and `IMPORTING` do not accept cancellation. Terminal states do not
transition to another lifecycle state. Cleanup after `IMPORTED` or `CANCELLED`
only clears `cleanupPending`; it never changes the terminal result. A cleanup
failure is retried without changing `IMPORTED` or `CANCELLED` to `FAILED`.

The report's `status` is the validation outcome, not the current job state. An
`IMPORTED` job therefore continues to expose its immutable READY report.

## Quota and physical admission

At job creation, the API reserves a conservative upper bound:

```text
min(3,000,000,000, declaredCompressedSizeBytes * 50)
```

After validation it replaces that reservation with actual extracted original
bytes. READY jobs retain the reservation until import, cancellation, invalidity,
or expiry releases/reclassifies it. Physical free-space admission is a separate
guard and may account for ZIP, extracted work, derivatives, compensation room,
and the configured free-volume reserve.

## Worker claims and leases

The single ingest worker polls `POST /internal/import-claims` for `VALIDATE`,
`IMPORT`, or `CLEANUP`. The API selects and leases one eligible task atomically.
Leases are short and renewable; a long validation heartbeats rather than owning
an unbounded lock. An expired lease can be reclaimed only after the API verifies
that no newer result/event was accepted.

Cleanup selection is API-owned and never uses filesystem age as authority.
`IMPORTING` is categorically ineligible for cleanup.

Abandoned ingress work is narrower than job cleanup. Mediahelper may remove
only a recognizable non-symlink `.part-<importId>-*` directory older than 24
hours, bounded to 100 removals per pass. It must never apply age rules to a
finalized `<importId>` directory. An `UPLOADING` job becomes stale after 24
hours, but its state, quota release, and any finalized payload cleanup remain an
API-owned compare-and-set cleanup claim/result implemented with lifecycle
operations rather than the media filesystem scan.

A VALIDATE claim also carries the immutable job creation time, requester IRI,
original ZIP filename, actual compressed byte count, SIP SHA-256, and complete
target snapshot. These are manifest evidence inputs; the worker neither looks
them up with a user credential nor invents them from local filenames.

The sequential worker runs parser-heavy file analysis in one spawned Unix
process group. The API client, claim, target preflight, evidence projection,
record retention, and result publication remain exclusively in the trusted
parent. Before parsing, the child clears its inherited environment, drops to
fixed UID/GID 65532 with no supplementary groups or capabilities, and installs
an inherited no-new-privileges seccomp filter that denies network socket
syscalls for it and decoder descendants. It can read its temporarily exposed
SIP and write only one job-local workspace; the parent revokes that access when
the child exits and atomically promotes only READY extraction.

The parent keeps the lease heartbeat and enforces the frozen six-hour monotonic
wall-clock limit across checksum verification, child analysis, bounded API
preflight, and document projection. At timeout it kills the complete group,
retains a bounded `VALIDATION_TIMEOUT` FAILED report without a manifest, deletes
all temporary payload, and only then publishes the failure. The retained report
and result metadata are create-only so an interrupted API call replays the exact
same evidence. This deadline is a resource-safety terminal outcome; ordinary
unexpected worker/service faults remain retryable and do not silently become
content INVALID.

After structural/content validation, the worker derives the ZIP's explicit and
implicit top-level children and calls the claim-bound
`POST /internal/import-claims/{claimId}/target-preflight` operation. The API
reads the selected folder and its direct `shared:inStagingFolder` children with
its dedicated GraphDB service connection. It applies the same NFC, trailing
dot/space, and case-folded portable key as ZIP validation and returns only:

- blocking `TARGET_CHANGED` when the current area/folder snapshot differs;
- blocking `TARGET_FOLDER_COLLISION` whenever either side is a folder; or
- warning `TARGET_MEDIA_NAME_COLLISION` for media/media name equivalence.

The worker receives no user token or general graph-query capability. This
validation-time result remains advisory for race safety: confirmation and the
Phase 5 atomic commit must recheck target identity, authorization, and
collisions because children can change after READY.

## Idempotency and conflict handling

- The SIP location is immutable. The first finalized PUT wins; later PUTs return
  the persisted receipt and never append, replace, or create another SIP.
- Every internal notification/result carries a UUID `eventId`. Replaying the
  identical event returns the original successful result. Reusing an `eventId`
  with different content returns `409`.
- Worker results bind to `claimId` and `expectedStateVersion`.
- Batch commit binds to the immutable manifest SHA-256 and is replay-safe.
- Exclusive final asset-directory creation remains mandatory even after API
  collision checks; neither layer treats a prior path as overwrite permission.

## Batch commit boundary

The worker prepares originals and derivatives and sends only normalized relative
paths, checksums, technical asset IDs, and OLDAP media facts. It never sends an
OLDAP user token or absolute filesystem path. The API:

- verifies all entries against the retained manifest;
- resolves the selected target root and `shared:stagingDefaultRole` itself;
- creates top-level ZIP files directly in the selected root;
- creates ZIP directories as new `shared:StagingFolder` descendants;
- creates all `shared:StagingMediaObject` resources and mappings in one GraphDB
  transaction;
- marks the ImportJob `IMPORTED` in the same durable commit boundary where
  supported by the selected GraphDB model.

If the transaction fails, no staging resources are committed. The worker removes
only final assets owned by that job before reporting an import failure.

## Stable HTTP/API errors

All errors use `{code, message, requestId, details?}`. Application behavior uses
`code`; `message` is bounded diagnostic prose. Expected stable codes include:

- `IMPORT_STATE_CONFLICT`, `IMPORT_VERSION_CONFLICT`, `IMPORT_CLAIM_CONFLICT`
- `IMPORT_TARGET_NOT_FOUND`, `IMPORT_TARGET_CHANGED`, `IMPORT_TARGET_COLLISION`
- `IMPORT_QUOTA_EXCEEDED`, `IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT`
- `IMPORT_PERMISSION_DENIED`, `IMPORT_REPORT_NOT_READY`
- `UPLOAD_CAPABILITY_INVALID`, `UPLOAD_ALREADY_FINALIZED`, `UPLOAD_SIZE_LIMIT`

Authentication failures do not reveal whether an unauthorized import ID exists.
