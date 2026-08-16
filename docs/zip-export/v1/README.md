# Project-neutral ZIP export media contract v1

## Implementation status

The source resolver, sequential BUILD/CLEANUP worker, private atomic artifact
store, exact download-capability verifier, Caddy GET/HEAD route, container
mounts, and Ansible configuration are implemented. The production worker
profile deliberately defaults to disabled until distinct export-service and
export-download secrets have been provisioned. A deployed real-size and HTTP
Range exercise remains an operational acceptance gate.

This contract adds an export artifact boundary without changing normal upload,
derivative, IIIF, or `/asset/<assetId>` delivery behavior.

## Placement

`oldap-api` owns jobs, authorization, manifests, leases, notification, audit,
and download-capability issuance. A separate project-neutral export worker runs
beside the media volume. It mounts media originals read-only and a dedicated
export root read-write. It never receives an OLDAP user token, GraphDB
credential, project profile, or ontology query capability.

The worker receives an already projected canonical manifest plus its SHA-256.
It validates every storage and ZIP path again, reads originals, verifies or
calculates SHA-256, streams one Zip64 archive, and atomically promotes the
finished artifact. Project-specific metadata is opaque scalar/array/object data
that the worker serializes according to the manifest schema.

Before manifest publication, oldap-api uses the dedicated internal batch
resolver to turn already authorized OLDAP media hints into confirmed original
facts. The resolver treats `storagePathCandidate` as untrusted, validates the
asset ID and original name below the configured media root, and returns the
canonical worker-relative path, byte size, MIME type, and SHA-256. This avoids
trusting `shared:path` in the API and avoids one HEAD request per media object.
The implemented route accepts 1 to 1,000 unique assets, rejects traversal and
every symlink below the trusted root, opens originals without following the
final component, and verifies that identity, size, and modification time remain
stable while hashing. Signature-based MIME detection covers the supported
media formats and falls back conservatively to filename inference.

The route is protected by a short-lived (at most two minutes)
`typ=export-source-resolver`, `aud=oldap-media-export-service` JWT whose subject
must be `oldap-api`. `OLDAP_EXPORT_SERVICE_JWT_SECRET` is delivered only to the
mediahelper and must differ from every access, media, import, and export
download key. Caddy exposes only the exact POST path and caps its request body
at 10 MB; other internal paths remain closed.

## Storage

```text
<OLDAP_EXPORT_ROOT>/
  .part-<exportId>-<random>/archive.zip
  <exportId>/
    archive.zip
    result.json
```

The worker alone writes and removes this root. Caddy mounts it read-only. The
normal mediahelper resolves only the exact finalized `archive.zip` after
validating an `export-download` capability. It must never accept a path from a
token or request parameter.

## Capability

- JWT `typ`: `export-download`
- audience: `oldap-media-export-download`
- required claims: `sub`, `exportId`, `jti`, `iat`, `exp`, `iss`, `aud`
- dedicated secret: `OLDAP_EXPORT_DOWNLOAD_JWT_SECRET`
- suggested TTL: five minutes

The secret must differ from access, refresh, normal media, import upload,
import service, and import-record secrets. Caddy exposes only GET and HEAD for
the exact UUID route. Mediahelper returns an internal fixed path only after
capability validation. Caddy provides `Content-Disposition: attachment`,
content length, `Accept-Ranges`, and range responses.

## Lifecycle

The API-controlled worker claims `BUILD` and `CLEANUP` tasks with renewable
leases. BUILD success reports archive byte count, SHA-256, manifest SHA-256,
completion time, and durable-finalization proof. Cleanup deletes only the
canonical export-ID directory after a matching API claim and reports deletion
proof before the API marks the job `DELETED`.

The normal exception path removes its active partial directory immediately.
Lease loss is checked between streamed copy chunks, so cancellation and worker
replacement stop without publishing an archive. A later successful idempotent
retry also removes UUID-scoped partial siblings left by a hard process or
container interruption. Final UUID directories are never age-deleted
independently of an API cleanup claim. All operations preserve the configured
physical free-space reserve.

## Approved bounds

- produced ZIP: manifest-selected deployment limit, never above the immutable
  50,000,000,000-byte v1 safety ceiling;
- READY and audit retention: deployment-selected and enforced by oldap-api
  (defaults 24 hours and 60 days);
- active-job and retained-byte quotas: atomically reserved by oldap-api for
  each user and system-wide;
- one sequential export worker for the pilot;
- Zip64 required where normal ZIP limits would be exceeded;
- no automatic multipart output.

The same worker, route, storage layout, and credential purpose serve every
OLDAP project. No project short name or ontology IRI affects media-side
authorization or filesystem routing.
