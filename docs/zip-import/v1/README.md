# ZIP Import JSON Contracts v1

## Purpose

These Draft 2020-12 JSON Schemas freeze the Phase 0 data contract between the
validator, `oldap-api`, FasnachtsPage, the importer, and retained audit records:

- `manifest.schema.json` is the exhaustive, bounded technical validation record.
- `report.schema.json` is the protected user-facing projection.
- `common.schema.json` is the single source for shared limits, target snapshots,
  content probe facts, validation summaries, and stable issue codes.

The example documents are contract fixtures, not production payloads.

`THREAT_MODEL.md` records attacks and residual risks,
`TEST_ZIP_CATALOG.md` defines fixture and execution tiers, and
`PHASE6_TEST_MATRIX.md` maps lifecycle, concurrency, quota, crash, retry, and
cleanup invariants to executable cross-repository evidence.
`OPERATIONS_RUNBOOK.md` is the deployment, backup/restore, retention, incident
response, recovery, and pre-pilot checklist for the media VM and API boundary.

The frozen policy snapshot includes the exact accepted audio sample rates and
bit depths, H.264/AAC profiles, and the stable `NO_IMPORTABLE_CONTENT` result
for empty or packaging-artifacts-only archives. Probe facts may still describe
invalid content outside those limits so that rejection evidence remains
representable.

## Versioning

`schemaVersion` uses semantic versioning independently from service versions.
Within major version 1, consumers must reject unknown properties because every
object is closed with `additionalProperties: false`. A backward-compatible new
optional field requires a minor schema version; removing, renaming, or changing
the meaning of a field requires a new major version and schema URL.

The retained document records both `schemaVersion` and the validator's
`policyVersion`. Revalidating an old SIP under a new policy creates a new import
job and new records; retained records are never silently reinterpreted.

## Manifest invariants

- The manifest is created only after bounded validation reaches `READY` or
  content-driven `INVALID`. Infrastructure failures may produce a report with
  `FAILED` but do not fabricate a complete manifest.
- Every inspected central-directory entry appears at most once and is identified
  by `entryIndex`.
- `inventoryComplete` is `true` only when the complete archive inventory was
  safely read. For a hostile archive that exceeds a hard scan bound, the report
  remains bounded, `inventoryComplete` is `false`, and a blocking aggregate issue
  explains why further entries were not enumerated.
- `sourcePath` preserves the decoded source spelling. `sourcePathBytesBase64`
  preserves the exact filename bytes from the ZIP metadata. `normalizedPath` and
  resource names use Unicode NFC.
- Root-level files have `depth: 0`; the selected existing target folder never
  counts toward the five ZIP directory levels.
- `plannedResource` describes create-only OLDAP staging data. It never assigns a
  final resource IRI or asset ID during validation.
- The manifest never contains quarantine paths, host filesystem paths, bearer
  tokens, service credentials, or raw parser exception text.

## Report invariants

- The report is available only through an authenticated, authorized API request.
- `READY` requires a complete inventory, no blocking errors, `canConfirm: true`,
  and `expiresAt`.
- `INVALID` and `FAILED` require `canConfirm: false` and have no `expiresAt`.
- Stable issue `code` values drive application behavior. `messageKey` is resolved
  by the UI; the retained report does not duplicate translated prose.
- Entry names are shown because the report belongs to the uploading user, but
  email and operational logs contain only bounded summaries and protected links.

## Integrity and retention

For `READY` and `INVALID`, the report stores the SHA-256 of the RFC 8785 JSON
Canonicalization Scheme (JCS) representation of the exact retained manifest.
JSON object member order in the examples is illustrative. `FAILED` deliberately
has no manifest hash because an infrastructure failure may prevent a trustworthy
manifest from being completed.

The validation manifest is immutable. Import-time resource and asset mappings
belong in a separate versioned import receipt to be specified in Phase 5; they do
not mutate validation evidence after user confirmation.
