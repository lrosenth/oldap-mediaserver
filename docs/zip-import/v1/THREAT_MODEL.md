# Secure ZIP Import Threat Model v1

## Scope and security objective

This model covers one authenticated user's ZIP submission from FasnachtsPage
through direct media ingress, quarantine, validation, confirmation, final asset
promotion, atomic OLDAP staging commit, reporting, and cleanup.

The primary objective is to accept only the agreed content while preserving host
and OLDAP integrity, bounding resource consumption, preventing cross-project
access, and making every accepted or rejected result auditable without retaining
unsafe payloads longer than required.

This is a defensive design and test plan. It does not authorize storing real
malware, publishing internal endpoints, or running destructive capacity tests on
production.

## Assets to protect

- final media assets under `/data/images`;
- quarantined SIPs and extracted work data under `/data/ingest`;
- retained manifests, reports, checksums, and later import receipts;
- OLDAP staging resources, hierarchy, roles, permissions, and quota state;
- API, upload-capability, import-service, and record-service credentials;
- media VM availability, disk capacity, CPU, RAM, process table, and backup;
- original names, submitter identity, report contents, and audit history;
- integrity of the existing synchronous single-file upload workflow.

## Actors and assumptions

- An authenticated user may intentionally submit hostile data and may know valid
  project, staging-area, and folder IRIs from resources they can see.
- An attacker may obtain one short-lived upload capability but not the user's
  OLDAP access token.
- Every archive entry and every media parser input is untrusted, including
  metadata, declared sizes, filenames, checksums, codecs, and duration.
- Media libraries and external parser processes can contain exploitable bugs.
- The media VM, API VM, GraphDB, and university network are operationally
  trusted but may fail, restart, run out of resources, or deliver events twice.
- TLS is correctly terminated for public and internal traffic. TLS compromise
  and a fully compromised host kernel are outside this model.

## Trust boundaries

1. Browser to public OLDAP API: user authentication and authorization boundary.
2. Browser to media ingress: short-lived single-job capability boundary.
3. Public proxy to the single retained-report route: exact path/method allowlist
   plus an import-scoped records JWT; all other internal routes remain unrouted.
4. Quarantine to parser subprocesses: hostile-content execution boundary.
5. Quarantine/work storage to final media storage: confirmation and promotion
   boundary.
6. Worker to API internal operations: service identity, claim, version, and
   idempotency boundary.
7. Media filesystem to GraphDB staging commit: cross-system consistency boundary.
8. Retained report to UI/email/logging: personal-data and injection boundary.

## Resource and concurrency profile

The security boundary is the container cgroup, not a Python or Java thread count.
The confirmed lean profile is:

- one validation/import job globally;
- archive entries extracted and inspected sequentially;
- at most one expensive parser/derivative subprocess at a time;
- worker container hard limit of 4 vCPUs;
- worker memory limit of 6 GiB on the 16-GiB VM;
- memory-plus-swap limit equal to the memory limit where supported, so the worker
  cannot turn a memory attack into uncontrolled host swapping;
- PID limit of 128, plus bounded file descriptors, child-process output,
  temporary space, and six-hour job wall time;
- FFmpeg codec/filter threads explicitly set to 1 for untrusted probes and
  transformations unless a measured operation requires 2;
- libvips worker pool capped at 2; Java/PDF validation gets a bounded heap and
  an effective processor count of at most 2;
- total CPU remains capped at 4 even if a library creates additional helper or
  garbage-collector threads.

Four simultaneous file inspections are deliberately not used in the MVP. They
would multiply peak memory and parser exposure for little benefit when one job
may take time. Docker documents that containers have no CPU/RAM limits unless
configured; therefore Compose/cgroup limits are mandatory, not optimization.

## Risk scale

- `P0`: could escape quarantine, overwrite/cross authorization boundaries,
  corrupt committed data, disclose credentials, or take down the VM.
- `P1`: bounded denial of service, lifecycle inconsistency, orphan data, or loss
  of audit integrity.
- `P2`: misleading reporting, privacy leakage, operational confusion, or a
  defense-in-depth gap with a bounded primary control.

No `P0` test may be waived for MVP release.

## Threat register

| ID | Priority | Threat and attack | Required controls | Verification | Residual risk |
| --- | --- | --- | --- | --- | --- |
| TM-01 | P0 | IDOR/cross-project job, target, report, confirmation, or commit | API checks job visibility, `ADMIN_CREATE`, effective staging-area `DATA_UPDATE`, and target membership at create/read/confirm/commit; unauthorized IDs do not reveal existence | AUTH group | Compromised legitimate role remains trusted until revoked; confirm/commit recheck bounds this |
| TM-02 | P0 | Stolen, replayed, wrong-audience, or wrong-job upload capability | Short expiry; exact `typ`, issuer, audience, importId, subject, `maxBytes`, jti; immutable first-wins PUT; never accepted elsewhere | CAP group | Stolen token can submit one SIP before expiry; user can cancel and audit identifies subject/jti |
| TM-03 | P0 | Public access to worker, record, claim, commit, or unrelated internal routes | Caddy routes only exact GET `/internal/imports/{UUID}/records/report`; import-scoped records JWT; every other `/internal` route unrouted; public/access/upload tokens rejected | AUTH-INT group | The report handler is network-reachable and depends on the isolated records secret plus TLS; deployment tests enforce the narrow allowlist |
| TM-04 | P0 | Content-Length omission/lie, chunked oversize body, interrupted upload, disk-fill during ingress | Require known length but enforce actual streamed bytes independently; random `.part`; per-job directory; physical reserve; fsync/atomic rename; every 60 seconds remove at most 100 recognizable non-symlink partial directories older than 24 hours; never age-delete a finalized UUID directory | UPLOAD group | Abrupt host/storage failure can leave a bounded orphan `.part` for up to 24 hours; finalized job cleanup remains API-claim-owned |
| TM-05 | P0 | ZIP Slip through `..`, absolute, drive, UNC, mixed separators, NUL, or path normalization | Reject before filesystem access; treat slash and backslash as separators for validation; construct destination from validated segments; verify resolved parent containment; never use `extractall()` | PATH group | Parser/library normalization differences; test Linux and portable Windows semantics |
| TM-06 | P0 | Symlink, hard-link representation, FIFO, device, socket, or permission metadata reaches filesystem | Accept regular files/directories only; inspect creator OS/external attributes and extra fields; create files with safe fixed modes and no link following | TYPE group | Unknown vendor-specific metadata; unknown/suspicious types reject the SIP |
| TM-07 | P0 | Per-entry, aggregate, recursive, count, or metadata decompression bomb | Stored/deflate only; no nested archives; central-directory preflight; streamed actual-byte counters; per-file and aggregate ratios; 10,000 entries; 3-GB total; physical reserve; stop early | BOMB group | Highly compressible allowed data may be rejected; accepted MVP tradeoff |
| TM-08 | P0 | Malformed/truncated ZIP, CRC failure, inconsistent local/central headers, overlapping entries, forged size, data-descriptor ambiguity, self-extracting preamble | Strict single-disk non-ZIP64 parser policy; cross-check headers, offsets, bounds, CRC and actual bytes; no repair mode; any ambiguity rejects all | ZIP-MALFORMED group | ZIP parser defects remain; parser runs inside bounded worker and corpus is regression-tested |
| TM-09 | P0 | Unicode, NFC, case-folding, reserved-name, control-character, duplicate-path, or file/directory collision creates ambiguous/overwriting hierarchy | Preserve raw bytes; require ASCII or unambiguous UTF-8; NFC canonicalization; portable collision keys; fixed segment/path limits; create-only target preflight and commit recheck | NAME group | Human-confusable characters are reported but not all can be safely blocked without harming legitimate names |
| TM-10 | P0 | Extension/MIME spoofing, polyglots, or parser disagreement causes unsafe handler selection | Content-first detection; extension only warning; independent container/codec probe; allowlist exact; nested/archive signatures reject; disagreement blocks | CONTENT-SPOOF group | Sophisticated polyglots can fool detectors; use multiple facts and never execute content |
| TM-11 | P0 | Exploit in libjpeg/libtiff/libpng/libvips/libheif/FFmpeg/Poppler/veraPDF or MIME detector | Minimal runtime packages/loaders; no ImageMagick fallback; fixed UID/GID 65532 with zero capabilities; closed environment; no client/claim/token argument; seccomp-denied network; job-only workspace; no shell; time/RAM/PID/CPU/output limits; patch cadence | PARSER group, no-secret child test, Linux UID/capability/seccomp/runtime checks | A kernel/container escape remains possible; parser dependencies still require prompt security updates |
| TM-12 | P0 | Pixel, frame, stream, metadata, font, page, duration, or codec complexity bomb | Inspect headers before full decode; 100 MP/30k axis; one video stream, 0/1 audio; 4K/60fps/2h; no subtitles/attachments; per-tool timeout and memory; bounded preview | MEDIA-LIMIT group | Malformed inputs may allocate before facts are available; subprocess/cgroup limits terminate them |
| TM-13 | P0 | Encrypted or active PDF, embedded payload, unsafe action, invalid PDF/A claim | veraPDF validates PDF/A-1/2; reject PDF/A-3/4, encryption, JS, Launch, rich media, and every embedded file; bounded Poppler preview after validation | PDF group | PDF/A is not malware detection and validator/renderer bugs remain contained as TM-11 |
| TM-14 | P0 | Quota race or physical disk exhaustion through multiple jobs, derivatives, retained records, or backup | API atomic reservation; conservative reservation formula; actual reconciliation; one worker job; separate physical reserve including derivative/compensation headroom; disk check before each phase | QUOTA group | Growth estimate uncertain; alerts and operator capacity procedure required before pilot |
| TM-15 | P0 | TOCTOU: target moved/deleted, role revoked, new folder collision, READY expiry during confirmation/import | Immutable target IRI; stateVersion CAS; recheck auth, membership, existence, expiry, quota, and collisions at confirm and commit; no side effects before final preflight | RACE group | Target metadata may change after commit; created resources remain auditable and are not overwritten |
| TM-16 | P0 | Crash between asset promotion and GraphDB commit leaves orphans or partial hierarchy | Exclusive job-owned asset directories; checksum verification; one GraphDB batch transaction; IMPORTED only after commit; compensation deletes only job-owned assets; idempotent event/commit | COMMIT group | Filesystem and GraphDB cannot share a native transaction; reconciliation window remains but must never expose partial staging data |
| TM-17 | P0 | Expiry/cancel cleanup races with import or deletes unrelated data | API-owned cleanup claims; exact importId ownership markers; explicit roots; no age-only deletion; IMPORTING ineligible; post-delete containment check; idempotent result | CLEANUP group | Operator manual deletion remains outside automation and needs runbook safeguards |
| TM-18 | P1 | Duplicate/out-of-order events, expired lease, two workers, stale state overwrites newer result | Atomic claims, renewable leases, expected stateVersion, immutable eventId payload, conflict on changed replay, original response on identical replay | EVENT group | Long partitions delay progress; correctness preferred over availability |
| TM-19 | P1 | Filenames inject HTML, logs, email headers, terminal controls, or leak sensitive names | JSON encoding; UI text rendering, not HTML; reject controls; bounded fields; no filenames in normal logs/email; authenticated report link; structured error codes; redact tokens | REPORT group | Authorized user sees their submitted names by design |
| TM-20 | P1 | Quarantine data survives retention or enters daily backup | Immediate invalid cleanup; READY seven days; cleanup/reconciliation; separate ingest path; backup exclusion where possible; retained records contain no payload | RETENTION group | University backup behavior needs confirmation; encrypted-at-rest gap is an accepted current infrastructure risk |
| TM-21 | P1 | Allowed media carries malware not detected by structural/format validation | Explicitly state allowlist is not antivirus; confirm Defender coverage; optional scanner before READY; use EICAR only in controlled operator test; never use real malware | MALWARE group | No scanner guarantees clean content; defense relies on non-execution, isolation, and safe delivery |
| TM-22 | P1 | Vulnerable or unexpectedly feature-rich dependency expands accepted attack surface | Pin versions/images; produce SBOM; remove unused loaders/codecs; security update procedure; regression corpus before upgrade; inspect effective libvips/FFmpeg build features | SUPPLY group | OS/vendor packages may lag; critical parser CVEs can temporarily disable affected type |
| TM-23 | P0 | Parser compromise reads service token or exfiltrates over network | API client and claim remain parent-only; child environment scrubbed before parsing; different fixed UID/GID with zero capabilities; no-new-privileges; libseccomp denies socket/network syscalls for child and descendants; SIP access revoked after exit; service token remains import-only | SANDBOX group plus unpicklable-client, secret-environment, capability, network-denial, and low-privilege extraction checks | Same-container kernel boundary is weaker than a separate VM; split parser service only if pilot evidence or future risk requires it |
| TM-24 | P1 | One deliberately slow job starves the global queue for six hours repeatedly | Per-file/per-tool deadlines; spawned analysis process group killed by the parent at the fixed total wall time; FAILED cleanup/report; fair job ordering, per-user active-job limit, cancellation before validation, audit/rate controls | DOS group plus timeout cleanup/replay tests | Authorized user can consume their bounded share; initial low volume makes one global worker acceptable |

## Fixture and test policy

The companion `TEST_ZIP_CATALOG.md` defines safe fixture tiers and expected
stable issue codes. Key rules are:

- generate structural ZIP attacks deterministically in temporary directories;
- never extract test archives with generic command-line tools merely to inspect
  them;
- store only tiny, non-executable, provenance-documented media fixtures;
- test production-size limits with reduced injected limits in normal CI;
- run actual capacity, EICAR, crash, and backup tests only in a disposable,
  explicitly approved operator environment;
- never download, store, or execute real malware.

## Security references

- [Python `zipfile` security and decompression pitfalls](https://docs.python.org/3/library/zipfile.html)
- [MITRE CWE-409: highly compressed data amplification](https://cwe.mitre.org/data/definitions/409.html)
- [OWASP malicious upload and archive traversal testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files)
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [FFmpeg thread/filter controls](https://www.ffmpeg.org/ffmpeg.html)
- [libvips concurrency control](https://libvips.github.io/ruby-vips/Vips.html)
- [veraPDF validation profiles](https://docs.verapdf.org/cli/validation/)
- [EICAR antivirus test-file handling](https://www.eicar.org/download-anti-malware-testfile/)
