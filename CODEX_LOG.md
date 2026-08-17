# CODEX_LOG

### Update 2026-08-17 23:12
- Decisions: Enable ZIP export only through an explicit production-host override while retaining the disabled shared default for unprepared future hosts.
- Implementation: Added the `dhlab-iii.dhlab.unibas.ch` host variables with one export worker enabled, covered the resolved production inventory with a regression assertion, and documented the production secret/account prerequisite and fail-closed default.
- Open: Verify the production export-service account is active and matches the shared Vault, then deploy API before media and run authenticated Staging plus Archive smoke tests.
- Risks/Assumptions: The shared encrypted Vault is assumed to contain the same distinct export secrets already accepted on home.org; no secret values are tracked.

### Update 2026-08-17 14:41
- Decisions: Publish the ZIP-export-capable mediahelper under a new immutable `v0.2.2` tag; do not rely on force-pulling the previously published `v0.2.1` tag on home.org.
- Implementation: Bumped `mediaserver/VERSION` to `0.2.2` after deployment diagnostics proved that home.org retained an older local `v0.2.1` image without `export_worker.py` because the playbook intentionally uses `pull: missing` for versioned tags.
- Open: Publish `v0.2.2` and rerun `make deploy-test`.
- Risks/Assumptions: Docker Hub `v0.2.1` was overwritten during the release attempt and must be treated as superseded; deployments should use `v0.2.2`.

### Update 2026-08-17 00:32
- Decisions: Activate the ZIP export worker only on the home acceptance environment; retain the production-safe disabled default until the production rollout is explicitly approved.
- Implementation: Enabled `zip_export_worker_enabled` in the `media.home.org` host variables and ignored local export/import runtime artifacts so release staging cannot include generated payloads.
- Open: Publish mediahelper v0.2.1, deploy both coordinated stacks to home.org, and complete authenticated end-to-end acceptance.
- Risks/Assumptions: The shared Vault now contains the two distinct export JWT secrets and the active export service credentials required by both deployments.

### Update 2026-08-16 23:44
- Decisions: Trust each canonical manifest's bounded deployment limit while retaining the media-side 50 GB hard ceiling; treat lease loss and hard-interruption leftovers as first-class restart cases.
- Implementation: Enforced the frozen limit during capacity admission and streamed ZIP writes, added chunk-level lease/cancellation checkpoints, removed active partials on failure and UUID-scoped leftovers after successful retry, documented local worker Compose inputs, and verified real HEAD plus two-part Range reconstruction with matching SHA-256. All 25 focused export/deployment/storage tests pass.
- Open: Rebuild the local image before exercising the new checkpoint behavior in containers; run representative production-scale throughput/resource measurement.
- Risks/Assumptions: A current winning lease may remove stale sibling workspaces after finalization; the single-concurrency worker and API lease ownership remain authoritative.

### Update 2026-08-16 00:07
- Decisions: Close media-side Archive export Phase 2 only after the real whole-archive artifact passes the same capability and cleanup boundary as the selected-unit artifact.
- Implementation: Built and served the live ARCHIVE_ALL ZIP with 20 archive directories, one original, README/export/archive-units/metadata support files, zero warnings, and an exact SHA-256 match. Caddy returned 401/200/200/206/405 for unauthenticated/GET/HEAD/Range/POST. API-claimed cleanup removed every artifact and invalidated the previously valid capability with 404.
- Open: Production secret provisioning/worker activation and representative capacity/performance measurements.
- Risks/Assumptions: Current live inventory is small; functional completion does not replace Phase-3 large-inventory measurement. Temporary acceptance secrets are not tracked and are removed after the run.

### Update 2026-08-15 23:58
- Decisions: Extend the worker's closed manifest envelope by export kind rather than loosening it generically. Use an outer exclusive Caddy handle for global route ordering and an inner route for immutable auth/header/rewrite ordering.
- Implementation: Added explicit STAGING_FOLDER/STAGING_ALL versus ARCHIVE_UNIT/ARCHIVE_ALL envelope validation with Archive-only `archiveUnits` tests. Fixed the previously unreachable Caddy export route and its internally reordered forward-auth chain in local and Ansible configs. Live ArchiveUnit acceptance now passes unauthorized 401, GET/HEAD 200, Range 206, POST 405, exact checksum/content, API-claimed deletion, zero remaining artifact files, and old-capability 404. All 29 focused export/deployment tests and Caddy validation pass.
- Open: Provision production export credentials and activate the worker profile; run representative capacity measurements. Successful whole-archive acceptance awaits correction of the API-owned unsafe source label.
- Risks/Assumptions: Caddy directive sorting is security-sensitive; deployment tests now require the nested handle/route shape. The test secrets were temporary and are not tracked.

### Update 2026-08-15 23:02
- Decisions: Keep Phase-2 archive semantics entirely in the API-owned manifest; the worker validates structural bindings and serializes common/opaque metadata without learning project ontologies.
- Implementation: Added Archive-kind-only `archiveUnits` manifest validation, exact unit/directory/media-container and parent binding, reserved root-name protection, and UTF-8 BOM RFC-4180 `archive-units.csv` generation with formula-safe existing CSV serialization. Added artifact coverage for metadata and single physical media output. All 28 focused export/deployment tests pass and changed files pass Black.
- Open: Consume manifests from the forthcoming requester-filtered API Archive reader, then perform a full physical Archive export acceptance after public runtime activation.
- Risks/Assumptions: `archive-units.csv` profile fields are treated as opaque validated scalar/list/map values. The media service deliberately cannot resolve labels or infer archive relationships.

### Update 2026-08-15 22:26
- Decisions: Preserve the original export request path through capability authentication and rewrite only after authorization; close Phase 1 on isolated physical acceptance while retaining production credentials and real-size capacity as operational work.
- Implementation: Changed both local and Ansible Caddy export delivery from sorted `handle` directives to ordered `route`, captured the export UUID explicitly, and authenticated against `/auth/exports/{uuid}/archive` before rewrite. Added deployment regressions. Built the current mediahelper image and verified unauthorized, GET, HEAD, Range, method guard, and post-cleanup denial through containerized mediahelper/Caddy; all 27 focused media/deployment tests and Caddy validation pass.
- Open: Provision production export service/download secrets, activate the worker profile, configure paired API SMTP, and measure representative holdings up to the configured limit.
- Risks/Assumptions: The accepted 32 MiB fixture proves streaming and byte-range behavior but not 50 GB throughput. A missing artifact can surface as fail-closed 409 rather than 404 under Docker Desktop bind-mount semantics; in both cases Caddy serves no bytes.

### Update 2026-08-15 00:02
- Decisions: Keep ZIP construction project-neutral and sequential, isolate BUILD control-plane and download credentials, mount originals read-only, and publish only atomically finalized immutable artifacts. Leave the production worker profile disabled until real purpose-specific secrets are provisioned.
- Implementation: Added strict export-service client/claims, canonical manifest verification, source-stability and checksum validation, Zip64 streaming, README/export/metadata CSV generation, atomic artifact evidence, claim-bound cleanup, exact download capability authorization, Caddy GET/HEAD delivery, Docker/Ansible wiring, and focused service/worker/storage/deployment tests.
- Open: Provision distinct production export-service/download secrets, activate the profile, run real-size and HTTP Range smoke tests, and complete API outbox/expiry plus frontend workflows.
- Risks/Assumptions: The 50 GB archive is streamed without staging source copies, but CSV inventory is retained in memory and representative production measurements remain required. Existing user changes to `mediaserver/VERSION`, `poetry.lock`, and `import-records/` remain untouched.

### Update 2026-08-14 22:47
- Decisions: Keep export source resolution as a small project-neutral mediahelper boundary. Treat all RDF path facts as untrusted, reject symlinks and non-canonical identities, hash originals through a no-follow descriptor, and expose only the exact POST route through Caddy.
- Implementation: Added purpose-specific service-JWT verification, closed 1–1,000 item request parsing, filesystem-authoritative original resolution, signature-first MIME detection, stable streaming size/SHA-256 calculation, Flask routing, 10 MB Caddy admission, container packaging, and deployment secret validation/wiring. Added 13 resolver checks and retained 4 deployment checks; all 17 focused checks and the full 151-test media suite pass, with one expected host skip.
- Open: Configure the same export-service secret in oldap-api deployment, activate the public export HTTP routes, and implement archive storage/download plus the export worker.
- Risks/Assumptions: Digest calculation is synchronous and intentionally favors immutable evidence over metadata trust; production-scale latency must be measured with real holdings. Existing user changes to `mediaserver/VERSION`, `poetry.lock`, and `import-records/` remain untouched.

### Update 2026-08-14 22:31
- Decisions: Add one project-neutral internal batch resolver because OLDAP RDF does not store original byte sizes and must not be treated as filesystem authority. Require a dedicated `export-source-resolver` JWT, at most 1,000 items, and exact asset/path/name validation below the media root.
- Implementation: Extended the validated media export OpenAPI and architecture documentation with `/internal/export-sources/resolve`, closed request/response schemas, canonical original path, MIME, size, and optional SHA-256 results. No application route was added yet.
- Open: Implement the resolver authentication and safe filesystem lookup, then add its deployment secret/configuration and focused tests before oldap-api enables export creation.
- Risks/Assumptions: This remains contract-only in oldap-mediaserver; existing upload, derivative, IIIF, asset, and import behavior is unchanged. Existing user changes to `mediaserver/VERSION`, `poetry.lock`, and `import-records/` remain untouched.

### Update 2026-08-14 12:36
- Decisions: Keep ZIP export additive and project-neutral. Run an ontology-blind worker beside the media volume, separate its export storage and credentials from normal assets/imports, and let oldap-api remain authoritative for jobs, manifests, leases, download capabilities, and cleanup claims.
- Implementation: Added the Phase-0 media architecture and a validated OpenAPI 3.1 contract for exact capability-protected GET/HEAD export delivery, including the fixed storage layout, purpose-specific JWT claims, 50 GB bound, atomic promotion, HTTP range expectation, and API-claimed cleanup rules.
- Open: Implement the export storage primitives, capability verifier, Caddy route, worker client/build loop against the now-defined API claim/manifest/result contract, deployment volumes/secrets, and tests.
- Risks/Assumptions: Documentation only in this repository; normal media routes and runtime deployment remain unchanged. Existing user changes to `mediaserver/VERSION`, `poetry.lock`, and `import-records/` were not touched.

### Update 2026-08-08 23:16
- Decisions: Start exactly one ZIP validation/import worker on every normal deployment; retain an explicit boolean maintenance switch instead of relying on a manual post-deploy profile command. Fail closed when the dedicated `/data` filesystem is not mounted.
- Implementation: Added `zip_import_worker_enabled: true`, passed the Compose profile through both deploy/status tasks, stopped the worker when explicitly disabled, asserted one running worker when enabled, added the `/data` mountpoint preflight, and synchronized tests and operations documentation.
- Open: Populate/verify the shared Vault, run the home-system deployment and authenticated ZIP smoke test, then execute the coordinated production window.
- Risks/Assumptions: Production deployment still requires an interactive sudo password on the media VM. The worker remains single-process and resource-limited; disabling it leaves queued jobs safely reclaimable after leases expire.

### Update 2026-08-07 01:29
- Decisions: Expose only the retained validation-report GET through Caddy so a separately running oldap-api can retrieve immutable evidence; retain the import-scoped records JWT as the application boundary and keep every other `/internal` operation unrouted.
- Implementation: Added the exact UUID-bound `/internal/imports/{importId}/records/report` GET proxy to local and Ansible Caddy configurations, strengthened deployment invariants, and synchronized architecture, API-contract, and threat-model documentation.
- Open: Deploy the rendered route with the next media-server release.
- Risks/Assumptions: The report endpoint is now network-reachable but accepts only a short-lived JWT scoped to one import ID. Claims, results, commit, cleanup, manifest, and broad `/internal` routing remain unavailable through Caddy. Seven focused deployment/record tests, compilation, whitespace checks, and Caddy validation pass; after local reload, the existing retained INVALID report was retrieved through Caddy with HTTP 200 and its expected digest.

### Update 2026-08-05 23:25
- Decisions: Use one operational runbook as the authoritative procedure across media, API, GraphDB, and frontend. Prefer stopping only the sequential worker during investigation; never infer lifecycle from filesystem age, reset GraphDB state manually, or reconcile assets by filename. Treat university daily backup as a 24-hour RPO until a different agreement exists.
- Implementation: Added deployment/rollback gates, authoritative storage and backup classification, ingest backup exclusion guidance, consistency and restore-drill procedures, implemented temporary-retention table, explicit 30-/90-day pruning gap, SEV incident playbooks, deterministic recovery order, and a pre-pilot checklist. Linked it from contract and Ansible documentation, refreshed the Compose profile comment, and marked the Phase 6 operations-documentation item complete.
- Open: Implement or explicitly accept API-owned 30-/90-day record pruning; confirm university backup exclusion, RTO, Defender and logging; add durable feature gating and conduct test/production pilots.
- Risks/Assumptions: GraphDB and ext4 backups are crash-consistent rather than atomically coordinated. Current automatic cleanup protects temporary payloads, while retained job/report records remain indefinitely until safe paired pruning exists. Whitespace checks, all three deployment-invariant tests, and the Ansible syntax check pass.

### Update 2026-08-05 23:12
- Decisions: Complete the automated Phase 6 matrix by reusing domain, filesystem, HTTP-contract, and frontend evidence rather than adding a parallel integration framework. Keep real production-size, destructive disk-pressure, native process-kill, backup/restore, deployed-browser, and conditional EICAR exercises operator-only.
- Implementation: Added cleanup recovery after deletion with lost API acknowledgement and a new claim; added deterministic retry after ambiguous import commit without compensation; documented the cross-repository lifecycle/concurrency/quota/crash/retry/cleanup evidence; marked the Phase 6 test-matrix item complete. oldap-api gained full happy-lifecycle and synchronized claim/confirmation race tests.
- Open: Document deployment/backup/retention/incident/recovery operations, add feature gating, and conduct test/production pilots.
- Risks/Assumptions: Automated end-to-end evidence composes service-level API authority with focused real filesystem and frontend contract tests; an authenticated deployed stack remains deliberately part of the pilot. All 137 media tests pass with one expected Linux-only skip and all 51 focused API tests pass; formatting and whitespace checks pass.

### Update 2026-08-05 23:08
- Decisions: Keep physical admission stateless and phase-local under the single-worker MVP. Preserve `max(20% of filesystem capacity, operator absolute reserve)` after each bounded write; keep API logical quota independent. Treat worker capacity pressure as retryable infrastructure state, never content INVALID.
- Implementation: Added shared free-space admission and phase estimates; enforced it before SIP storage, validation extraction, and confirmed asset preparation; added stable HTTP 507 `IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT`, privacy-safe structured capacity logs, replay-safe ingress behavior, Compose/Ansible configuration, contract/runbook documentation, and deterministic pressure tests. Marked the Phase 6 observability/disk-admission item complete.
- Open: Complete the broader end-to-end/failure matrix, deployment/backup/retention/incident/recovery runbooks, feature gating, and test/production pilots.
- Risks/Assumptions: Derivative space is deliberately an estimate (two times extracted originals); the mandatory 20% reserve supplies additional headroom. The one sequential worker removes intra-worker write races, but external media writes remain possible and are handled by checks repeated at each phase. All 135 tests pass with one expected Linux-only host skip; compilation and whitespace checks pass; the production image builds and imports the capacity guard.

### Update 2026-08-05 22:47
- Decisions: Count reconciliation only where identity and ownership are provable; do not introduce an age-based orphan/final-asset sweeper. Reuse durable callback receipts, expired leases, deterministic owner markers, import replay/compensation, and idempotent cleanup. Retry email only inside oldap-api during idle worker polls, at most three times with five-minute spacing.
- Implementation: Audited and documented the complete callback/workdir/promoted-asset/commit/cleanup recovery chain; added persisted notification last-attempt state, bounded API retry selection, and idle-poll triggering without exposing SMTP to media. Marked the Phase 6 reconciliation and email-retry work items complete.
- Open: Add physical disk-capacity admission, structured owner-visible operations, deployment/backup/incident runbooks, feature gating, and authenticated pilots.
- Risks/Assumptions: SMTP is bounded at-least-once; acceptance followed by an API persistence failure can duplicate a message. The deployment deliberately has one sequential ingest worker, so notification retry selection needs no second distributed mail lease in the lean MVP. All 50 focused API tests and 129 media tests pass with one expected Linux-only host skip.

### Update 2026-08-05 22:40
- Decisions: Start Phase 6 by completing the already-designed CLEANUP task on the existing global sequential worker. Keep finalized payload deletion API-selected and compare-and-set; never infer job expiry from media filesystem age. Preserve IMPORTED extracted-byte quota because staged originals remain allocated.
- Implementation: Added 24-hour UPLOADING and persisted-deadline READY selection, explicit IMPORTING/intermediate-state exclusion, strict cleanup claims/results, canonical ingest-only deletion, EXPIRED finalization after proof, cleanupPending clearing for terminal jobs, retained record/final-asset protection, idempotent replay, and upload/callback race guards. Updated API/OpenAPI, worker client/execution, tests, README, stable context, and living plan.
- Open: Add broader orphan/callback/email reconciliation, physical disk admission, structured owner-visible operations, runbooks, feature gating, and authenticated pilots.
- Risks/Assumptions: IMPORTED quota remains represented by its job until a future deliberate accounting migration. Cleanup shares the single queue and therefore favors active VALIDATE/IMPORT work; this is intentional for the low-volume MVP. All 129 media tests pass with one expected Linux-only host skip; all 48 focused API tests pass; compilation, YAML parsing, formatting, and whitespace checks pass.

### Update 2026-08-05 22:24
- Decisions: Close ZIP-import Phase 5 after connecting the existing concurrency-safe confirmation API, sequential importer, atomic resource commit, and compensated-failure path to the user workflow. Keep successful temporary-payload cleanup and operational activation in Phase 6.
- Implementation: Added the FasnachtsPage two-step READY confirmation bound to the rendered stateVersion, duplicate/stale-action protection, authoritative conflict refresh, IMPORTING polling, and distinct IMPORTED/FAILED terminal guidance. Added confirmation/lifecycle policy coverage and synchronized the living plan and repository contexts to mark Phase 5 DONE.
- Open: Phase 6 must implement API-claimed expiry/success cleanup, reconciliation, disk admission, operational runbooks, feature gating, and authenticated pilot exercises. The university Defender answer remains a pre-pilot input.
- Risks/Assumptions: The frontend correctly delegates the final authorization, target, quota, and collision decisions to oldap-api. The worker Compose profile remains operator-gated. All 96 FasnachtsPage domain tests, targeted ESLint, and its production build pass; project-wide svelte-check remains at the unchanged 22-error/37-warning baseline with no ZIP-import diagnostics.

### Update 2026-08-05 22:06
- Decisions: Run VALIDATE and IMPORT on the same existing global sequential worker. Use deterministic commit/failure events and owner markers instead of another queue/store. Compensate only explicit 4xx commit rejection; retain assets after transport, 5xx, or malformed-receipt ambiguity because GraphDB may already have committed.
- Implementation: Added strict IMPORT claim parsing, dual-task claiming/heartbeat, implicit-parent and empty-folder planning, manifest-bound asset preparation/promotion, exact commit-receipt verification, definitive-rejection compensation, payload deletion, durable failure receipt, terminal FAILED publication/replay, and the media-volume worker mount. Added text/folder/success/rejection/ambiguity/failure-replay/control-plane/deployment tests and updated runtime documentation and the living plan.
- Open: Add the FasnachtsPage confirmation action and end-to-end READY -> confirm -> IMPORTING -> IMPORTED/FAILED UX. Successful IMPORTED temporary-payload cleanup remains the API-claimed Phase 6 task.
- Risks/Assumptions: The existing `zip-import-validation` profile name is retained for deployment compatibility although the worker now also imports. Production promotion still requires Linux renameat2 and the media work/final roots on the same filesystem.
- Verification: All 127 mediahelper tests pass with one expected Linux-only host skip; all 42 focused oldap-api import/authentication tests pass; both authoritative OpenAPI contracts validate; compilation and whitespace checks pass.

### Update 2026-08-05 21:53
- Decisions: Keep the API as the sole atomic staging mutation owner. Identify returned resource mappings by relative path in addition to source entry index so omitted ZIP directory entries can be synthesized without inventing or exhausting index values. Retain detailed codec/probe facts in the immutable manifest rather than widening the closed StagingMediaObject ontology for the MVP.
- Implementation: Completed the oldap-api Phase 5 batch boundary with live original-user authorization, target/default-role/collision checks, deterministic staging IRIs, one-transaction hierarchy plus IMPORTED persistence, and exact replay. Synchronized the standalone internal OpenAPI contract and living plan; made derivativeName mandatory in the commit evidence.
- Open: Wire IMPORT claims in mediahelper, synthesize implicit folders, promote prepared assets, invoke the atomic commit, compensate rejected commits, and handle terminal failures/recovery.
- Risks/Assumptions: Same-name media at the existing root remain permitted under D-004, while every folder-involving collision blocks. Successful temporary-payload cleanup remains Phase 6.
- Verification: Both authoritative API contracts validate; all 41 focused oldap-api import/authentication tests pass, with compilation and whitespace checks clean.

### Update 2026-08-05 21:11
- Decisions: Start Phase 5 with an explicit filesystem transaction boundary before GraphDB mutation. Reuse the already implemented API `READY -> IMPORTING` CAS confirmation. Use deterministic UUIDv5 asset IDs per import/entry, same-filesystem work roots, Linux `renameat2(RENAME_NOREPLACE)`, and exact ownership markers for replay and compensation.
- Implementation: Added checksum-bound retained-manifest loading; complete original/derivative preparation; closed MIME/dcterms/protocol/derivative verification; original checksum revalidation; exclusive asset promotion; interrupted-attempt verification; and job-owned compensation. Added the missing canonical `document.txt` derivative and focused preparation, retry, collision, compensation, manifest-digest, and text tests. Included the new module in the restricted runtime image and updated the living plan/stable context.
- Open: Implement the fresh API target/authorization/collision recheck and one-transaction GraphDB folder/media commit, then wire IMPORT claims, promotion/commit compensation, terminal state publication, and FasnachtsPage confirmation UX.
- Risks/Assumptions: Atomic production promotion requires Linux `renameat2` and work/final paths on the same ext4 filesystem. The new preparer is intentionally not activated until the API batch commit and worker recovery protocol are connected. Malware scanning remains a separate university operational decision.
- Verification: The complete mediahelper suite passes with 121 tests and one expected Linux-only host skip; focused formatting, compilation, and whitespace checks pass.

### Update 2026-08-05 20:21
- Decisions: Close Phase 4 without an application-integrated malware scanner; keep the university Defender `/data` question as a pre-pilot operational check. Keep confirmation and all staging mutations in Phase 5.
- Implementation: Completed the FasnachtsPage protected report-review route with authoritative polling, strict v1 report validation, lifecycle/expiry/issue/checksum/tree views, progressive large inventories, Staging handoff link, and UUID-restricted post-login return. Updated the ZIP plan and stable context to mark Phase 4 complete.
- Open: Phase 5 must implement fresh confirmation checks and atomic staging commit. University IT's Defender response and an authenticated live-stack run remain pilot-readiness items.
- Risks/Assumptions: The local API was unavailable for the UI smoke test; the protected email route/login handoff were verified in-browser, and report rendering is covered by frontend contracts/tests/build. The worker remains profile-gated until Phase 5 and pilot checks are ready.

### Update 2026-08-05 12:28
- Decisions: Keep the lean single-container worker but establish a real same-container security boundary: trusted parent owns API/claims/evidence/publication; hostile parser child receives no client or claim, uses a fixed separate UID/GID, has no capabilities or network syscalls, and accesses only its current job workspace. Keep the Compose profile as explicit operator opt-in until UI/pilot readiness, not because parser isolation remains incomplete.
- Implementation: Added `parser_sandbox.py` with production UID/GID 65532, closed environment, supplementary-group/privilege drop, no-new-privileges libseccomp network denial, retry-safe job workspace permissions, post-analysis SIP revocation, and atomic READY promotion. Refactored the child to return parser evidence only; target preflight and document projection moved to the parent under the remaining six-hour budget. Added minimal container capabilities/no-new-privileges, fixed image identity/libseccomp wiring, deployment invariants, and no-client/no-secret tests.
- Open: Implement the FasnachtsPage report/tree/warning/error/expiry UI; confirm Defender coverage and remaining pilot operations with university IT/team. A future separate parser container/VM is warranted only if evidence shows the current kernel boundary is insufficient.
- Risks/Assumptions: The trusted parent intentionally remains root with six narrowly listed capabilities so it can prepare/revoke volume permissions, drop the child UID, and kill a different-UID process group. A kernel/container escape remains outside the process boundary. Production requires Linux with libseccomp and an ext4-like volume supporting Unix ownership/modes.
- Verification: All 117 media tests pass with one Linux-only skip. The production image builds and verifies minimal parent capabilities, child UID/GID 65532, zero child capabilities, secret removal, socket denial, low-privilege ZIP extraction/content validation, and FFprobe/qpdf/veraPDF execution under seccomp. All 37 focused oldap-api import/boundary tests, both authoritative OpenAPI specs, Compose rendering, Ansible syntax, compilation, focused Black, and whitespace checks pass.

### Update 2026-08-05 12:11
- Decisions: Enforce the frozen six-hour validation ceiling in the sequential parent rather than with an in-process signal, so hung C decoders and external tools are terminable. Treat deadline exhaustion as terminal FAILED with no fabricated manifest; keep unrelated analysis/service faults retryable. Continue profile-gating until parser credential/UID isolation is resolved.
- Implementation: Moved SIP verification, structural extraction, content validation, target preflight, and document projection into a spawned Unix process group. The parent keeps heartbeats, monitors a monotonic deadline, kills the complete group on timeout, retains a schema-valid `VALIDATION_TIMEOUT` report/result, deletes quarantine, then publishes. Added create-only FAILED report storage/read/replay without a manifest and timeout schema/worker tests.
- Open: Remove the import-service client/secret from the parser process and review its UID/filesystem/network boundary; implement the FasnachtsPage report UI. Phase 5 must still recheck target and collisions during commit.
- Risks/Assumptions: Production is Linux/Unix with `setsid`/process-group signals. The six-hour policy is not environment-broadenable. The spawned child currently receives the import-service client solely because target preflight is still inside the timed pipeline; the worker profile remains disabled pending that correction.
- Verification: All 113 media tests pass with one Linux-only skip, including a real descendant-process kill assertion; all 37 focused oldap-api import/boundary tests and both authoritative OpenAPI specs pass. Compose, Ansible syntax, compilation, focused Black, whitespace, production image build, and in-image worker/`setsid` checks pass. Repository-wide Black still reports the same four pre-existing files outside this slice.

### Update 2026-08-05 11:55
- Decisions: Keep target hierarchy reads in oldap-api and expose only a claim-bound collision operation to media. Treat every canonical-equivalent collision involving a folder as blocking, media/media equivalence as a warning, and validation preflight as advisory until Phase 5 rechecks inside commit.
- Implementation: Added strict top-level entry derivation including implicit ZIP folders, target-preflight client parsing, report finding projection, and READY/INVALID integration. oldap-api now verifies the live VALIDATE lease, reads a bounded direct-child inventory through its dedicated GraphDB connection, compares NFC/portable keys, and returns only stable TARGET_CHANGED/TARGET_FOLDER_COLLISION/TARGET_MEDIA_NAME_COLLISION evidence. Updated both OpenAPI contracts and API-boundary documentation.
- Open: Add the total validation deadline and FAILED cleanup/result flow, isolate Pillow from worker credentials, confirm Defender coverage, and implement the FasnachtsPage review UI. Phase 5 must repeat target/authorization/collision checks atomically.
- Risks/Assumptions: Direct-child inspection is capped at 10,000 and fails as an operational service error above that envelope rather than silently returning incomplete evidence. Media names use shared:originalName with schema:name fallback. All 109 media tests pass with one Linux-only skip; all 29 focused API import tests and both OpenAPI validations pass.

### Update 2026-08-05 11:36
- Decisions: Detect every MVP format from content, combine veraPDF conformance with independent qpdf/pdfinfo safety checks, reject structured/script text rather than treating it as text/plain, and keep the worker profile-gated until target preflight, total deadline handling, and parser privilege isolation are resolved.
- Implementation: Added sequential bounded JPEG/PNG/TIFF, WAV/FLAC/MP3, H.264/AAC MP4, PDF/A-1/2, and UTF-8 probes; packaging-artifact handling; READY/content-INVALID manifest/report projection; seven-day READY evidence; quota summary reconciliation; Docker qpdf/JRE/pinned veraPDF runtime; and focused contract/pipeline tests. External parser output is kernel-limited through prlimit-backed temporary files.
- Open: Implement target-child preflight and the six-hour total wall-clock transition, isolate in-process Pillow parsing from worker credentials, confirm Defender coverage for `/data`, and add the FasnachtsPage report/review UI.
- Risks/Assumptions: PDF/A validation materially increases the worker image size and runtime. Explicit ZIP directory entries are represented exactly; synthesis of omitted parent directory entries belongs to the import mapping review. The profile remains disabled, so the new path is not yet a production activation claim. All 105 host tests pass with the Linux-only prlimit test skipped; the production image builds and verifies the full parser runtime and kernel output cap in-container. Compose, Ansible syntax, compilation, targeted Black, and whitespace checks pass; repository-wide Black still reports four pre-existing files.

### Update 2026-08-05 03:10
- Decisions: Use the existing oldap-api global lease as the only queue, heartbeat independently of validation, and retain evidence outside temporary ingest. Publish INVALID only after payload deletion; profile-gate the worker until content validation can handle structurally valid ZIPs truthfully.
- Implementation: Added strict claim/service-JWT client, sequential worker, heartbeat thread, SIP checksum verification, RFC 8785 create-only manifest/report records, import-records JWT read endpoint, structural INVALID projection, deletion/crash replay, and a no-port restricted worker container with 4 CPU/6 GiB/128 PID limits. Extended claim facts and deployment secret/storage separation.
- Open: Add wall-clock cancellation, MIME/codec/PDF-A/UTF-8 probes, target-child preflight, READY projection/quota reconciliation, and then enable the worker profile. Confirm the private API-to-media route used for retained-record reads in production networking.
- Risks/Assumptions: Structural success deliberately produces no lifecycle result yet. Records are on the same ext4 volume but a distinct private root. Ninety-seven media tests, twenty-five focused API import tests, Black/compile checks, and all three OpenAPI validations pass.

### Update 2026-08-05 01:45
- Decisions: Start Phase 4 with a pure, network-free ZIP structure boundary before adding worker claims, target lookup, content parsers, or record publication. Support only the approved one-disk, non-ZIP64 stored/deflated subset and make extraction all-or-nothing.
- Implementation: Added bounded EOCD/central/local/data-descriptor parsing, strict filename decoding, NFC and portable collision checks, path/type/flag/method/header/range validation, declared and actual size/ratio enforcement, and individual mode-0700 extraction with CRC/SHA-256 evidence and complete rollback. Included the module in the narrow runtime image and documented the boundary and Phase 4 progress.
- Open: Add the restricted single claim worker and heartbeat, manifest/report projection and immutable storage, target-root preflight, content/MIME/codec/PDF-A probes, API validation-result publication, invalid payload deletion, quota reconciliation, and FasnachtsPage review views.
- Risks/Assumptions: Python's decompressor is used only after an independent bounded metadata pass; parser defects remain contained by the still-to-be-wired worker cgroup. This slice does not claim a job or publish READY/INVALID. All 90 tests pass; targeted formatting, compilation, whitespace, the production Docker build, and in-image import pass. Repository-wide Black still reports four pre-existing files outside this slice.

### Update 2026-08-05 01:30
- Decisions: Complete Phase 3 with a browser-owned, non-resumable direct PUT. Snapshot the selected existing StagingFolder IRI when creating the API job, keep the media capability outside normal access-token renewal, and expose progress without any confirmation action before validation.
- Implementation: FasnachtsPage now validates the 500 MB ZIP envelope, creates the job through the generated authenticated OLDAP client, streams the file directly to media quarantine with a UUID request ID, validates the durable receipt, and reports the running validation/email handoff. Updated the generated public API client, focused tests, stable frontend context, and Phase 3 plan status.
- Open: Phase 4 must implement isolated full ZIP validation, extraction, report production, and the single-worker queue. A physical free-space admission guard remains required before pilot rollout.
- Risks/Assumptions: Browsers supply Content-Length for a File XHR but prohibit application code from setting that header explicitly. Upload retry/reissue UI and authoritative job polling remain later lifecycle UI work. Focused tests and ESLint pass, the production frontend build succeeds, and project-wide Svelte checking remains at its existing 22-error/37-warning baseline with no ZIP-flow diagnostics.

### Update 2026-08-05 01:15
- Decisions: Give abandoned ingress parts a 24-hour grace, 96 times the supported request timeout, and remove at most 100 per maintenance pass. Permit age-based deletion only for strict `.part-<canonical UUID>-*` real directories; never apply it to finalized UUID directories. Define stale UPLOADING as 24 hours but keep its state, quota, and finalized cleanup behind API compare-and-set claims in Phase 6.
- Implementation: Added bounded symlink-safe partial-directory cleanup to the existing 60-second maintenance loop; wired the 86400-second deployment setting; documented D-019, the Phase 6 lifecycle obligation, threat control, contracts, README, stable context, and living plan.
- Open: FasnachtsPage must start direct upload from the selected existing StagingFolder. Phase 6 must implement the API-owned stale-UPLOADING claim/result transition and physical free-space admission before pilot rollout.
- Risks/Assumptions: Directory mtime is an acceptable partial-upload liveness proxy only because the deletion grace exceeds the enforced request timeout by a factor of 96 and the ingest root is mode 0700. A privileged host actor remains outside this application boundary. All 66 tests, formatting, compilation, whitespace and Ansible syntax checks, and the production Docker build pass.

### Update 2026-08-05 01:00
- Decisions: Reconcile API notification with a tiny in-process bounded loop rather than add a broker or another container. Persist one immutable callback event ID before SIP finalization, mint service JWTs per attempt, mark DELIVERED only after a validated API acknowledgement, and keep callback failure independent from durable upload success.
- Implementation: Added the purpose-specific API notifier, exact retained sip-stored payload, response identity/state checks, atomic PENDING-to-DELIVERED receipt replacement, immediate replay retry, and a configurable 60-second/100-receipt reconciler. Wired the separate service secret, subject, interval, Docker image, Compose, Ansible/Vault validation, README, stable context, and living plan.
- Open: Add bounded stale-part removal and stale-UPLOADING lifecycle behavior, then connect FasnachtsPage. A physical free-space admission guard is still required before pilot deployment.
- Risks/Assumptions: The MVP deploys one Gunicorn worker; multiple workers could make duplicate callback attempts, but the API event contract is idempotent and local DELIVERED replacement is atomic. PENDING may persist while API/service authentication remains unavailable but the SIP and exact event remain durable. All 64 tests, compilation, formatting, whitespace and Ansible syntax checks, the production Docker build, and in-image callback imports pass.

### Update 2026-08-05 00:45
- Decisions: Begin Phase 3 with one non-resumable, idempotent PUT and an atomically renamed per-import quarantine directory. Treat exact upload-request-ID replay as success without rereading the body; reject a different request ID after finalization. Mount ingest outside the delivery root and only into mediahelper.
- Implementation: Added strict purpose-specific upload JWT verification; bounded streaming ZIP ingress with SHA-256, declared/actual length and restrictive signature checks, durable SIP/receipt fsync, atomic directory finalization, partial rollback, and redacted operational logs. Added the Flask route/CORS contract, authoritative OpenAPI, Docker image wiring, Caddy 500 MB/15-minute route, local and Ansible private-volume wiring, Vault secret validation, and 8 focused new storage/auth/deployment tests.
- Open: Deliver/retry the idempotent sip-stored callback and persist DELIVERED notification state; define stale UPLOADING and abandoned-part cleanup; integrate the selected StagingFolder upload flow in FasnachtsPage. Add the physical free-space admission guard before production pilot.
- Risks/Assumptions: The ZIP signature check is ingress framing only; full central-directory, path, encryption, bomb, MIME, and codec validation remains Phase 4. Filesystem durability relies on fsync plus same-filesystem directory rename. All 59 tests, both media OpenAPI validations, Caddy validation, compilation, whitespace checks, the production Docker build, and in-image ingest-module imports pass.

### Update 2026-08-05 00:30
- Decisions: Mark cross-repository ZIP import Phase 2 complete at the API-owned job/authorization/quota boundary; retain import and cleanup completion events for their later execution/lifecycle phases. Phase 3 is now the next active implementation phase.
- Implementation: Updated the living plan and stable context to record completed API persistence, permissions, quotas, scoped credentials, worker leases, protected reports, notification state, opaque pagination, privacy-preserving audit logging, and boundary tests. No media runtime code changed in this closure step.
- Open: Implement media-owned direct SIP upload, immutable quarantine storage, upload-capability enforcement, and the SIP-stored callback in Phase 3. Media-side protected retained-record serving follows with validation/report work.
- Risks/Assumptions: Production quota correctness depends on GraphDB transaction isolation and must be deployment-tested; existing staging areas must define positive `shared:stagingQuotaBytes`. The media ZIP endpoint and worker do not yet exist.

### Update 2026-08-04 22:48
- Decisions: Complete Phase 1 by making the trust distinction explicit: legacy MIME/filename classification remains backward-compatible routing information, while parser-derived audio/PDF facts use separate immutable result types. Keep the approved ZIP limits as non-overridable code-level ceilings synchronized with the v1 schema. Make derivative generation Flask-independent while retaining caller-owned whole-asset rollback.
- Implementation: Added `media.py` with typed upload classification, ffprobe JSON normalization, and bounded PDF structure probing; added `derivatives.py` with reusable libvips/FFmpeg/Poppler orchestration and typed output inventory; added typed ZIP policy and ingest-worker resources to `config.py`; simplified `/upload` to compose these interfaces; included the new modules in the narrow Docker context/image; documented responsibilities and marked Phase 1 `DONE`.
- Open: Phase 2 has not started. Full ZIP allowlist validation (content MIME, image/video/PDF-A policy enforcement) remains Phase 4 work built on these boundaries; Phase 2 next adds API-owned ImportJob persistence, state transitions, authorization, quotas, and capabilities.
- Risks/Assumptions: The existing single-upload MIME/filename routing is intentionally preserved and must not be reused as secure ZIP content detection. Native derivative tools still process only an exclusively reserved asset workspace, and callers must remove the complete asset on partial derivative failure.
- Verification: Added policy/schema drift, classification, typed audio/PDF probe, and derivative orchestration tests; all 51 tests pass. Python compilation, YAML parsing, whitespace checks, production Docker build, and in-image module imports pass.

### Update 2026-08-04 22:31
- Decisions: Start Phase 1 with the reusable storage/configuration boundary and include SHA-256 in the existing single-file upload. Use lower-case 64-character SHA-256 of the exact stored original, keep it server-managed, write it as `shared:checksum`, and expose the same digest as an additive `checksum` response field. Use an unpredictable per-operation directory rather than a global `<assetId>.<ext>` temporary path.
- Implementation: Added side-effect-free `MediahelperSettings`; added Flask-independent typed storage primitives for safe paths, exclusive asset reservation, isolated workspaces, and chunked original copying with integrity metadata; integrated them into `/upload`; updated the runtime image whitelist/copies, OpenAPI, README, stable context, and Phase 1 plan. Existing destinations are never removed on an exclusive-create collision, and partial newly created originals are removed on failure.
- Open: Extract typed content detection/probing and derivative generation from the Flask request handler and add agreed ZIP-limit configuration at that boundary before closing Phase 1.
- Risks/Assumptions: The deployed shared ontology must include the already-defined optional `shared:checksum` property. The digest covers only the unchanged original, not generated derivatives. Existing assets are not backfilled by this change.
- Verification: Added storage/configuration unit coverage plus upload assertions for MediaObject/response checksums and spoof resistance; all 44 repository tests pass, Python modules compile, the OpenAPI YAML parses, whitespace checks pass, and the checksum is verified against independently calculated test digests. The production Dockerfile builds as `oldap-mediahelper:phase1-test`, including importable `config` and `storage` modules.

### Update 2026-08-04 22:13
- Decisions: Close Phase 0. Confirm WAV integer PCM 8/16/24/32-bit at 8–192 kHz, FLAC 8/16/24-bit at 8–192 kHz, MP3 at 8–48 kHz, all mono/stereo; MP4 H.264 8-bit 4:2:0 Baseline/Main/High through level 5.2 with optional AAC-LC; strict content-detected UTF-8 `text/plain`; empty/artifacts-only ZIP rejection; and a sequential worker ceiling of 4 vCPUs, 6 GiB RAM, and 128 PIDs. Deliberately defer the quota ontology property to Phase 2 and Defender/integrated scanning to Phase 4 before the pilot.
- Implementation: Marked Phase 0 `DONE`; synchronized the plan, decision register, threat model, fixture catalogue, stable project context, policy-limit schema, examples, and issue codes. No runtime application code was added or changed.
- Open: Phase 1 has not started. Phase 2 owns the exact staging-area quota property; the VM owner and university IT must establish Defender coverage for `/data` in Phase 4 before a pilot.
- Risks/Assumptions: Same-container parser isolation remains weaker than a separate sandbox and depends on the documented cgroup, process, token, egress, and filesystem controls being implemented and verified. Content-detector normalization must map tool-specific codec/profile names to the frozen policy without broadening it.
- Verification: JSON syntax, Draft 2020-12 schemas and READY/INVALID examples, OpenAPI 3.1 contracts with external references, negative schema invariants, and repository whitespace are revalidated at closure.

### Update 2026-08-04 19:18
- Decisions: Treat the container cgroup, not language/library thread counts, as the resource boundary; keep one global job and sequential archive-entry/parser processing under 4 vCPUs; propose 6 GiB RAM with no extra swap, bounded PIDs, and smaller per-tool pools; generate rejected formats and malicious ZIP metadata deterministically; split fixtures into default, integration, scaled-boundary, and operator-only tiers; never commit real malware, EICAR, or gigabyte-expanding fixtures.
- Implementation: Added `THREAT_MODEL.md` with assets, trust boundaries, resource profile, 24 prioritized threats, controls, verification, and residual risks, plus `TEST_ZIP_CATALOG.md` covering accepted and rejected formats, ZIP/path/name attacks, bombs, authorization, races, crash/commit/cleanup, and controlled operational tests. Marked the Phase 0 threat-model deliverable complete and synchronized the decision register, plan, and stable context. No runtime or test generator code was added.
- Open: Confirm the 6-GiB memory ceiling, empty/artifacts-only ZIP rejection, exact WAV/FLAC/MP3 bit-depth/sample-rate rules, structured UTF-8 text handling, Defender/application scanner deferral, and staging-area quota ontology property.
- Risks/Assumptions: Same-container parser isolation is weaker than a separate parser sandbox; the MVP mitigates with unprivileged sanitized subprocesses, no inherited tokens, restricted egress, cgroups, minimal loaders, and an import-only service identity. EICAR can trigger real quarantine behavior and remains operator-only after university coordination.
- Verification: Documentation cross-references stable schema/API codes and separates every unsafe or resource-heavy scenario from normal CI; repository whitespace checks pass.

### Update 2026-08-04 18:28
- Decisions: Split the v1 contract between API-owned public/internal ImportJob operations and media-owned direct SIP/record operations; keep direct upload immutable and non-resumable; use purpose-specific access, upload, import-service, and record-service credentials; require expected state versions for public mutations, event IDs and claims for internal idempotency, renewable leases for the single worker, API-proxied reports, and one transactional create-only staging commit. Cleanup failure never converts IMPORTED/CANCELLED to FAILED.
- Implementation: Added validated OpenAPI 3.1 contracts for `api.oldap.org` and `media.oldap.org`, plus `api-contracts.md` documenting trust boundaries, public flow, lifecycle preconditions, conservative quota reservation, claims, replay handling, batch commit, and stable errors. Marked the Phase 0 API deliverable and D-018 complete and synchronized project context. No runtime application code was changed.
- Open: Complete the threat model/fixture catalogue; define the staging-area quota ontology property, exact remaining audio sample/bit-depth rules, worker RAM, and malware/Defender disposition. Merge these standalone contracts into authoritative service OpenAPI files only with Phase 2/3 implementations.
- Risks/Assumptions: Internal routes must be excluded from public proxy routing in addition to token checks. GraphDB must support the resource/job batch boundary or the implementation needs a precisely documented equivalent without weakening IMPORTED atomicity.
- Verification: Both YAML files parse successfully and pass OpenAPI 3.1 validation with all relative JSON Schema references resolved; repository whitespace checks pass.

### Update 2026-08-04 18:18
- Decisions: Confirm PDF/A-1/PDF-A-2 only with independent active-content/attachment rejection; version validation evidence as strict JSON Schema Draft 2020-12; separate immutable technical manifests from protected user reports and later import receipts; bind READY/INVALID reports to RFC 8785 canonical manifests with SHA-256; bound hostile inventories explicitly instead of expanding unbounded reports.
- Implementation: Added shared, manifest, and report v1 schemas under `docs/zip-import/v1/`, READY/INVALID manifest and report examples, contract documentation, target/policy snapshots, raw/NFC name fields, technical probe facts, planned staging resources, stable issue codes, and conditional READY/INVALID/FAILED invariants. Updated D-002/D-017, Phase 0 progress, and stable context. No runtime application code was changed.
- Open: Define public/internal API and state-machine contracts, exact remaining audio codec/sample constraints, quota representation, threat fixtures, worker RAM, and the malware-scanning deferral. Specify the separate import receipt in Phase 5.
- Risks/Assumptions: JSON Schema cannot enforce UTF-8 byte length or cross-array count equality by itself; implementation checks and contract tests must enforce those invariants. Raw filename bytes are audit-only and never become filesystem paths.
- Verification: JSON syntax passed with `jq`; all three schemas passed Draft 2020-12 meta-schema validation, and four READY/INVALID examples validated with format checking using a temporary validator outside the repository.

### Update 2026-08-04 18:05
- Decisions: Restrict the MVP to ordinary single-disk ZIP archives using stored/deflate only, reject ZIP64 and optional complex ZIP features, reduce compressed size to 500,000,000 bytes and extracted size to 3,000,000,000 bytes, cap all audio at two channels, and require user `ADMIN_CREATE` plus effective role `DATA_UPDATE` on the containing `shared:StagingArea`. Recommend PDF/A-1 or PDF/A-2 with independent active-content and attachment rejection, pending user confirmation.
- Implementation: Updated the Phase 0 policies, final limit table, ZIP subset, permission checks, decision register, roadmap context, and progress log. Added primary-reference links for the PDF/A proposal. No application code was changed.
- Open: Confirm D-017; define exact audio sample/bit-depth acceptance, manifest/report schemas, API contracts, quota representation, threat fixtures, worker RAM, and whether malware scanning is deferred to Phase 4.
- Risks/Assumptions: PDF/A narrows PDF features but still requires isolated parsing; acceptance must not rely on self-declared metadata, and all embedded files remain independently forbidden.

### Update 2026-08-04 17:52
- Decisions: Confirm the target-root collision policy: canonical-equivalent existing child folders and file/directory conflicts block the all-or-nothing import; same-named existing media are allowed with explicit report warnings because their independent technical asset IDs prevent overwrites.
- Implementation: Marked D-004 decided and synchronized the validation checklist, plan progress log, and stable project context. No application code was changed.
- Open: Define stable machine-readable report codes and the exact canonical comparison fields in the Phase 0 manifest/report schemas.
- Risks/Assumptions: The warning policy intentionally permits duplicate human-readable media names in one staging folder; the UI must make their distinct asset identities clear.

### Update 2026-08-04 17:48
- Decisions: Make one explicitly selected existing `shared:StagingFolder` the immutable root of every ZIP import; create no ZIP-name wrapper, attach ZIP-root files directly to that folder, create ZIP-root directories as new children, and exclude the selected folder from the five-level ZIP depth limit. Block existing canonical folder and file/directory conflicts; propose reporting same-named existing media as non-overwriting warnings because asset IDs are independent.
- Implementation: Updated the living ZIP import plan, Phase 2–5 work items, decision register, progress log, and stable project context with target-root, authorization-recheck, collision-preflight, and incremental-import semantics. No application code was changed.
- Open: Confirm the same-named-media warning policy; define the exact API, manifest, and report fields for the target-root IRI and display-name snapshot, plus the stable error returned if the hierarchy changes between validation and confirmation.
- Risks/Assumptions: A fresh authorization and collision check is required immediately before import so concurrent staging changes cannot produce a partial or ambiguous hierarchy.

### Update 2026-08-04 15:52
- Decisions: Make `api.oldap.org` the exclusive owner of import email; keep FasnachtsPage polling authoritative, commit ImportJob state before mail submission, use authenticated non-action links, retain no SMTP settings on the media VM, and track bounded notification retries independently from import state.
- Implementation: Reviewed the deployed password-reset SMTP path and its focused tests, documented the reusable import-notification contract and four MVP templates in `ZIP_IMPORT_PLAN.md`, and synchronized stable project context. No application code was changed.
- Open: Extract the password-reset-specific SMTP transport into a small reusable `oldap-api` mail module when ImportJob API work begins; notification persistence fields and retry timing remain part of that contract design.
- Risks/Assumptions: University SMTP acceptance does not guarantee inbox delivery, so users must always be able to find and act on imports through authenticated FasnachtsPage status views.

### Update 2026-08-04 14:07
- Decisions: Keep the ZIP importer project-neutral but activate Fasnacht first; require project `ADMIN_CREATE` plus target staging `DATA_UPDATE`; represent ZIP directories as create-only `shared:StagingFolder` subtrees below an optional existing target; adopt the restrictive format/name/lifecycle recommendations, provisional 10 GB compressed and 50 GB extracted limits, one global worker job, `FAILED`/`CANCELLED`, per-staging-area quotas, and no resumable upload. Keep the MVP to one worker container, GraphDB state, the existing ext4 volume, and no new database or broker.
- Implementation: Updated `ZIP_IMPORT_PLAN.md` with confirmed product rules, deployment capacity, limits, seven phases numbered 0–6, lean-MVP boundaries, resolved decision status, and the remaining Defender/quota-schema/RAM questions; synchronized stable project context. No application code was changed.
- Open: Confirm Microsoft Defender's actual Linux `/data` scan coverage, choose the worker RAM limit, and define the project-neutral quota property plus the exact API authorization check for staging-area versus target-folder permissions.
- Risks/Assumptions: The unencrypted 1 TB ext4 volume is backed up daily and can be extended, but temporary ingest data should be excluded from backups; physical admission must account for derivative expansion in addition to the extracted-byte user quota.

### Update 2026-08-04 00:33
- Decisions: Maintain the secure ZIP-to-staging initiative as one living, cross-repository plan organized into seven gated phases; keep the existing single-file upload compatible during incremental delivery.
- Implementation: Added `ZIP_IMPORT_PLAN.md` with scope, invariants, phase checklists and exit criteria, open decisions, component ownership, verification requirements, and a progress log; linked the plan from the stable project context. No application code was changed.
- Open: Resolve the Phase 1 limits, exact MIME/codec rules, unsupported-file policy, naming semantics, operational failure state, quota reservation, malware scanning, retention, and resumable-upload decisions.
- Risks/Assumptions: The plan spans `oldap-mediaserver`, `oldap-api`, `oldaplib`, and `FasnachtsPage`; each repository must maintain its own technical change log once implementation begins.

### Update 2026-07-23 17:41
- Decisions: Treat production media CORS separately from API refresh-cookie CORS, require post-deploy health/version verification, and suppress Caddy handlers during intentional rollback.
- Implementation: Restored `https://fasnacht.digital` to the production media allowlist, made Compose wait for running services, added retried public mediahelper health/version and tokenless IIIF authorization probes after flushing Caddy handlers, guarded rollback handlers, ignored local Caddy/Cantaloupe runtime artifacts, documented the deployment contract, and added focused target/inventory regression tests.
- Open: Confirm that the shared production Vault contains rotated access/media keys, then deploy test before production and verify a real IIIF image plus PDF asset in addition to the automated mediahelper health check.
- Risks/Assumptions: The deployment host can resolve its public media domain; internal-CA certificate validation is disabled only for the home target, while production keeps normal TLS validation.

### Update 2026-07-20 22:27
- Decisions: Treat `media.home.org` as a separate VM from the home API, rely on authoritative home DNS instead of stale Docker host aliases, keep private-CA HTTPS for browser parity, and constrain each deployment target twice through its play host expression and inventory limit.
- Implementation: Pointed the test media stack at `http://api.home.org`, added exact per-environment CORS origins, configured the production ACME contact, added explicit Make target limits for test and production, and synchronized deployment documentation and project context.
- Open: Run `make deploy-test`, trust the media Caddy root CA on test clients, and verify DNS from the deployed containers before promoting the same image tags with `make deploy-production`.
- Risks/Assumptions: Home DNS keeps `media.home.org` and `api.home.org` on their separate VMs and is reachable through Docker's resolver; access and media JWT keys in the shared Vault match the API deployment.

### Update 2026-07-16 23:02
- Decisions: Use the same protected central Vault file as `oldap-setup` for test and production media deployments while retaining explicit overrides.
- Implementation: Added Make defaults for `$HOME/ProgDev/OLDAP/auth/auth.vault.yml` and `--ask-vault-pass`, a preflight file check, automatic `auth_secrets_file` propagation to both deployment targets, and synchronized deployment documentation.
- Open: Run `make deploy-test` or `make deploy-production` and enter the Vault and sudo passwords when prompted.
- Risks/Assumptions: The central Vault contains the access and media JWT variables expected by `deploy-media.yml`, and those values match the API deployment.

### Update 2026-07-16 12:00
- Decisions: Treat asset deletion as an upload-domain mutation that requires the same strictly validated OLDAP access token as asset creation; never accept a media delivery capability for deletion.
- Implementation: Replaced the stale deleted `require_bearer_token()` call in `DELETE /upload/<asset_id>` with `require_access_token()` and added regression coverage for missing credentials and cross-purpose media tokens.
- Open: Rebuild and redeploy the mediahelper image before verifying MediaLibrary deletion through FasnachtsPage.
- Risks/Assumptions: The frontend already sends the current Bearer access token; the existing OLDAP permission check remains authoritative for `DATA_DELETE`.

### Update 2026-07-16 00:17
- Decisions: Standardize image delivery on tiled pyramidal BigTIFF and remove JPEG 2000 plus the proprietary codec runtime from the supported upload and IIIF architecture; bump both affected pre-1.0 components to `0.2.0` for the breaking target-format change.
- Implementation: Made TIFF the default and only image target, fixed the derivative contract to `master.tif`, removed proprietary conversion/build stages and the tracked base-image scaffold, restricted the imageserver build context to the Cantaloupe JAR and OLDAP files, configured Cantaloupe ManualSelectionStrategy with Java2dProcessor for TIFF, and updated delegate fallbacks, tests, OpenAPI, Compose comments, README, and stable project context.
- Open: Build and push `lrosenth/oldap-mediahelper:v0.2.0` and `lrosenth/oldap-imageserver:v0.2.0`, then deploy the pinned tags; delete the obsolete private base image and any local licensed artifacts manually after confirming they are no longer needed.
- Risks/Assumptions: The deployment has no existing JPEG 2000 derivatives; TIFF output remains uncompressed, so storage usage may be higher than with a lossless compressed TIFF profile.

### Update 2026-07-15 23:49
- Decisions: Version the Flask mediahelper independently from the repository Python package and other images, using `mediaserver/VERSION` as its single source and requiring explicit deployment propagation alongside the imageserver tag.
- Implementation: Added mediahelper version `0.1.0`, strict Make version/tag/image derivation and inspection targets, OCI/runtime version metadata, VERSION-file runtime fallback with focused tests, Root-Make and Ansible propagation without a duplicated default, and synchronized release/deployment documentation and project context.
- Open: Build and push `lrosenth/oldap-mediahelper:v0.1.0` before deploying it; Kakadu base-image versioning remains separate future work.
- Risks/Assumptions: The existing `pyproject.toml` version remains a repository/Python packaging concern and does not define the mediahelper image tag; published component image tags remain immutable.

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
