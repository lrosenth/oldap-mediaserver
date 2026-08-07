# Phase 6 Lifecycle and Recovery Test Matrix

This matrix maps the lean MVP's cross-component lifecycle risks to executable
evidence. It intentionally reuses focused domain, filesystem, HTTP-contract,
and frontend tests instead of creating a second integration framework.

## Automated evidence

| Area | Required invariant | Executable evidence |
| --- | --- | --- |
| End-to-end success | API authority progresses `UPLOADING -> VALIDATING -> READY -> IMPORTING -> IMPORTED`, preserves event evidence, then accepts cleanup proof without releasing imported staging quota | `oldap-api/oldap_api/test/test_import_domain.py::test_complete_happy_lifecycle_reaches_imported_cleanup_with_audit_evidence` |
| End-to-end invalid | Unsafe or unsupported content publishes INVALID only after payload deletion, retains immutable report evidence, and releases logical quota | `oldap-mediaserver/tests/test_ingest_worker.py::test_invalid_payload_is_deleted_before_api_publication`; `oldap-api/oldap_api/test/test_import_internal.py::test_invalid_result_requires_deleted_payload_and_releases_quota` |
| User lifecycle | The frontend gates confirmation to the exact reviewed READY version and represents polling/terminal states | `FasnachtsPage/tests/staging-zip-import.test.ts`; `FasnachtsPage/tests/staging-zip-import-report.test.ts` |
| Concurrency | Two job creations cannot overreserve a StagingArea; simultaneous workers obtain at most one global claim; simultaneous confirmation of one READY version has one winner | `oldap-api/oldap_api/test/test_import_domain.py::test_concurrent_creation_cannot_overreserve_staging_quota`; `::test_concurrent_workers_can_claim_only_one_global_task`; `::test_concurrent_ready_actions_have_one_authoritative_winner` |
| Quota reconciliation | Creation uses the conservative reservation, READY reconciles to actual extracted originals, invalid/failed/expired releases quota, and imported cleanup retains the staged allocation | `oldap-api/oldap_api/test/test_import_domain.py`; `oldap-api/oldap_api/test/test_import_internal.py` |
| Physical capacity | Upload returns stable HTTP 507 without partial SIP, validation blocks before extraction, import blocks before asset writes, and finalized replay needs no allocation | `oldap-mediaserver/tests/test_storage_capacity.py`; `tests/test_quarantine.py::test_endpoint_rejects_capacity_pressure_but_allows_exact_replay`; capacity tests in `tests/test_ingest_worker.py` and `tests/test_import_worker.py` |
| Validation crash/retry | Retained validation or timeout evidence republishes after an API outage without recreating or requiring the deleted SIP | `oldap-mediaserver/tests/test_ingest_worker.py::test_retained_result_recovers_after_api_failure_without_sip`; `::test_validation_timeout_deletes_payload_and_replays_failed_result` |
| Import crash/retry | Ambiguous commit failure never compensates potentially committed assets; deterministic replay can subsequently complete | `oldap-mediaserver/tests/test_import_worker.py::test_import_worker_retries_ambiguous_commit_without_compensation`; ownership/replay tests in `tests/test_import_assets.py` |
| Cleanup crash/retry | A crash after payload deletion but before API acknowledgement is reclaimed safely; absent payload is an idempotent success and retained records/final assets remain | `oldap-mediaserver/tests/test_ingest_worker.py::test_cleanup_recovers_after_deletion_when_api_acknowledgement_is_lost`; API cleanup replay tests in `oldap-api/oldap_api/test/test_import_domain.py` and `test_import_internal.py` |
| Cleanup races | IMPORTING is never cleanup-eligible; stale upload callbacks/capability reissue lose to an active cleanup claim; imported cleanup does not change IMPORTED | `oldap-api/oldap_api/test/test_import_domain.py::test_stale_upload_expires_only_after_claimed_payload_deletion`; `::test_cleanup_never_claims_importing_and_imported_cleanup_keeps_quota` |
| Callback/email retry | SIP callback replay keeps one immutable event; notification retry is API-owned, bounded to three attempts, and backed off five minutes | `oldap-mediaserver/tests/test_quarantine.py`; `oldap-api/oldap_api/test/test_import_domain.py::test_notification_reconciliation_is_bounded_and_backed_off`; `test_import_notifications.py` |
| Partial-upload cleanup | Cleanup removes only recognizable old `.part-*` directories, is bounded per pass, and never touches finalized UUID directories or symlinks | `oldap-mediaserver/tests/test_quarantine.py::test_abandoned_part_cleanup_is_bounded_and_never_touches_finalized_data`; `::test_abandoned_part_cleanup_honors_per_pass_limit` |
| Atomic commit | Staging resources and IMPORTED state share one GraphDB transaction; deterministic resource/asset collisions never overwrite existing data | `oldap-api/oldap_api/test/test_import_commit.py`; `oldap-mediaserver/tests/test_import_assets.py` |

## Operator-only evidence

The following remain deliberately outside normal CI and belong to pilot or
disposable infrastructure exercises:

- real 500-MB compressed and 3-GB extracted boundary archives;
- real low-free-space tests on a disposable mounted volume;
- process/container kill during native media conversion;
- backup exclusion and restore of retained manifest/report records;
- authenticated browser-to-media-to-API operation against the deployed test
  environment;
- malware/EICAR verification only if university IT requires a scanner control.

These are tracked by `TEST_ZIP_CATALOG.md` as T2/T3 or by the Phase 6 pilot and
operations work. They must never run against production data roots.
