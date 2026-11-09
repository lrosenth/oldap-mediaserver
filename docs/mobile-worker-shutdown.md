# Graceful mobile worker shutdown

The standalone mobile worker now handles SIGTERM and SIGINT by setting a shutdown
event. It finishes an already claimed processing, cleanup or lifecycle operation
before exiting normally. Processing/cleanup heartbeats remain active until that
operation finishes. A claim returning concurrently with a signal is handled;
afterward no further work is claimed. Idle waits are interruptible.

Ordinary operation failures retain their existing durable-phase/retry behavior.
Shutdown does not add commit replay, release leases prematurely, mark uncertain
writes successful or roll back already published assets. A subsequent start uses
the existing registry recovery rules. Upload/media/API contracts and original
bytes are unchanged; the behavior is independent of GraphDB versus Jena.

The internal `MobileUploadWorker.run_forever` helper gains an optional keyword
`stop` event. Existing callers remain compatible. No oldaplib, Harvester or
oldap-tools public function signature changes are required.

## Deployment and maintenance

Both Compose sources allow 15 minutes for an ordinary Compose stop. Coordinated
home maintenance uses `docker stop --signal SIGTERM --timeout -1`, which waits
without escalating to SIGKILL ([Docker documentation](https://docs.docker.com/reference/cli/docker/container/stop/)).
An indefinitely stalled converter or dependency therefore needs operator diagnosis;
maintenance deliberately does not force it to finish. Arbitrary Docker/host stop
commands may impose different limits and are not covered by this guarantee.

Keep the API reachable until the mobile worker has durably recorded its result.
The shared setup quiescence tasks stop media ingress/helper/ordinary workers,
then drain mobile work, then close API ingress. They verify drain support before
starting maintenance. API/Jena shutdown follows only after successful draining.

The media image updater detects whether the installed worker supports draining.
It uses SIGTERM without a forced-kill timeout for the new worker. Its explicitly
legacy path still requires an unused mobile registry before SIGINT. This lets the
first update replace the old implementation safely. New deployments and the
home namespace/memory/backup workflows default to SIGTERM.

## Verification

Unit tests cover completion of a claimed commit while leaving the next upload
queued, signals concurrent with claim return, stopping after an empty lifecycle
poll, idle wakeup, preexisting stop, cleanup completion and lifecycle acknowledgement.
The existing crash/lease/receipt suite remains applicable.

`scripts/check_mobile_shutdown.py --image IMAGE` runs disposable network-isolated
containers. It sends real SIGTERM to idle and active PID-1 processes and SIGINT
to an active process using the packaged production entry point/polling loop.
A gated fake work item proves that the process stays alive until completion,
exits with code zero and does not start a second item. These tests do not claim
real media conversion or API writes; the SQLite phase tests cover state handling.

See `mobile-worker-shutdown-results.json` for the image provenance, home rollout
and verification results. Production remains unchanged.

## Home activation (2026-11-05)

Published and installed the isolated candidate
`jena-0.2.17-rc1-a7b5d97ba17b-amd64` at digest
`sha256:a1f9b384929050910e13db74bacc876add2f7cb750f1f6531e10fd341bac3ecf`.
The native AMD64 build uses the frozen allowlisted source context. The running
worker source hash matches it. The first rollout used the guarded empty-registry
legacy shutdown, then the new worker passed a real SIGTERM stop (0.159 seconds,
exit zero) and restart. Its installed ordinary stop timeout is 900 seconds.

All 391 media tests pass (20 skipped, four subtests); four deployment checks and
96 setup cases (92 passed, four skipped) pass. Three packaged signal scenarios
and 26 live API/media checks pass. SIPI and Caddy IDs/start times are unchanged.
No productive tag or deployment was changed. The full mobile processing test
uses the durable registry with fake media/API effects; no real user upload was
interrupted on home.
