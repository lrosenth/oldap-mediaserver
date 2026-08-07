# ZIP Import Operations Runbook

## Purpose and operating model

This runbook is the authoritative operational procedure for the lean OLDAP ZIP
import MVP. It covers deployment, backup, retention, incident response, and
recovery across `oldap-mediaserver`, `oldap-api`, GraphDB, and FasnachtsPage.

The deployment has one media VM with 8 vCPUs, 16 GiB RAM, and an extensible
approximately 1-TB ext4 volume mounted at `/data`. The ingest worker is global
and sequential, limited to 4 vCPUs, 6 GiB RAM, and 128 PIDs. There is no message
broker or additional database.

This document distinguishes three kinds of instruction:

- **Automated**: implemented and safe to rely on now.
- **Operator procedure**: a deliberate action by the VM/application owner.
- **Open control**: must be agreed or implemented before production pilot.

## Ownership and escalation

| Responsibility | Primary owner |
| --- | --- |
| Media VM, Docker deployment, disk capacity, first response | Designated VM/application owner |
| OLDAP API, ImportJob state, authorization, quota, GraphDB transaction | OLDAP application owner |
| Hypervisor, university backup, network, central logging, Defender decision | University IT Services |
| User communication and decision to retry/cancel an import | Project support/application owner |

Record the current names, telephone numbers, and university escalation channel
in the protected operations inventory. Do not put personal contact details or
secrets in this Git repository.

## Authoritative storage inventory

Production defaults are defined in `ansible/group_vars/all.yml`.

| Host path | Container path | Contents | Backup class |
| --- | --- | --- | --- |
| `/data/media` | `/data/images` | Final originals, derivatives, asset owner markers, IIIF cache | Critical, except reproducible cache |
| `/data/oldap-ingest` | `/data/ingest` | Temporary SIP, extraction, parser and import work | Temporary; exclude from routine backup where possible |
| `/data/oldap-import-records` | `/data/import-records` | Immutable manifest, report, checksums, validation/import failure evidence | Critical audit evidence |
| `/opt/oldap-mediaserver/compose` | `/opt/.../compose` | Rendered Compose/Caddy config and root-only environment files | Rebuild from Git/Vault; protect as secrets if backed up |
| `/opt/oldap-mediaserver/caddy-data` | Caddy `/data` | ACME state | Operationally useful, replaceable |
| GraphDB import/data graphs | API/GraphDB | ImportJob state, quota, staging hierarchy and MediaObjects | Critical; must be restored coherently with media |

The ingest root must never be mounted into Caddy or Cantaloupe. The retained
record root must remain outside both ingest and delivery roots.

## Routine checks

Perform these checks before deployment and at least weekly during a pilot:

```bash
sudo docker compose -f /opt/oldap-mediaserver/compose/docker-compose.yml ps
curl --fail --silent --show-error https://media.oldap.org/health
df -h /data
df -i /data
sudo docker compose -f /opt/oldap-mediaserver/compose/docker-compose.yml logs --since 24h --no-color mediaserver ingest-worker
```

Expected results:

- `/health` reports `status=ok`, service `oldap-mediahelper`, and the deployed
  immutable component version;
- all intended base services are running;
- the ingest worker is running only when ZIP import has been deliberately
  enabled;
- free space remains above the mandatory 20% reserve;
- no repeating `ingest_worker_attempt_failed`, `ingest_capacity_blocked`,
  heartbeat failure, callback failure, or cleanup failure appears.

Container logs may be forwarded to university logging. Never add tokens,
filenames, report content, email addresses, or parser stderr to operational log
messages.

## Deployment

### 1. Pre-deployment gate

Before changing the test or production system:

1. Confirm the change is reviewed and all affected repository tests pass.
2. Confirm immutable mediahelper and imageserver version tags exist; never
   deploy `latest`.
3. Run `make show-versions` from the repository root and record both versions
   in the change ticket.
4. Confirm the matching five purpose-specific JWT secrets are available from
   the encrypted authentication Vault. Never paste them into a ticket or log.
5. Check `/data` space/inodes and verify that no active import is in
   `IMPORTING` before a planned disruptive change.
6. Confirm a recent successful university backup and the last restore-test date.

### 2. Test deployment

Deploy to the home test system first:

```bash
make deploy-test
```

The Ansible playbook validates secret separation, storage boundaries, rendered
Compose syntax, the public mediahelper health/version, and a tokenless IIIF
authorization probe that must return `401`.

Then perform one small authenticated ZIP exercise covering upload, READY report,
confirmation, IMPORTED, and cleanup. Use synthetic/non-sensitive material.

### 3. Production deployment

After the test evidence is recorded:

```bash
make deploy-production
```

Standard deployment starts the base media stack. The ZIP worker remains behind
the `zip-import-validation` Compose profile until the separate feature/pilot
gate is approved. For an explicitly approved pilot, start it on the VM with:

```bash
cd /opt/oldap-mediaserver/compose
sudo docker compose --profile zip-import-validation up -d ingest-worker
sudo docker compose ps
```

Stop new ZIP processing without deleting data or state:

```bash
cd /opt/oldap-mediaserver/compose
sudo docker compose stop ingest-worker
```

Stopping the worker is the preferred maintenance switch. Claims expire after
their API lease and are safely reclaimed when the worker returns.

### 4. Post-deployment verification

Verify:

- public `/health` and expected version;
- tokenless IIIF probe returns `401`, not an image or `200`;
- media and API can reach one another in both required directions;
- the worker has only the intended three volume mounts and resource limits;
- a small normal single-file upload still stores a checksum;
- if the ZIP feature is enabled, one small valid and one invalid synthetic ZIP
  reach the expected terminal states.

### Rollback

Prefer a version rollback using the last known immutable tags:

```bash
make deploy-production MEDIAHELPER_TAG=vX.Y.Z IMAGESERVER_TAG=vA.B.C
```

Do not roll back GraphDB schema/state or media files merely because an
application image is rolled back. If the older application is incompatible
with already committed state, stop the worker and escalate rather than forcing
the deployment.

`rollback=true` removes the running Compose stack and causes an outage; it does
not delete bind-mounted data, but it is not the normal version rollback.

## Backup and restore policy

### Backup scope

The current university backup runs every 24 hours to a separate system. This
implies a current infrastructure recovery-point objective of up to 24 hours;
no recovery-time objective has yet been agreed.

Required backup content:

- `/data/media`, excluding `/data/media/cache` when supported;
- `/data/oldap-import-records`;
- GraphDB repositories containing OLDAP data, MediaObjects, staging resources,
  ImportJobs, quota and import event evidence;
- encrypted Vault/authentication source and the Git repositories through their
  own protected backup process;
- Caddy state if preserving ACME continuity is desired.

Exclude `/data/oldap-ingest` from routine backup where the university system
supports path exclusions. It contains temporary user payloads and is neither
the authoritative archive nor required after successful import. Until IT
confirms the exclusion, treat temporary SIPs as potentially present in daily VM
backup retention and include that fact in the privacy/security record.

Do not create ad-hoc copies of SIPs on personal computers or shared drives.

### Consistency

GraphDB and ext4 do not share an atomic snapshot. A normal daily infrastructure
backup is therefore crash-consistent, not an application transaction. Recovery
uses immutable checksums, ImportJob events, owner markers, and deterministic
replay to reconcile it.

For a planned application-consistent backup or restore test:

1. Stop the ingest worker.
2. Prevent new media uploads during the snapshot window or schedule a short
   maintenance window.
3. Complete/abort no manual GraphDB transaction; allow in-flight API requests to
   finish.
4. Snapshot GraphDB and the critical filesystem roots within the same recorded
   window.
5. Resume services and record snapshot identifiers/timestamps.

### Restore test

Before the first production pilot, perform one restore into disposable test
infrastructure. Repeat after material storage/schema changes and on the cadence
agreed with university IT.

The test must prove:

- GraphDB starts and ImportJobs can be read;
- retained manifests/reports match their recorded SHA-256 values;
- at least one imported MediaObject resolves to an existing final original and
  derivative;
- authorization still protects assets and reports;
- the worker can safely reclaim an expired test claim;
- no temporary ingest backup is needed to serve already imported material.

## Retention

### Implemented temporary-payload retention

| State/data | Implemented behavior |
| --- | --- |
| Interrupted `.part-*` upload | Removed after 24 hours, maximum 100 per maintenance pass |
| Stale `UPLOADING` job | Cleanup-eligible after 24 hours; API claim and deletion proof required |
| `INVALID` validation | SIP and extracted/work data deleted before INVALID is published |
| `FAILED` validation/import | Temporary data deleted before terminal failure publication where required by the failure contract |
| `READY` | Temporary validated payload retained until displayed `expiresAt`, normally seven days |
| `IMPORTING` | Never expiry-cleaned |
| `IMPORTED` | SIP, extraction and job work removed after successful commit through API-claimed cleanup |
| `CANCELLED` / `EXPIRED` | Temporary payload removed through API-claimed cleanup |

### Retained record policy and current gap

The agreed policy is:

- INVALID and FAILED job/report records: 90 days;
- EXPIRED and CANCELLED job/report records: 30 days;
- IMPORTED manifest, report, checksums and mapping: retained with the staging or
  archival record.

**Open control:** automatic 30-/90-day deletion of API ImportJob records and
`/data/oldap-import-records` is not implemented. Current behavior retains these
records indefinitely. Until an API-owned, event-bound pruning operation exists:

- do not delete record directories by filesystem age;
- do not delete only the API job or only the media record copy;
- treat indefinite retention as the safer consistency default;
- record the gap in the pilot approval and implement pruning before claiming
  full enforcement of D-011.

## Incident response

### Severity

| Level | Examples | Initial response |
| --- | --- | --- |
| SEV-1 | Suspected compromise, unauthorized access, corrupt/overwritten originals, filesystem near exhaustion | Stop ingest worker; stop upload service if writes threaten evidence/capacity; contact university IT and application owner immediately |
| SEV-2 | Job stuck, repeating worker crash, API/media outage, cleanup not completing, restore inconsistency | Stop worker if failures repeat; preserve logs/state; investigate within the same working day |
| SEV-3 | Email failure, delayed READY report, isolated user error with authoritative state intact | Keep polling authoritative; handle through normal support |

### First-response checklist

1. Record UTC time, import ID, observed public state, affected user/project, and
   the last known action. Do not record bearer tokens or full filenames.
2. Stop the ingest worker if continued processing may change evidence:

   ```bash
   cd /opt/oldap-mediaserver/compose
   sudo docker compose stop ingest-worker
   ```

3. Capture bounded logs and current capacity:

   ```bash
   sudo docker compose logs --since 2h --no-color mediaserver ingest-worker
   df -h /data
   df -i /data
   sudo docker compose ps
   ```

4. Check the authoritative ImportJob through authenticated API/operator tooling.
   Filesystem presence alone never determines lifecycle state.
5. Preserve owner markers, manifests, reports and checksums. Never rename,
   replace, or manually merge asset directories.
6. Escalate suspected host/parser compromise to university IT. Do not open or
   copy the suspicious payload onto a workstation.

### Scenario playbooks

#### Low disk or inode exhaustion

- The ZIP path rejects new work before crossing its reserve, but stop both the
  worker and mediahelper if the whole volume is still approaching exhaustion;
  normal single-file uploads share the volume.
- Identify growth by the three explicit roots, not by deleting guessed orphans.
- Cache can be regenerated, but purge it only during a maintenance window and
  only with the separately documented cache procedure.
- Extend the logical volume or obtain an approved additional volume. Resume the
  worker only after the reserve is restored.

#### Worker repeatedly fails or job remains IMPORTING

- Stop the worker after repeated identical failures.
- Inspect `ingest_worker_attempt_failed`, heartbeat, capacity and API response
  classes without exposing content.
- Wait for the five-minute claim lease to expire before expecting another
  worker/claim to own the job.
- Restart once after correcting the cause. Deterministic asset/commit replay is
  the recovery mechanism; never reset the job state manually.

#### API unavailable or callback pending

- Keep durable SIP/record evidence intact. Media callbacks and job results are
  replayed idempotently.
- Restore API/GraphDB service, then allow the bounded reconciler/worker to retry.
- Email is not authoritative; users can continue through the authenticated job
  page when lifecycle state is available.

#### Cleanup failed after data deletion

- Do not recreate an empty SIP directory.
- Allow the API lease to expire and the cleanup task to be reclaimed.
- Deleting an already absent canonical payload is an idempotent success; the new
  deletion proof completes API state.

#### Suspected malicious file or parser exploit

- Stop the worker and block further ZIP processing.
- If host compromise is plausible, isolate the VM through university IT rather
  than investigating the file interactively.
- Preserve logs, container/image digest, import ID, job state and backup
  timestamps. Follow university incident and data-protection procedures.
- Rotate purpose-specific secrets and redeploy API/media together if credential
  exposure cannot be excluded.

#### Email delivery failure

- Verify the ImportJob state and protected report first.
- The API retries at most three submissions with five-minute spacing.
- Do not retry or roll back an import solely because SMTP failed.

## Recovery

### Container or VM restart

Containers use `restart: unless-stopped`. After a VM restart:

1. Verify Docker and the base services.
2. Verify `/data` is mounted before allowing containers to write.
3. Keep the ZIP worker stopped until API and GraphDB are healthy.
4. Let existing leases expire; then start the worker and observe one claim.
5. Confirm cleanup/reconciliation completes without manual directory changes.

### Full data restore

1. Declare a maintenance incident and stop write services.
2. Record the exact backup timestamps for GraphDB, `/data/media`, and
   `/data/oldap-import-records`.
3. Restore into a disposable environment first when time permits.
4. Restore GraphDB and both critical filesystem roots from the closest coherent
   backup window. Do not restore `/data/oldap-ingest` unless incident analysis
   explicitly requires temporary evidence.
5. Restore ownership and access boundaries: ingest and record roots are root
   owned mode `0700`; delivery data must remain writable only by intended
   services.
6. Start GraphDB/API, then mediahelper/imageserver/Caddy. Keep worker stopped.
7. Verify health, authorization, representative original/derivative existence,
   manifest/report digests, and disk reserve.
8. Review nonterminal ImportJobs. Allow stale leases to expire and use normal
   deterministic replay; never force states in GraphDB.
9. Start the worker and monitor the first recovered VALIDATE/IMPORT/CLEANUP task.
10. Record data loss against the 24-hour RPO and communicate affected imports.

If GraphDB refers to a missing final asset or an asset exists without provable
job ownership after restore, stop recovery for that job and escalate. Never
overwrite an existing asset or synthesize success from filename similarity.

## Pre-pilot operational checklist

- [ ] Named owners and escalation contacts recorded outside Git.
- [ ] University backup scope confirmed, including ingest exclusion behavior.
- [ ] Restore drill completed with recorded evidence.
- [ ] Recovery-time objective agreed; current recovery-point objective accepted.
- [ ] University response on Defender/Linux `/data` documented.
- [ ] Central log access and retention confirmed.
- [ ] Record-pruning gap accepted or API-owned 30-/90-day pruning implemented.
- [ ] Worker feature gate and rollback tested on `media.home.org`.
- [ ] One valid, invalid, expired, cancelled, and recovered import exercised.
- [ ] Production pilot window, support contact, and stop criteria agreed.
