# One-off legacy TIFF repair

`scripts/repair_image_derivatives.py` audits `*/derived/master.tif` recursively.
The default is read-only. `--apply` regenerates only derivatives that fail the
existing upload TIFF header contract, using the same `DerivativeProcessor` and
normalizer. Compression remains **none**; compression benchmarking is separate.
This is a maintenance script, not an API, worker, or automatic startup migration.

The audit checks all pyramid IFDs: orientation, channels/alpha, sample type/depth,
compression, tile size, profile consistency and pyramid geometry. It does not
fully decode every compatible image or certify ICC correctness/visual quality.
Missing derivatives, other derivative names, and symlinked directories are not
traversed/repaired. An explicitly selected asset that is absent returns an error.
A failure of the header contract can include TIFFs SIPI could otherwise read
(e.g. losslessly compressed TIFFs); this tool targets the current upload contract.

For repair, exactly one entry must exist in the sibling `original/` directory
(`.DS_Store` and macOS AppleDouble `._*` sidecars are ignored and left untouched). Ambiguous originals, symlinked files, unsupported sources
and conversion failures are reported, not guessed. IDs, filenames, originals and
GraphDB are unchanged. No network/API access or credentials are needed.

## Run on the media VM

Copy the script to a convenient operator directory, e.g. `/opt/repair_image_derivatives.py`.
Use the current mediahelper image containing image normalization (v0.2.15 here).
No image rebuild or host Python/libvips installation is required. The script
overrides the converter loader hint to random access with revalidation, including
when the packaged converter still requests sequential reading. This is required
for large rotated JPEGs and avoids stale decoder entries on reused paths. Run the audit:

```sh
sudo docker run --rm --network none \
  --mount type=bind,src=/data/media,dst=/data/media,readonly \
  --mount type=bind,src=/opt/repair_image_derivatives.py,dst=/repair.py,readonly \
  --entrypoint python lrosenth/oldap-mediahelper:v0.2.15 \
  /repair.py /data/media > repair-audit.jsonl
```

Each output line is JSON: `compatible`, `needs_repair`, `repaired`, or `error`,
followed by a summary. Exit 0 means no operational errors (a dry run can still
report `needs_repair`); exit 1 means one or more failures. Argument errors return 2.
Records are flushed immediately. Keep the report outside the served media root.

Before **applying**, pause uploads/imports/mobile commits and any other repository
writers. Run only one repair process. SIPI may continue reading; a request already
reading the replaced derivative can need a retry. File fingerprints detect common
concurrent changes but are not a substitute for this maintenance window.
Ensure space for the old backup plus a new uncompressed pyramid. Use an
operator-controlled backup directory **outside** `/data/media` and outside public
Caddy mounts. Pilot the known orientation-8 asset first:

```sh
sudo install -d -m 0700 /data/media-repair-backup
sudo docker run --rm --network none \
  --mount type=bind,src=/data/media,dst=/data/media \
  --mount type=bind,src=/data/media-repair-backup,dst=/backup \
  --mount type=bind,src=/opt/repair_image_derivatives.py,dst=/repair.py,readonly \
  --entrypoint python lrosenth/oldap-mediahelper:v0.2.15 \
  /repair.py /data/media --apply --backup-dir /backup \
  --asset-id 0R9AFPvCTnMn > repair-pilot.jsonl
```

Check the report and actual IIIF image/orientation. Remove `--asset-id` for the
complete run; it may also be repeated to select several IDs. Use separate reports.
On the laptop, bind the repository's `data` directory instead of `/data/media`.
The script runs as container root to preserve each derivative's UID/GID and mode;
originals are only read. Run Home first, then the production media host.

## Publication, retry and recovery

Each replacement is generated in a unique temporary directory beside the target,
validated, and flushed. The original's SHA-256 is checked before/after conversion.
The previous TIFF is copied to the backup tree at the same relative path, hashed
and flushed before atomic replacement. UID/GID/mode are preserved; new timestamps
are intentional. ACLs/xattrs of the replaced derivative are not copied. The report
contains original/previous/new hashes and the backup path inside the container.
SIPI source-version checks invalidate old cached derivatives; no global cache wipe
is needed. Browser reload can be necessary. Compression and broad reconversion
of otherwise compatible images remain separate decisions.

Re-running skips compatible derivatives. A backup is never overwritten: it is
reused only when its hash matches the current old TIFF. A conflicting/incomplete
backup causes an error; retain it for diagnosis and choose a fresh backup directory.
Ordinary failures clean only the temporary directory owned by that operation.
A hard interruption can leave `.sipi-repair-*` directories; inspect them before
manual cleanup. An error after atomic replacement (e.g. directory fsync failure)
can mean publication already occurred: inspect the actual target and backup.
Keep backups until visual acceptance. To roll back, copy the corresponding backup
to a temporary sibling of `master.tif`, preserve ownership/mode and atomically rename
it over the target. Never restore over the original source file.

## Verification

`poetry run pytest -q` includes read-only audit, missing selection, ambiguous and
symlinked originals, conversion failure, and native repair/backup/idempotence cases.
Native cases require libvips; run them with the repository mounted read-only:

```sh
docker run --rm --network none -v "$PWD:/review:ro" -w /review \
  --entrypoint python lrosenth/oldap-mediahelper:v0.2.15 \
  -m unittest discover -s tests -p test_repair_image_derivatives.py -v
```
