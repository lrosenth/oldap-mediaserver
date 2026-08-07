# Secure ZIP Import Fixture Catalogue v1

## Purpose

This catalogue defines what must be tested, how fixtures may be obtained, which
tests are safe by default, and the expected stable result. It does not require a
project team member to handcraft rejected formats or dangerous archives.

The future fixture generator should emit a small machine-readable index with at
least `id`, `sha256`, `construction`, `tier`, `expectedState`, `expectedCodes`,
and `sourceLicence`. Binary fixtures without provenance and an expected result
are not accepted into the repository.

## Test tiers

| Tier | Default | Envelope | Purpose |
| --- | --- | --- | --- |
| T0 unit | yes | normally below 1 MiB and 5 seconds | parser policy, paths, names, MIME/codec facts, state rules |
| T1 integration | yes in dedicated CI | below 50 MiB and 60 seconds | real parsers, derivatives, container limits, API/media flow |
| T2 scaled boundary | scheduled | small data with injected lower limits | +1-byte/count/ratio/time boundary behavior without huge artifacts |
| T3 operator only | never automatic | real 500 MB/3 GB, EICAR, disk pressure, kill/restart, backup | deployment and incident-readiness proof in a disposable environment |

T3 requires an explicit target directory, free-space check, operator approval,
and cleanup verification. It is never run against production data roots.

## Fixture construction strategy

### ZIP structure and malicious metadata

Use deterministic Python builders in temporary directories. `zipfile.ZipInfo`
is sufficient for ordinary entries, names, compression, and Unix attributes.
Small `struct`-based helpers may mutate central/local headers, offsets, flags,
CRC, or ZIP64 markers. Generators write bytes only; tests never invoke generic
`unzip`/`extractall()` on hostile fixtures.

Compression bombs use highly compressible bounded data and deliberately reduced
test limits. The validator must abort while streaming as soon as the injected
limit is crossed. No committed fixture expands to gigabytes.

### Valid accepted media

Generate tiny baseline files with the same runtime libraries/CLI tools used by
the product, then add a few real-world samples supplied by the team to catch
metadata and camera/software variation. Every real sample must be non-sensitive,
redistributable, and checksum-documented.

### Valid but rejected formats

Rejected detection needs structurally valid files, not random extensions. They
can be produced without the user manually collecting them:

| Family | Safe source/generator |
| --- | --- |
| GIF, BMP, WebP, HEIC/AVIF where available | tiny generated image through Pillow/libvips or the format's reference encoder |
| OGG/Opus, AAC/M4A, AIFF | FFmpeg synthetic sine source |
| AVI, MOV, MKV, HEVC/VP9/AV1 MP4 | FFmpeg color/sine generators with one-second duration |
| DOCX, XLSX, PPTX, ODT | minimal document exported by LibreOffice in a disposable fixture-build container; OOXML also verifies nested-ZIP classification |
| RTF, HTML, SVG, XML, JSON, CSV | deterministic small text generators with correct syntax/content type |
| TAR, GZIP, 7z, RAR | standard archive tools in the fixture-build container; no external payloads |
| Executable/script | harmless minimal format sample or plain script text; never execute it |
| Non-PDF/A, encrypted, attached, or active PDF | generated with a PDF fixture tool and checked with veraPDF/qpdf; no operational secrets |

Upstream conformance corpora may be used only after licence/provenance review and
must be pinned by source URL, upstream revision, licence, and SHA-256. Random
files from the internet are not acceptable fixtures.

## A. Accepted baseline and reporting

| ID | Fixture | Expected | Tier |
| --- | --- | --- | --- |
| OK-001 | Single ASCII root JPEG, stored | `READY`, direct target-root media | T0 |
| OK-002 | UTF-8/NFC directory plus deflated PNG | `READY`, one new staging folder | T0 |
| OK-003 | Five ZIP directory levels | `READY`, depth boundary accepted | T0 |
| OK-004 | Empty directories mixed with files | `READY`, empty folders preserved | T0 |
| OK-005 | JPEG, single-page TIFF, PNG in one archive | `READY` | T1 |
| OK-006 | WAV/PCM mono and stereo, FLAC stereo, MP3 stereo | `READY` after final audio matrix | T1 |
| OK-007 | MP4 with one H.264 stream and no audio | `READY` | T1 |
| OK-008 | MP4 with one H.264 and one stereo AAC stream | `READY` | T1 |
| OK-009 | PDF/A-1 and PDF/A-2 at supported conformance levels | `READY` | T1 |
| OK-010 | UTF-8 and pure ASCII text | `READY` | T0 |
| OK-011 | `.DS_Store`, `__MACOSX`, AppleDouble and `Thumbs.db` plus valid media | `READY`, `PACKAGING_ARTIFACT_IGNORED` | T0 |
| OK-012 | Existing media has same NFC/case collision key | `READY`, `TARGET_MEDIA_NAME_COLLISION` warning | T1 |
| OK-013 | Extension disagrees but detected content is otherwise allowed | `READY`, `EXTENSION_CONTENT_MISMATCH` warning | T0 |
| OK-014 | Identical internal event replay | original success returned, no duplicate | T0 |
| OK-015 | Finalized SIP PUT replay | persisted receipt returned, SIP unchanged | T1 |

## B. ZIP envelope and malformed archive rejection

| ID | Fixture | Expected stable code | Tier |
| --- | --- | --- | --- |
| ZIP-001 | Random/non-ZIP body with `.zip` name | `ZIP_FORMAT_UNSUPPORTED` or HTTP 415 before validation | T0 |
| ZIP-002 | Truncated end-of-central-directory | `ZIP_FORMAT_UNSUPPORTED` | T0 |
| ZIP-003 | Self-extracting bytes before first local header | `SELF_EXTRACTING_ZIP_NOT_ALLOWED` | T0 |
| ZIP-004 | Small archive carrying ZIP64 fields | `ZIP64_NOT_ALLOWED` | T0 |
| ZIP-005 | Multi-disk/split markers | `MULTI_DISK_NOT_ALLOWED` | T0 |
| ZIP-006 | Traditional ZipCrypto entry | `ENCRYPTED_ENTRY` | T1 |
| ZIP-007 | AES-encrypted entry | `ENCRYPTED_ENTRY` | T1 |
| ZIP-008 | BZIP2 compression method | `UNSUPPORTED_COMPRESSION_METHOD` | T0 |
| ZIP-009 | LZMA/Zstandard/Deflate64 method | `UNSUPPORTED_COMPRESSION_METHOD` | T0 |
| ZIP-010 | Nested ZIP containing an otherwise valid JPEG | `NESTED_ARCHIVE_NOT_ALLOWED` | T0 |
| ZIP-011 | Declared CRC differs from actual content | `ZIP_CRC_MISMATCH` | T0 |
| ZIP-012 | Local filename differs from central-directory filename | `ZIP_FORMAT_UNSUPPORTED` | T0 |
| ZIP-013 | Local/central compressed sizes disagree | `ZIP_FORMAT_UNSUPPORTED` | T0 |
| ZIP-014 | Entry byte ranges overlap or point into central directory | `ZIP_FORMAT_UNSUPPORTED` | T0 |
| ZIP-015 | Duplicate exact path in two central entries | `DUPLICATE_PATH` | T0 |
| ZIP-016 | Data descriptor is internally inconsistent | `ZIP_FORMAT_UNSUPPORTED` | T0 |
| ZIP-017 | Archive comment with safe archive | `ARCHIVE_COMMENT_IGNORED`, otherwise `READY` | T0 |
| ZIP-018 | Empty ZIP or packaging-artifacts-only ZIP | `NO_IMPORTABLE_CONTENT`; `INVALID` | T0 |

## C. Paths, entry types, names, and collisions

| ID | Fixture | Expected stable code | Tier |
| --- | --- | --- | --- |
| PATH-001 | `../escape.jpg` | `PARENT_TRAVERSAL` | T0 |
| PATH-002 | `a/../../escape.jpg` | `PARENT_TRAVERSAL` | T0 |
| PATH-003 | `/absolute.jpg` | `ABSOLUTE_PATH` | T0 |
| PATH-004 | `C:\\escape.jpg` | `ABSOLUTE_PATH` | T0 |
| PATH-005 | `\\\\server\\share\\escape.jpg` | `ABSOLUTE_PATH` | T0 |
| PATH-006 | Mixed `a\\..\\escape.jpg` separators | `PARENT_TRAVERSAL` | T0 |
| PATH-007 | NUL in filename metadata | `NUL_IN_NAME` | T0 |
| PATH-008 | Unix symlink entry | `SYMLINK_NOT_ALLOWED` | T0 |
| PATH-009 | FIFO, device, socket, or unknown special mode | `SPECIAL_FILE_NOT_ALLOWED` | T0 |
| PATH-010 | Reserved portable name such as `CON` or `NUL.txt` | `RESERVED_NAME` | T0 |
| PATH-011 | Control or bidi-control character in name | `RESERVED_NAME` | T0 |
| PATH-012 | Non-ASCII legacy filename without unambiguous UTF-8 | `INVALID_NAME_ENCODING` | T0 |
| PATH-013 | NFC/NFD equivalents in same parent | `NAME_NORMALIZATION_COLLISION` | T0 |
| PATH-014 | `Photo.jpg` and `photo.jpg` in same parent | `CASE_COLLISION` | T0 |
| PATH-015 | Same normalized path used as file and directory | `FILE_DIRECTORY_CONFLICT` | T0 |
| PATH-016 | UTF-8 segment exactly 255 bytes | accepted if otherwise valid | T0 |
| PATH-017 | UTF-8 segment 256 bytes | `PATH_SEGMENT_LENGTH_LIMIT` | T0 |
| PATH-018 | Relative path exactly 1,024 UTF-8 bytes | accepted if otherwise valid | T0 |
| PATH-019 | Relative path 1,025 UTF-8 bytes | `PATH_LENGTH_LIMIT` | T0 |
| PATH-020 | Six ZIP directory levels | `PATH_DEPTH_LIMIT` | T0 |
| PATH-021 | Existing child folder has same portable collision key | `TARGET_FOLDER_COLLISION` | T1 |
| PATH-022 | Target child appears after READY but before confirmation | API `IMPORT_TARGET_CHANGED`/conflict, no import side effect | T1 |

## D. Resource-exhaustion and boundary cases

| ID | Fixture/scenario | Expected stable result | Tier |
| --- | --- | --- | --- |
| LIMIT-001 | 10,000 tiny entries | boundary accepted if all other rules pass | T2 |
| LIMIT-002 | 10,001 entries | `ENTRY_COUNT_LIMIT`, bounded incomplete inventory | T2 |
| LIMIT-003 | One entry ratio exactly 100:1 | boundary accepted | T2 |
| LIMIT-004 | One entry ratio above 100:1 | `COMPRESSION_RATIO_LIMIT`, streaming abort | T2 |
| LIMIT-005 | Aggregate ratio exactly 50:1 | boundary accepted | T2 |
| LIMIT-006 | Aggregate ratio above 50:1 | `COMPRESSION_RATIO_LIMIT` | T2 |
| LIMIT-007 | Individual/aggregate extracted bytes at configured boundary | accepted | T2 scaled; T3 real |
| LIMIT-008 | Individual file exceeds configured boundary by one byte | `ENTRY_SIZE_LIMIT` | T2 scaled; T3 real |
| LIMIT-009 | Aggregate extracted bytes exceed boundary by one byte | `EXTRACTED_TOTAL_LIMIT` | T2 scaled; T3 real |
| LIMIT-010 | Upload body exceeds 500,000,000 actual bytes despite smaller declared length | HTTP 413, no finalized SIP | T3 |
| LIMIT-011 | Free-volume reserve would be crossed | HTTP 507 / `IMPORT_PHYSICAL_CAPACITY_INSUFFICIENT` | T2 simulated |
| LIMIT-012 | Parser exceeds per-tool deadline | blocking parser/timeout result; child killed | T1 |
| LIMIT-013 | Job exceeds six-hour wall deadline | `VALIDATION_TIMEOUT`, process group killed, payload deleted before `FAILED`, exact replay | T0 reduced deadline plus T2 child-process integration |
| LIMIT-014 | Parser attempts memory beyond cgroup | child/worker fails boundedly; host remains healthy; `FAILED` | T2/T3 |
| LIMIT-015 | Parser forks beyond PID limit or emits unbounded output | terminated/truncated; `FAILED` | T2 |
| LIMIT-016 | Parser attempts to read inherited service secret or API client | no client/claim argument; closed environment contains no secret | T0 spawn boundary |
| LIMIT-017 | Parser or decoder attempts network socket use | `EPERM` under inherited seccomp; validation cannot exfiltrate | T1 Linux image |
| LIMIT-018 | Parser attempts privileged filesystem/process action | fixed UID/GID 65532, empty supplementary groups, zero effective capabilities | T1 Linux image |
| LIMIT-016 | Slow job followed by another user's job | second remains queued; no parallel validation | T1 |

## E. Content, codec, and document policy

| ID | Fixture | Expected stable code/result | Tier |
| --- | --- | --- | --- |
| MEDIA-001 | Truncated/corrupt JPEG | parser failure or `UNSUPPORTED_MEDIA_TYPE`; `INVALID` | T0 |
| MEDIA-002 | JPEG above 100 MP | `IMAGE_PIXEL_LIMIT` | T1 |
| MEDIA-003 | Image axis above 30,000 | `IMAGE_AXIS_LIMIT` | T1 |
| MEDIA-004 | Multi-page TIFF | `MULTIPAGE_TIFF_NOT_ALLOWED` | T1 |
| MEDIA-005 | GIF, BMP, WebP, HEIC, AVIF, SVG, camera RAW | `UNSUPPORTED_MEDIA_TYPE` | T1 |
| MEDIA-006 | WAV with three or more channels | `AUDIO_CHANNEL_LIMIT` | T1 |
| MEDIA-007 | WAV with ADPCM, float, or other unapproved codec | `AUDIO_CODEC_UNSUPPORTED` | T1 |
| MEDIA-007A | WAV PCM outside 8/16/24/32 bits or 8–192 kHz | `AUDIO_BIT_DEPTH_UNSUPPORTED` or `AUDIO_SAMPLE_RATE_UNSUPPORTED` | T1/T2 |
| MEDIA-008 | FLAC with more than two channels | `AUDIO_CHANNEL_LIMIT` | T1 |
| MEDIA-008A | FLAC outside 8/16/24 bits or 8–192 kHz | `AUDIO_BIT_DEPTH_UNSUPPORTED` or `AUDIO_SAMPLE_RATE_UNSUPPORTED` | T1/T2 |
| MEDIA-009 | Corrupt MP3 or implausible metadata | parser/codec error; `INVALID` | T1 |
| MEDIA-009A | MP3 outside 8–48 kHz | `AUDIO_SAMPLE_RATE_UNSUPPORTED` | T1/T2 |
| MEDIA-010 | OGG/Opus, AAC/M4A, AIFF | `UNSUPPORTED_MEDIA_TYPE` | T1 |
| MEDIA-011 | MP4 with HEVC, AV1, VP9, or MPEG-4 Part 2 video | `VIDEO_CODEC_UNSUPPORTED` | T1 |
| MEDIA-011A | H.264 outside Baseline/Main/High, above level 5.2, above 8-bit, or not 4:2:0 | `VIDEO_CODEC_UNSUPPORTED` | T1/T2 |
| MEDIA-012 | MP4 with non-AAC audio | `VIDEO_AUDIO_CODEC_UNSUPPORTED` | T1 |
| MEDIA-012A | MP4 with AAC profile other than LC or more than two audio channels | `VIDEO_AUDIO_CODEC_UNSUPPORTED` or `AUDIO_CHANNEL_LIMIT` | T1 |
| MEDIA-013 | More than one video or audio stream | `VIDEO_STREAM_LAYOUT_UNSUPPORTED` | T1 |
| MEDIA-014 | Subtitle, data, or attachment stream | `VIDEO_STREAM_LAYOUT_UNSUPPORTED` | T1 |
| MEDIA-015 | Width/height, fps, or duration just above limit | matching video limit code | T2 scaled |
| MEDIA-016 | AVI, MOV, MKV, WebM | `UNSUPPORTED_MEDIA_TYPE` | T1 |
| PDF-001 | Ordinary valid PDF without PDF/A conformance | `PDF_NOT_PDFA_1_OR_2` | T1 |
| PDF-002 | False PDF/A metadata declaration | `PDF_NOT_PDFA_1_OR_2` | T1 |
| PDF-003 | PDF/A-3 or PDF/A-4 | `PDF_NOT_PDFA_1_OR_2` | T1 |
| PDF-004 | Encrypted/password-protected PDF | `PDF_ENCRYPTED` | T1 |
| PDF-005 | PDF with JavaScript, Launch, or rich media | `PDF_ACTIVE_CONTENT` | T1 |
| PDF-006 | PDF with any embedded/attached file | `PDF_ATTACHMENT_NOT_ALLOWED` | T1 |
| PDF-007 | Malformed PDF/A that stresses validator/renderer | bounded parser failure, never `READY` | T1 |
| TEXT-001 | Invalid UTF-8/Latin-1/UTF-16 | `TEXT_INVALID_UTF8` | T0 |
| TEXT-002 | Text exactly 1 MiB | accepted | T2 |
| TEXT-003 | Text 1 MiB plus one byte | `TEXT_SIZE_LIMIT` | T2 |
| OTHER-001 | Valid DOCX/XLSX/PPTX/ODT | `NESTED_ARCHIVE_NOT_ALLOWED` or `UNSUPPORTED_MEDIA_TYPE`, fully reported | T1 |
| OTHER-002 | RTF, HTML, SVG, XML, JSON, CSV detected as a specific structured format | `UNSUPPORTED_MEDIA_TYPE`; never downgrade to generic text | T0 |
| OTHER-003 | TAR/GZIP/7z/RAR | `NESTED_ARCHIVE_NOT_ALLOWED` or `UNSUPPORTED_MEDIA_TYPE` | T1 |
| OTHER-004 | ELF/PE executable or content detected as a shell/Python script | `UNSUPPORTED_MEDIA_TYPE`; never execute | T0 |

## F. Authorization, capability, quota, and race tests

| ID | Scenario | Expected | Tier |
| --- | --- | --- | --- |
| AUTH-001 | User lacks `ADMIN_CREATE` | 403 `IMPORT_PERMISSION_DENIED` | T0 |
| AUTH-002 | Effective staging-area role below `DATA_UPDATE` | 403 | T0 |
| AUTH-003 | Target folder belongs to another staging area/project | 403/409 without existence leak | T0 |
| AUTH-004 | User reads another user's non-visible job/report | indistinguishable 404/403 policy | T0 |
| CAP-001 | Missing, expired, wrong issuer/type/audience upload JWT | 401 | T0 |
| CAP-002 | Token importId differs from URL | 403 `UPLOAD_CAPABILITY_INVALID` | T0 |
| CAP-003 | Token maxBytes below request size | 413 | T0 |
| CAP-004 | Media delivery or OLDAP access JWT used for ingest PUT | 401 | T0 |
| CAP-005 | Upload JWT used on internal/public API operation | 401 | T0 |
| AUTH-INT-001 | Internal route reached through public proxy | route unavailable before auth | T1 deployment |
| AUTH-INT-002 | User/upload token used on internal route | 401 | T0 |
| AUTH-INT-003 | Import-service token used for record read or vice versa | 401/403 | T0 |
| RACE-001 | Confirmation with stale `expectedStateVersion` | 409 `IMPORT_VERSION_CONFLICT` | T0 |
| RACE-002 | Role revoked between READY and confirmation | 403, state remains READY until expiry/cancel | T1 |
| RACE-003 | Target deleted/moved before commit | conflict/failure before GraphDB side effect | T1 |
| RACE-004 | Two simultaneous confirmations | exactly one `IMPORTING`, other 409 | T1 |
| QUOTA-001 | Two job creations race for remaining staging quota | atomic reservation admits at most allowed total | T1 |
| QUOTA-002 | Actual extraction larger/smaller than reservation | reconcile atomically or invalidate without negative quota | T1 |

## G. Crash, idempotency, commit, and cleanup tests

| ID | Failure injection | Required invariant | Tier |
| --- | --- | --- | --- |
| REC-001 | Process killed during upload | only bounded `.part`; no stored receipt/state transition | T1 |
| REC-002 | SIP finalized, API notification fails | same receipt retained; reconciler eventually sends one logical event | T1 |
| REC-003 | Process killed during extraction | no final assets/resources; work cleaned/reclaimed | T1 |
| REC-004 | Identical validation result replay | original result; no duplicate email/state change | T0 |
| REC-005 | Same eventId with changed payload | 409 conflict and audit entry | T0 |
| REC-006 | Lease expires while worker is stopped | task reclaimable; stale worker result rejected | T1 |
| REC-007 | Two workers attempt claim | only one active claim | T1 |
| REC-008 | Crash after first final asset promotion | no staging resources; compensation/reconciliation removes job assets only | T1 |
| REC-009 | GraphDB batch fails midway | transaction rolls back complete resource batch | T1 |
| REC-010 | Commit response lost after successful transaction | replay returns same mappings; no duplicate resources | T1 |
| REC-011 | Crash after IMPORTED before temp cleanup | staging remains valid; cleanup resumes without state regression | T1 |
| REC-012 | Cleanup scheduler examines IMPORTING | job categorically not claimable | T0 |
| REC-013 | Cleanup called twice | second success/no-op; never deletes other job/final assets | T1 |
| REC-014 | Cleanup fails for IMPORTED/CANCELLED | state unchanged, `cleanupPending` remains true, retry scheduled | T1 |
| REC-015 | READY expires during worker polling | confirmation blocked at deadline; EXPIRED only after payload deletion | T1 |
| REC-016 | Email transport fails in any terminal transition | job/report unchanged; bounded retry; UI remains authoritative | T0 |

## H. Malware and operational-only tests

| ID | Scenario | Required invariant | Tier |
| --- | --- | --- | --- |
| OPS-001 | Official EICAR test string as direct rejected file | only after Defender/scanner coordination; expected scanner behavior documented | T3 |
| OPS-002 | Official EICAR file inside one ZIP | scanner/archive-depth behavior measured; no automatic CI or backup | T3 |
| OPS-003 | Daily backup window while READY payload exists | confirm ingest exclusion or document/delete backup copies by policy | T3 |
| OPS-004 | Real 500-MB upload boundary | exact byte enforcement and reserve behavior | T3 |
| OPS-005 | Real near-3-GB extraction in disposable volume | cgroup/disk counters, cleanup, no host instability | T3 |
| OPS-006 | Container memory/CPU/PID exhaustion | worker fails boundedly and other media/API services remain healthy | T3 |

EICAR is a harmless industry test signature, but endpoint protection intentionally
treats it like malware and may quarantine it or prevent deletion. Therefore the
string and its ZIPs are never committed, copied into normal development storage,
or generated without the VM owner and university security process agreeing on
the disposable location and cleanup procedure.

## Resolved catalogue decisions

Phase 0 fixes the following expected behavior:

1. Reject an empty or packaging-artifacts-only ZIP with
   `NO_IMPORTABLE_CONTENT`.
2. Accept WAV integer PCM at 8/16/24/32 bits and 8–192 kHz, FLAC at 8/16/24
   bits and 8–192 kHz, and MP3 at 8–48 kHz; all audio is mono or stereo.
3. Accept only content detected specifically as `text/plain` and decoded as
   strict UTF-8. Reject detected CSV, JSON, XML, HTML, SVG, and script formats;
   an extension mismatch on genuine plain text remains a warning.
4. Limit the sequential worker to 4 vCPUs, 6 GiB RAM, an equal
   memory-plus-swap ceiling where supported, and 128 PIDs.
