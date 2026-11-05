# Asset delivery authorization

`/asset/<id>[/original|derived]` is served by Caddy after the mediahelper's
`/auth/asset/...` decision. The HTTP routes and successful response contracts
are unchanged. This policy applies to both GET and HEAD and to all derivatives,
including thumbnails, as well as originals.

## Capability or public lookup

- When `token` is absent, resolve the asset as the configured public `unknown`
  identity through OLDAP. An invisible/missing asset remains 404.
- When `token` is present, it must occur exactly once and be non-empty. Verify its
  signature, type, issuer, audience and lifetime. Invalid/expired tokens return
  403; they never fall back to public access. Configuration failures remain 503.
- At least one of the established `id`/`assetId` claims must be present. Every
  supplied identifier must match the requested asset. Conflicts/missing identity
  return 403, without a public lookup.
- Both signed claims and public API results must contain integer `permval` in
  1..6. Missing, zero, out-of-range and malformed values return 403. Booleans,
  strings and fractional values are not converted into permissions.

The minimum remains DATA_RESTRICTED (1), matching the existing SIPI deployment.
This correction does not introduce new reduced-resolution or original-download
entitlements. A different policy for restricted representations would need an
explicit coordinated decision across API, frontend and both delivery paths.

Existing valid capabilities retain their bounded lifetime after source rights
change. This fix does not add per-request account/role revocation lookup for
signed capabilities. Unsigned clients cannot change permission claims without
invalidating the signature.

## Verification and rollout

Focused tests include invalid/expired/empty/duplicate credentials, conflicting or
missing asset identities, invalid/missing permissions, successful numeric grants
and tokenless public resolution. The Jena migration rehearsal also verifies the
real Caddy path, byte integrity, ranges and CORS using copied PDF/JPEG files and
fresh fixture-only keys. It mounts repository source read-only over the installed
mediahelper runtime; this is not a released rebuilt image.

Deploy a newly built/versioned mediahelper image to activate the correction.
No running local/remote service is changed by editing this repository. Legacy
callers that send invalid tokens for public files must omit the token or obtain a
fresh valid capability. Tokens missing `permval` or an asset identifier are now
rejected intentionally; ordinary OLDAP API tokens already include these fields.

Verification on 2026-10-31: 374 tests and four subtests passed, 20 skipped;
Black, Poetry metadata (existing deprecation warnings) and diff checks pass.
The owned real-export Jena run passes nine grouped asset checks plus 23 API
and ten image checks. Source hashes are unchanged after cleanup. Both formerly
accepted negative cases now return 403, while tokenless public access succeeds.
