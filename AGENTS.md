# Repository Instructions

- Keep source code and repository documentation in English.
- Preserve the existing `/upload`, media/IIIF token, ZIP import, and ZIP export
  contracts. Mobile work must remain additive under versioned `/media/v1`
  routes.
- Keep originals bit-identical, treat paths and ownership evidence as untrusted,
  and never let temporary cleanup traverse into final asset storage.
- Do not route, deploy, provision secrets, or modify sibling repositories without
  explicit user authorization.
- Run `poetry run pytest -q`, focused Black checks for changed Python files,
  `poetry check`, and `git diff --check` before merge. Verify container/runtime
  changes with the mediahelper Docker image when Docker is available.
