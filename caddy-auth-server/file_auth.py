from flask import Flask, request, abort, Response
import jwt
import posixpath

app = Flask(__name__)

JWT_KEY = "…"           # euer shared secret (HS256) oder Public Key (RS256)
JWT_ISS = "http://oldap.org"

def safe_join(project: str, sub: str | None, filename: str) -> str:
    # Normalize & verhindern von ../ Traversal
    parts = [project]
    if sub:
        parts.append(sub)
    parts.append(filename)

    raw = "/".join(parts)
    norm = posixpath.normpath(raw).lstrip("/")   # macht's relativ

    # Blockiere Traversal / leere Ergebnisse
    if norm.startswith("..") or norm == "." or norm == "":
        raise ValueError("bad path")
    return norm

@app.get("/auth")
def auth():
    token = request.args.get("token")
    if not token:
        abort(401)

    try:
        payload = jwt.decode(
            token,
            JWT_KEY,
            algorithms=["HS256"],   # oder ["RS256"]
            issuer=JWT_ISS,
            options={"require": ["exp", "iat"]}
        )
    except Exception:
        abort(401)

    permval = int(payload.get("permval", 0))
    if permval < 1:
        abort(403)

    project = str(payload.get("project", "")).strip()
    sub = str(payload.get("sub", "")).strip() or None
    filename = str(payload.get("file", "")).strip()

    if not project or not filename:
        abort(403)

    try:
        internal_path = safe_join(project, sub, filename)
    except ValueError:
        abort(403)

    resp = Response("OK", 200)
    resp.headers["X-Internal-Path"] = internal_path
    return resp