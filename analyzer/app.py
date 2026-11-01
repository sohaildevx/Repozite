"""Repozite analyzer: a minimal Flask service for static analysis.

POST /analyze
    Body: {"files": [{"path": "src/app.py", "content": "..."}, ...]}
    Supported paths: .py, .js, .jsx, .mjs, .cjs, .ts, .tsx -- anything
    else is reported in meta.skipped without failing the request.
    Returns: {"findings": [{file_path, line_number, rule, severity,
                            description, source}, ...],
              "meta": {files_submitted, files_analyzed, findings_count,
                       skipped}}

GET /health
    Liveness probe (no data, no auth).

Security posture:
- Binds to 127.0.0.1 only (never 0.0.0.0) -- trusted components only.
- Optional shared secret: set ANALYZER_TOKEN in the environment and every
  request must carry an identical X-Analyzer-Token header (401 otherwise).
  Use this in production so nothing but the Django backend can call us.
- Validates file count, per-file size, total size, and path shape.
- Rejects sensitive filenames (.env, *.pem, id_rsa, ...) outright.
- Writes files ONLY to a per-request tempdir that is deleted afterwards.
- Never imports or executes submitted code.
- Returns generic error messages; no stack traces leak to clients.
"""

import hmac
import os
import tempfile
from pathlib import Path, PurePosixPath

from flask import Flask, jsonify, request

from analyzer import (
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    SyntaxCheckToolError,
    analyze,
    check_syntax,
    classify_path,
    is_sensitive_path,
)

app = Flask(__name__)
# Read once at startup; empty string means "token auth disabled" (dev mode).
app.config["ANALYZER_TOKEN"] = os.environ.get("ANALYZER_TOKEN", "")



class ValidationError(Exception):
    """Raised on bad input; caught once at the endpoint to return 400."""


def _error(message: str, status: int):
    """Uniform error envelope -- no stack traces, no internals."""
    return jsonify({"error": message}), status


def _validate_path(rel_path) -> str:
    """Validate one submitted file path; return it normalized.

    Rules: non-empty string, relative, no traversal (..), no absolute
    roots, no Windows drives/backslashes, no null bytes, <= 500 chars,
    <= 10 levels deep, not a sensitive filename.

    Raises ValidationError with a human-readable message on any violation.
    """
    if not rel_path or not isinstance(rel_path, str):
        raise ValidationError("Every file needs a non-empty 'path'.")
    if "\x00" in rel_path:
        raise ValidationError("Path contains null bytes.")
    if len(rel_path) > 500:
        raise ValidationError(f"Path too long (>500 chars): {rel_path[:60]}...")
    if "\\" in rel_path:
        raise ValidationError(f"Use forward slashes in paths: {rel_path}")

    p = PurePosixPath(rel_path)
    if p.is_absolute():
        raise ValidationError(f"Absolute paths are not allowed: {rel_path}")
    if ".." in p.parts:
        raise ValidationError(f"Path traversal ('..') is not allowed: {rel_path}")
    if len(p.parts) > 10:
        raise ValidationError(f"Path nesting too deep (>10 levels): {rel_path}")
    if is_sensitive_path(rel_path):
        raise ValidationError(
            f"Sensitive files are excluded from analysis: {Path(rel_path).name}"
        )

    return p.as_posix()


def _check_token() -> tuple | None:
    """Enforce the shared secret when ANALYZER_TOKEN is configured.

    Returns an error response, or None when access is allowed.
    hmac.compare_digest avoids timing side channels.
    """
    expected = app.config.get("ANALYZER_TOKEN") or ""
    if not expected:
        return None  # disabled (dev): loopback bind is the only barrier
    provided = request.headers.get("X-Analyzer-Token", "")
    if not provided or not hmac.compare_digest(provided, expected):
        return _error("Unauthorized.", 401)
    return None


def _parse_files_payload() -> dict[str, str]:
    """Parse and validate the {"files": [...]} request body.

    Returns {normalized_path: content}. Raises ValidationError with a
    client-safe message on any violation (400 path), so every endpoint
    enforces identical limits and rules.
    """
    payload = request.get_json(silent=True)
    if payload is None:
        raise ValidationError("Request body must be JSON.")

    files_raw = payload.get("files")
    if not isinstance(files_raw, list) or not files_raw:
        raise ValidationError("'files' must be a non-empty list.")
    if len(files_raw) > MAX_FILES:
        raise ValidationError(
            f"Too many files ({len(files_raw)}); limit is {MAX_FILES}."
        )

    total_bytes = 0
    files: dict[str, str] = {}

    for i, entry in enumerate(files_raw):
        if not isinstance(entry, dict):
            raise ValidationError(f"files[{i}] must be an object.")

        norm_path = _validate_path(entry.get("path"))

        content = entry.get("content")
        if not isinstance(content, str):
            raise ValidationError(f"files[{i}].content must be a string.")

        size = len(content.encode("utf-8", errors="replace"))
        if size > MAX_FILE_BYTES:
            raise ValidationError(
                f"File '{norm_path}' is {size} bytes; "
                f"limit is {MAX_FILE_BYTES}."
            )
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValidationError(
                f"Total payload exceeds {MAX_TOTAL_BYTES} bytes."
            )

        if norm_path in files:
            raise ValidationError(f"Duplicate path: {norm_path}")
        files[norm_path] = content

    if not files:
        raise ValidationError("No analyzable files after validation.")
    return files


@app.post("/analyze")
def analyze_endpoint():
    """Analyze a controlled set of source files and return findings."""
    denied = _check_token()
    if denied is not None:
        return denied

    try:
        files = _parse_files_payload()
    except ValidationError as exc:
        return _error(str(exc), 400)

    # Partition: supported source files go to their language engines;
    # everything else is skipped and reported so the caller knows exactly
    # what was (not) analyzed.
    buckets: dict[str, dict[str, str]] = {
        "python": {}, "javascript": {}, "typescript": {},
    }
    skipped = []
    for p in sorted(files):
        lang = classify_path(p)
        if lang is None:
            skipped.append({"path": p, "reason": "unsupported file type"})
        else:
            buckets[lang][p] = files[p]

    analyzed = sum(len(bucket) for bucket in buckets.values())

    findings: list[dict] = []
    if analyzed:
        # Sandbox: write files only into a tempdir we created, analyze,
        # delete. Nothing outside this directory is ever touched.
        try:
            with tempfile.TemporaryDirectory(prefix="repozite-analyze-") as tmp:
                sandbox = Path(tmp)
                for bucket in buckets.values():
                    for rel, content in bucket.items():
                        target = sandbox / rel
                        target.parent.mkdir(parents=True, exist_ok=True)
                        # Binary-safe write; tools handle encoding detection.
                        target.write_bytes(content.encode("utf-8", errors="replace"))

                findings = analyze(buckets, sandbox)
        except Exception:
            # Never leak internals; a generic 500 keeps stack traces server-side.
            return _error("Analysis failed unexpectedly.", 500)

    return jsonify({
        "findings": findings,
        "meta": {
            "files_submitted": len(files),
            "files_analyzed": analyzed,
            "findings_count": len(findings),
            "skipped": skipped,
        },
    })


@app.post("/check-syntax")
def check_syntax_endpoint():
    """Parse-only syntax check for submitted files (the agent's syntax gate).

    Returns {"results": [{"path", "ok", "line", "message"}, ...]} for
    every supported submitted file. Contents are parsed, never executed.
    When a language toolchain itself cannot run this answers 503 -- an
    unchecked file is NEVER reported as ok.
    """
    denied = _check_token()
    if denied is not None:
        return denied

    try:
        files = _parse_files_payload()
    except ValidationError as exc:
        return _error(str(exc), 400)

    buckets: dict[str, dict[str, str]] = {
        "python": {}, "javascript": {}, "typescript": {},
    }
    for p in sorted(files):
        lang = classify_path(p)
        if lang is not None:
            buckets[lang][p] = files[p]

    if not any(buckets.values()):
        return jsonify({"results": []})

    try:
        # Sandbox: write files only into a tempdir we created, parse,
        # delete. Nothing outside this directory is ever touched.
        with tempfile.TemporaryDirectory(prefix="repozite-syntax-") as tmp:
            sandbox = Path(tmp)
            for bucket in buckets.values():
                for rel, content in bucket.items():
                    target = sandbox / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content.encode("utf-8", errors="replace"))
            results = check_syntax(
                buckets["python"],
                buckets["javascript"],
                buckets["typescript"],
                sandbox,
            )
    except SyntaxCheckToolError as exc:
        return _error(str(exc), 503)
    except Exception:
        return _error("Syntax check failed unexpectedly.", 500)

    return jsonify({"results": results})


@app.get("/health")
def health():
    """Liveness probe for the Django side and for ops tooling."""
    return jsonify({"status": "ok"})


# Bind to loopback only. In production this service sits behind the Django
# host (or a private network); it is never exposed to the internet.
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
