"""Static-analysis logic: multi-language engines (Python, JS/TS).

Design rules (security-critical):
- We NEVER import or execute submitted code. We only read it as text,
  parse it with ast.parse (which does not execute), and hand the files
  to external tools (Ruff/Bandit for Python; ESLint, the TypeScript
  compiler and Semgrep for JavaScript/TypeScript) as subprocesses with
  timeouts.
- External tools are invoked with OUR OWN bundled configuration only:
  repository ESLint configs are never loaded (--no-config-lookup) and
  Semgrep runs exclusively against the rules file shipped here, so an
  untrusted repository can never get its own code or config executed.
- Files are written only into a caller-provided temp directory that was
  created by this process -- never to a user-supplied path.
- Every subprocess has a hard timeout; a hung tool cannot wedge the service.
- Sensitive filenames (.env, *.pem, id_rsa, ...) are rejected up front.

Every finding is normalized to the same shape:
    {file_path, line_number, rule, severity, description, source}
where `source` is which engine found it: "ast", "ruff", "bandit",
"eslint", "tsc" or "semgrep".
"""

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Hard limits -- mirrored in app.py validation, enforced again here.
MAX_FILES = 100
MAX_FILE_BYTES = 200_000           # 200 KB per file
MAX_TOTAL_BYTES = 2_000_000        # 2 MB per submission
TOOL_TIMEOUT_SECONDS = 30          # per tool, per submission
SEMGREP_TIMEOUT_SECONDS = 60       # Semgrep's cold start is heavier

# Supported source languages (mirrored by the snapshot fetcher).
PYTHON_SUFFIXES = (".py",)
JAVASCRIPT_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")
TYPESCRIPT_SUFFIXES = (".ts", ".tsx")

# Where the bundled tool artifacts live (eslint.config.mjs, ts_check.js,
# ts_prelude.d.ts, semgrep-rules.yml, node_modules/).
_ANALYZER_DIR = Path(__file__).resolve().parent

# Filenames we refuse to analyze outright (secret exfiltration guard).
SENSITIVE_PATTERNS = {
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "credentials", "credentials.json", "secrets.json",
    "service-account.json", ".npmrc", ".pypirc",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")


def is_sensitive_path(rel_path: str) -> bool:
    """True if this path looks like it holds secrets. Reject, never analyze."""
    name = Path(rel_path).name.lower()
    if name in SENSITIVE_PATTERNS:
        return True
    if name.endswith(SENSITIVE_SUFFIXES):
        return True
    # .env.something (conservative: any .env-prefixed file is refused)
    if name.startswith(".env"):
        return True
    return False


def classify_path(rel_path: str) -> str | None:
    """Return the language bucket for a path, or None when unsupported.

    Generated bundles (.min.js) are excluded -- build output, not source.
    Mirrors the snapshot fetcher's gate so the upload and scan flows
    accept the same file set.
    """
    lower = rel_path.lower()
    if lower.endswith(".min.js"):
        return None
    if lower.endswith(PYTHON_SUFFIXES):
        return "python"
    if lower.endswith(JAVASCRIPT_SUFFIXES):
        return "javascript"
    if lower.endswith(TYPESCRIPT_SUFFIXES):
        return "typescript"
    return None


def _severity_from_ruff(code: str) -> str:
    """Map a Ruff rule code to our severity vocabulary.

    E9/F82x are syntax/runtime errors (high); F is pyflakes (medium);
    E (other) is pycodestyle errors (medium); everything else (C4, SIM,
    B, UP, ...) is stylistic (low).
    """
    if code.startswith(("E9", "F82")):
        return "high"
    if code.startswith(("F", "E")):
        return "medium"
    return "low"


def _severity_from_bandit(level: str) -> str:
    return {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(
        level.upper(), "low"
    )


def _rel_path(filename: str, sandbox_dir: Path) -> str:
    """Strip the sandbox prefix from a tool-reported absolute path."""
    p = Path(filename)
    if sandbox_dir in p.parents:
        return p.relative_to(sandbox_dir).as_posix()
    return p.as_posix()


def run_ast_checks(files: dict[str, str]) -> list[dict]:
    """Custom AST checks. `files` maps rel_path -> source text.

    ast.parse() compiles to an AST without executing anything -- it's
    exactly what `python -m py_compile` does, minus the write.

    Returns findings for: syntax errors, eval/exec usage, and bare
    excepts. A file that fails to parse yields one AST001 finding and
    no further AST checks (graceful handling of invalid syntax).
    """
    findings = []

    for rel_path, source in sorted(files.items()):
        try:
            tree = ast.parse(source, filename=rel_path)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            # SyntaxError carries .lineno/.msg; the others are rare but
            # must not crash the request either.
            line = getattr(exc, "lineno", None) or 1
            msg = getattr(exc, "msg", None) or type(exc).__name__
            findings.append({
                "file_path": rel_path,
                "line_number": line,
                "rule": "AST001",
                "severity": "high",
                "description": f"SyntaxError: {msg}",
                "source": "ast",
            })
            continue  # a file that won't parse has no further AST checks

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute)
                    else ""
                )
                if name in ("eval", "exec"):
                    findings.append({
                        "file_path": rel_path,
                        "line_number": node.lineno,
                        "rule": "AST002",
                        "severity": "high",
                        "description": (
                            f"Use of {name}() executes arbitrary code at "
                            "runtime and is a common injection vector."
                        ),
                        "source": "ast",
                    })
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:  # bare `except:`
                    findings.append({
                        "file_path": rel_path,
                        "line_number": node.lineno,
                        "rule": "AST003",
                        "severity": "medium",
                        "description": (
                            "Bare except catches everything including "
                            "KeyboardInterrupt and SystemExit; catch "
                            "specific exceptions instead."
                        ),
                        "source": "ast",
                    })

    return findings


def _tool_failure_finding(tool: str, rule: str, message: str) -> dict:
    """A degraded-but-valid finding when a tool could not run.

    We return it as a finding (instead of raising) so the caller always
    gets a well-formed response even when a subprocess dies.
    `rule` is TOOL_TIMEOUT or TOOL_ERROR; `message` is client-safe text.
    """
    return {
        "file_path": ".",
        "line_number": 1,
        "rule": rule,
        "severity": "medium",
        "description": message,
        "source": tool,
    }


def run_ruff(files: dict[str, str], sandbox_dir: Path) -> list[dict]:
    """Run Ruff over the sandboxed .py files. Returns findings (never raises)."""
    paths = [str(sandbox_dir / p) for p in sorted(files)]
    if not paths:
        return []

    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "ruff", "check",
                "--output-format", "json",
                "--no-cache",           # never write cache files anywhere
                "--isolated",           # ignore any user/project config
                *paths,
            ],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [_tool_failure_finding(
            "ruff", "TOOL_TIMEOUT", "Ruff timed out; results may be incomplete."
        )]
    except (OSError, ValueError):
        return [_tool_failure_finding(
            "ruff", "TOOL_ERROR",
            "Ruff could not be executed; results may be incomplete.",
        )]

    # Ruff exits 0 (clean), 1 (findings), 2 (error). JSON goes to stdout.
    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [_tool_failure_finding(
            "ruff", "TOOL_ERROR",
            "Ruff returned unreadable output; results may be incomplete.",
        )]

    findings = []
    for item in raw:
        code = item.get("code") or "RLU000"
        findings.append({
            "file_path": _rel_path(item.get("filename", ""), sandbox_dir),
            "line_number": item.get("location", {}).get("row", 1),
            "rule": code,
            "severity": _severity_from_ruff(code),
            "description": item.get("message", "").strip(),
            "source": "ruff",
        })
    return findings


def run_bandit(files: dict[str, str], sandbox_dir: Path) -> list[dict]:
    """Run Bandit (security linter) over the sandboxed .py files."""
    if not files:
        return []

    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "bandit", "-r", "-f", "json",
                "-q",                   # only report issues, not progress
                "--exit-zero",          # findings are not an error exit
                str(sandbox_dir),
            ],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [_tool_failure_finding(
            "bandit", "TOOL_TIMEOUT",
            "Bandit timed out; results may be incomplete.",
        )]
    except (OSError, ValueError):
        return [_tool_failure_finding(
            "bandit", "TOOL_ERROR",
            "Bandit could not be executed; results may be incomplete.",
        )]

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [_tool_failure_finding(
            "bandit", "TOOL_ERROR",
            "Bandit returned unreadable output; results may be incomplete.",
        )]

    findings = []
    for item in data.get("results", []):
        findings.append({
            "file_path": _rel_path(item.get("filename", ""), sandbox_dir),
            "line_number": item.get("line_number", 1),
            "rule": item.get("test_id", "BNT000"),
            "severity": _severity_from_bandit(item.get("issue_severity", "LOW")),
            "description": item.get("issue_text", "").strip(),
            "source": "bandit",
        })
    return findings


def run_eslint(files: dict[str, str], sandbox_dir: Path) -> list[dict]:
    """Run ESLint over the sandboxed JS/TS files. Never raises.

    The bundled analyzer config is used with --no-config-lookup, and the
    subprocess runs with cwd=sandbox so ESLint's glob base path resolves
    against the sandbox. Repository configs are never read.
    """
    if not files:
        return []

    node = shutil.which("node")
    eslint_js = _ANALYZER_DIR / "node_modules" / "eslint" / "bin" / "eslint.js"
    config = _ANALYZER_DIR / "eslint.config.mjs"
    if node is None or not eslint_js.is_file() or not config.is_file():
        return [_tool_failure_finding(
            "eslint", "TOOL_ERROR",
            "ESLint could not be executed; results may be incomplete.",
        )]

    paths = [str(sandbox_dir / p) for p in sorted(files)]
    try:
        proc = subprocess.run(
            [
                node, str(eslint_js),
                "--no-config-lookup",        # never read repo/user configs
                "--config", str(config),     # our bundled rules only
                "--format", "json",
                "--no-error-on-unmatched-pattern",
                *paths,
            ],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            cwd=str(sandbox_dir),            # ESLint base path = sandbox
        )
    except subprocess.TimeoutExpired:
        return [_tool_failure_finding(
            "eslint", "TOOL_TIMEOUT",
            "ESLint timed out; results may be incomplete.",
        )]
    except (OSError, ValueError):
        return [_tool_failure_finding(
            "eslint", "TOOL_ERROR",
            "ESLint could not be executed; results may be incomplete.",
        )]

    # ESLint exits 0 (clean), 1 (findings), 2 (fatal). JSON goes to stdout.
    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [_tool_failure_finding(
            "eslint", "TOOL_ERROR",
            "ESLint returned unreadable output; results may be incomplete.",
        )]
    if not isinstance(raw, list):
        return [_tool_failure_finding(
            "eslint", "TOOL_ERROR",
            "ESLint returned unreadable output; results may be incomplete.",
        )]

    findings = []
    for entry in raw:
        rel = _rel_path(entry.get("filePath", ""), sandbox_dir)
        for msg in entry.get("messages") or []:
            sev_num = msg.get("severity")
            if sev_num == 2:
                severity = "high"
            elif sev_num == 1:
                severity = "medium"
            else:
                continue
            fatal = bool(msg.get("fatal"))
            rule = msg.get("ruleId") or ("ESLINT-FATAL" if fatal else "ESLINT")
            line = msg.get("line") or 1
            findings.append({
                "file_path": rel,
                "line_number": max(int(line), 1),
                "rule": str(rule)[:50],
                "severity": severity,
                "description": str(msg.get("message") or "").strip(),
                "source": "eslint",
            })
    return findings


def run_tsc(files: dict[str, str], sandbox_dir: Path) -> list[dict]:
    """Type/syntax-check the sandboxed .ts/.tsx files via ts_check.js.

    ts_check.js drives the TypeScript compiler API (noEmit, never
    executes code), prepends the analyzer's ambient prelude, and filters
    diagnostics that only mean "the snapshot has no node_modules".
    """
    if not files:
        return []

    node = shutil.which("node")
    script = _ANALYZER_DIR / "ts_check.js"
    if node is None or not script.is_file():
        return [_tool_failure_finding(
            "tsc", "TOOL_ERROR",
            "The TypeScript compiler could not be executed; "
            "results may be incomplete.",
        )]

    paths = [str(sandbox_dir / p) for p in sorted(files)]
    try:
        proc = subprocess.run(
            [node, str(script), *paths],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [_tool_failure_finding(
            "tsc", "TOOL_TIMEOUT",
            "The TypeScript compiler timed out; results may be incomplete.",
        )]
    except (OSError, ValueError):
        return [_tool_failure_finding(
            "tsc", "TOOL_ERROR",
            "The TypeScript compiler could not be executed; "
            "results may be incomplete.",
        )]

    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [_tool_failure_finding(
            "tsc", "TOOL_ERROR",
            "The TypeScript compiler returned unreadable output; "
            "results may be incomplete.",
        )]
    if not isinstance(raw, list):
        return [_tool_failure_finding(
            "tsc", "TOOL_ERROR",
            "The TypeScript compiler returned unreadable output; "
            "results may be incomplete.",
        )]

    findings = []
    for item in raw:
        try:
            code = int(item.get("code") or 0)
        except (TypeError, ValueError):
            code = 0
        # Grammar/parse failures = file does not parse (high, mirroring
        # Python's AST001); type errors are medium. `kind` comes from
        # ts_check.js via getSyntacticDiagnostics().
        severity = "high" if item.get("kind") == "syntax" else "medium"
        findings.append({
            "file_path": _rel_path(item.get("file", ""), sandbox_dir) or ".",
            "line_number": max(int(item.get("line") or 1), 1),
            "rule": f"TS{code}",
            "severity": severity,
            "description": str(item.get("text") or "").strip(),
            "source": "tsc",
        })
    return findings


def _semgrep_argv() -> list[str] | None:
    """Locate the Semgrep console script installed next to this Python."""
    exe = Path(sys.executable)
    sibling = exe.with_name("semgrep.exe" if os.name == "nt" else "semgrep")
    if sibling.is_file():
        return [str(sibling)]
    found = shutil.which("semgrep")
    return [found] if found else None


def run_semgrep(files: dict[str, str], sandbox_dir: Path) -> list[dict]:
    """Run Semgrep (security rules) over the sandboxed JS/TS files.

    Only the bundled semgrep-rules.yml is ever passed as config, and only
    the submitted files are given as targets; repository rule files are
    never loaded and scanned code is parsed, never executed.
    """
    if not files:
        return []

    argv = _semgrep_argv()
    rules = _ANALYZER_DIR / "semgrep-rules.yml"
    if argv is None or not rules.is_file():
        return [_tool_failure_finding(
            "semgrep", "TOOL_ERROR",
            "Semgrep could not be executed; results may be incomplete.",
        )]

    paths = [str(sandbox_dir / p) for p in sorted(files)]
    try:
        proc = subprocess.run(
            [
                *argv, "scan",
                "--config", str(rules),
                "--json",
                "--quiet",
                "--metrics=off",              # never upload source anywhere
                "--disable-version-check",    # no network beyond the scan
                "--timeout", "15",
                *paths,
            ],
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [_tool_failure_finding(
            "semgrep", "TOOL_TIMEOUT",
            "Semgrep timed out; results may be incomplete.",
        )]
    except (OSError, ValueError):
        return [_tool_failure_finding(
            "semgrep", "TOOL_ERROR",
            "Semgrep could not be executed; results may be incomplete.",
        )]

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [_tool_failure_finding(
            "semgrep", "TOOL_ERROR",
            "Semgrep returned unreadable output; results may be incomplete.",
        )]
    # A non-zero exit (e.g. invalid rule config) or a results-less payload
    # means the scan itself failed -- findings must not be claimed.
    if proc.returncode != 0 or not isinstance(data, dict) or "results" not in data:
        return [_tool_failure_finding(
            "semgrep", "TOOL_ERROR",
            "Semgrep returned unusable output; results may be incomplete.",
        )]

    findings = []
    for item in data.get("results") or []:
        check_id = str(item.get("check_id") or "")
        # IDs are namespaced "repozite.<name>" (possibly with a config
        # prefix); show the stable analyzer name in the rule field.
        rule = check_id.split("repozite.")[-1] if "repozite." in check_id else check_id
        extra = item.get("extra") or {}
        raw_sev = str(extra.get("severity") or "").upper()
        severity = {"ERROR": "high", "WARNING": "medium"}.get(raw_sev, "low")
        line = (item.get("start") or {}).get("line") or 1
        findings.append({
            "file_path": _rel_path(item.get("path", ""), sandbox_dir),
            "line_number": max(int(line), 1),
            "rule": rule[:50],
            "severity": severity,
            "description": str(extra.get("message") or "").strip(),
            "source": "semgrep",
        })
    return findings


class SyntaxCheckToolError(Exception):
    """The syntax-check toolchain could not run; message is client-safe."""


def _js_syntax(files: dict[str, str], sandbox_dir: Path) -> dict[str, dict]:
    """espree parse verdicts for .js/.jsx/.mjs/.cjs files (js_check.js)."""
    node = shutil.which("node")
    script = _ANALYZER_DIR / "js_check.js"
    if node is None or not script.is_file():
        raise SyntaxCheckToolError("JavaScript syntax checker is unavailable.")

    paths = [str(sandbox_dir / p) for p in sorted(files)]
    try:
        proc = subprocess.run(
            [node, str(script), *paths],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise SyntaxCheckToolError("JavaScript syntax checker timed out.")
    except (OSError, ValueError):
        raise SyntaxCheckToolError("JavaScript syntax checker is unavailable.")

    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        raw = None
    if not isinstance(raw, list):
        raise SyntaxCheckToolError(
            "JavaScript syntax checker returned unreadable output."
        )

    out = {}
    for item in raw:
        rel = _rel_path(str(item.get("path", "")), sandbox_dir)
        out[rel] = {
            "path": rel,
            "ok": bool(item.get("ok")),
            "line": max(int(item.get("line") or 1), 1),
            "message": str(item.get("message") or ""),
        }
    for rel in files:
        if rel not in out:
            raise SyntaxCheckToolError(
                "JavaScript syntax checker returned no verdict for a file."
            )
    return out


def _ts_syntax(files: dict[str, str], sandbox_dir: Path) -> dict[str, dict]:
    """Syntactic-only verdicts for .ts/.tsx files (ts_check.js)."""
    node = shutil.which("node")
    script = _ANALYZER_DIR / "ts_check.js"
    if node is None or not script.is_file():
        raise SyntaxCheckToolError("TypeScript syntax checker is unavailable.")

    paths = [str(sandbox_dir / p) for p in sorted(files)]
    try:
        proc = subprocess.run(
            [node, str(script), "--syntax-only", *paths],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise SyntaxCheckToolError("TypeScript syntax checker timed out.")
    except (OSError, ValueError):
        raise SyntaxCheckToolError("TypeScript syntax checker is unavailable.")

    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        raw = None
    if not isinstance(raw, list):
        raise SyntaxCheckToolError(
            "TypeScript syntax checker returned unreadable output."
        )

    out = {
        rel: {"path": rel, "ok": True, "line": 1, "message": ""}
        for rel in files
    }
    for item in raw:
        if item.get("kind") != "syntax":
            continue
        rel = _rel_path(str(item.get("file", "")), sandbox_dir)
        if rel in out and out[rel]["ok"]:
            out[rel] = {
                "path": rel,
                "ok": False,
                "line": max(int(item.get("line") or 1), 1),
                "message": str(item.get("text") or "invalid syntax"),
            }
    return out


def check_syntax(
    python_files: dict[str, str],
    js_files: dict[str, str],
    ts_files: dict[str, str],
    sandbox_dir: Path,
) -> list[dict]:
    """Parse-only syntax verdicts for every submitted file.

    Never executes repository code. Python parses in-process with ast;
    JS/JSX with espree; TS/TSX with the TypeScript compiler (syntactic
    diagnostics only). Returns [{"path", "ok", "line", "message"}...]
    sorted by path. Raises SyntaxCheckToolError when a language toolchain
    cannot run, so callers can answer with an error instead of a fake
    "ok".
    """
    results: dict[str, dict] = {}

    for rel, content in sorted(python_files.items()):
        entry = {"path": rel, "ok": True, "line": 1, "message": ""}
        try:
            ast.parse(content, filename=rel)
        except SyntaxError as exc:
            entry = {
                "path": rel,
                "ok": False,
                "line": getattr(exc, "lineno", None) or 1,
                "message": str(getattr(exc, "msg", None) or "invalid syntax"),
            }
        except (ValueError, TypeError):
            # e.g. null bytes -- invalid content, not a tool failure.
            entry = {
                "path": rel,
                "ok": False,
                "line": 1,
                "message": "File content is not valid Python source.",
            }
        results[rel] = entry

    if js_files:
        results.update(_js_syntax(js_files, sandbox_dir))
    if ts_files:
        results.update(_ts_syntax(ts_files, sandbox_dir))

    return [results[p] for p in sorted(results)]


def analyze(buckets: dict[str, dict[str, str]], sandbox_dir: Path) -> list[dict]:
    """Run the engines for each language bucket over the sandbox and merge.

    `buckets` maps "python" / "javascript" / "typescript" -> {rel: src}.
    Python keeps its original three engines (ast, ruff, bandit) untouched;
    JS/TS go through ESLint, the TypeScript compiler and Semgrep. Buckets
    that are empty run no tool at all -- a Python-only request never
    invokes the JS toolchain.

    Tool crashes never propagate: each runner degrades to a single
    TOOL_* finding so the caller always gets a valid response.
    """
    python_files = buckets.get("python") or {}
    js_files = buckets.get("javascript") or {}
    ts_files = buckets.get("typescript") or {}

    findings = []

    if python_files:
        findings.extend(run_ast_checks(python_files))
        findings.extend(run_ruff(python_files, sandbox_dir))
        findings.extend(run_bandit(python_files, sandbox_dir))

    js_ts_files = {**js_files, **ts_files}
    if js_ts_files:
        findings.extend(run_eslint(js_ts_files, sandbox_dir))
        if ts_files:
            findings.extend(run_tsc(ts_files, sandbox_dir))
        findings.extend(run_semgrep(js_ts_files, sandbox_dir))

    findings.sort(
        key=lambda f: (f["file_path"], f["line_number"], f["rule"])
    )
    return findings
