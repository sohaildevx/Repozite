"""Tests for the Flask analyzer service.

Run from the analyzer/ directory:
    python -m unittest tests -v

Covers:
- valid requests return normalized findings (file_path, line_number, rule,
  severity, description, source)
- source attribution per engine (ast / ruff / bandit / eslint / tsc / semgrep)
- invalid syntax handled as a finding, not a crash
- unsupported (non-source) files skipped gracefully
- JS/TS files analyzed by the real ESLint/tsc/Semgrep toolchain, and
  Python-only requests provably run none of those tools
- empty/malformed requests, oversized files, excessive file counts
- sensitive files (.env, *.pem, id_rsa) rejected
- path traversal / absolute paths rejected
- tool timeouts surfaced as TOOL_TIMEOUT findings (no crash)
- shared-secret token auth (X-Analyzer-Token)
- health endpoint
"""

import json
import subprocess
import unittest
from unittest.mock import patch

from app import app


class AnalyzerTestCase(unittest.TestCase):
    """Shared setup: Flask test client."""

    def setUp(self):
        self.client = app.test_client()

    def _post(self, files, token=None):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Analyzer-Token"] = token
        return self.client.post(
            "/analyze",
            data=json.dumps({"files": files}),
            headers=headers,
        )


class ValidRequestTests(AnalyzerTestCase):
    """Happy-path analysis."""

    def test_clean_file_returns_no_findings(self):
        resp = self._post([
            {"path": "clean.py", "content": "x = 1\nprint(x)\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("findings", data)
        self.assertIn("meta", data)
        self.assertEqual(data["meta"]["files_submitted"], 1)
        self.assertEqual(data["meta"]["files_analyzed"], 1)

    def test_eval_detected(self):
        resp = self._post([
            {"path": "bad.py", "content": "eval('1+1')\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        self.assertIn("AST002", rules)

    def test_bare_except_detected(self):
        resp = self._post([
            {"path": "bad.py", "content": "try:\n    pass\nexcept:\n    pass\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        self.assertIn("AST003", rules)

    def test_syntax_error_detected(self):
        resp = self._post([
            {"path": "broken.py", "content": "def foo(:\n    pass\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        self.assertIn("AST001", rules)

    def test_finding_shape(self):
        """Every finding carries all six documented fields."""
        resp = self._post([
            {"path": "bad.py", "content": "eval('2')\n"},
        ])
        data = resp.get_json()
        self.assertTrue(data["findings"])
        for f in data["findings"]:
            for key in ("file_path", "line_number", "rule", "severity",
                        "description", "source"):
                self.assertIn(key, f)
            self.assertIn(f["source"], {"ast", "ruff", "bandit"})

    def test_ruff_finds_issue(self):
        """Ruff should flag an unused import (F401)."""
        resp = self._post([
            {"path": "unused.py", "content": "import os\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        self.assertIn("F401", rules)

    def test_bandit_finds_hardcoded_password(self):
        """Bandit should flag a hardcoded password string."""
        resp = self._post([
            {"path": "secrets.py",
             "content": "password = 'hunter2'\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        # B105 = hardcoded_password_string
        self.assertTrue(
            any(r.startswith("B1") for r in rules),
            f"Expected a Bandit B1xx finding, got: {rules}",
        )


class SourceAttributionTests(AnalyzerTestCase):
    """Each finding identifies which engine produced it."""

    def _finding(self, rule):
        resp = self._post([
            {"path": "sample.py",
             "content": "import os\npassword = 'hunter2'\nx = eval('1')\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        matches = [f for f in resp.get_json()["findings"] if f["rule"] == rule]
        self.assertTrue(matches, f"rule {rule} not found")
        return matches[0]

    def test_ast_finding_source(self):
        self.assertEqual(self._finding("AST002")["source"], "ast")

    def test_ruff_finding_source(self):
        self.assertEqual(self._finding("F401")["source"], "ruff")

    def test_bandit_finding_source(self):
        self.assertEqual(self._finding("B105")["source"], "bandit")


class UnsupportedFileTests(AnalyzerTestCase):
    """Unsupported files are skipped gracefully, not rejected or analyzed."""

    def test_only_txt_file_returns_200_with_skip(self):
        resp = self._post([
            {"path": "README.md", "content": "# hello\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["meta"]["files_analyzed"], 0)
        self.assertEqual(data["meta"]["files_submitted"], 1)
        self.assertEqual(data["meta"]["skipped"],
                         [{"path": "README.md",
                           "reason": "unsupported file type"}])

    def test_mixed_files_analyze_only_python(self):
        resp = self._post([
            {"path": "app.py", "content": "eval('1')\n"},
            {"path": "notes.txt", "content": "just text\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["meta"]["files_analyzed"], 1)
        self.assertEqual(data["meta"]["skipped"][0]["path"], "notes.txt")
        # The .py file was still analyzed:
        rules = [f["rule"] for f in data["findings"]]
        self.assertIn("AST002", rules)
        # And findings only reference the analyzed file:
        self.assertEqual({f["file_path"] for f in data["findings"]},
                         {"app.py"})


class JavaScriptTypeScriptTests(AnalyzerTestCase):
    """JS/TS files flow through ESLint/tsc/Semgrep; Python stays intact.

    These tests run the REAL toolchain (node + bundled eslint config,
    ts_check.js, semgrep + bundled rules) against temporary sources.
    """

    def test_js_file_gets_eslint_and_semgrep_findings(self):
        resp = self._post([
            {"path": "app.js",
             "content": "const unused = 1;\neval('2');\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["meta"]["files_analyzed"], 1)
        sources = {f["source"] for f in data["findings"]}
        rules = {f["rule"] for f in data["findings"]}
        # ESLint: unused variable + eval, with its own rule IDs...
        self.assertIn("eslint", sources)
        self.assertIn("no-unused-vars", rules)
        self.assertIn("no-eval", rules)
        # Semgrep: the bundled security rule fired too...
        self.assertIn("semgrep", sources)
        self.assertIn("js-eval", rules)
        # ...and the Python engines never touched the JS file.
        for python_engine in ("ast", "ruff", "bandit"):
            self.assertNotIn(python_engine, sources)

    def test_ts_type_error_reported_by_tsc(self):
        resp = self._post([
            {"path": "bad.ts",
             "content": 'const n: number = "str";\nexport {};\n'},
        ])
        self.assertEqual(resp.status_code, 200)
        findings = resp.get_json()["findings"]
        tsc = [f for f in findings if f["source"] == "tsc"]
        self.assertTrue(tsc, f"expected tsc findings, got: {findings}")
        self.assertTrue(all(f["rule"].startswith("TS2") for f in tsc))
        self.assertTrue(all(f["severity"] == "medium" for f in tsc))
        self.assertEqual(tsc[0]["file_path"], "bad.ts")

    def test_ts_syntax_error_is_high_severity(self):
        resp = self._post([
            {"path": "broken.tsx",
             "content": "export const C = () => <div>;\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        findings = resp.get_json()["findings"]
        tsc_syntax = [f for f in findings
                      if f["source"] == "tsc" and f["rule"].startswith("TS1")]
        self.assertTrue(
            tsc_syntax,
            f"expected a TS1xxx syntax finding, got: {findings}",
        )
        for f in tsc_syntax:
            self.assertEqual(f["severity"], "high")

    def test_mixed_python_and_js_request_runs_both_engine_sets(self):
        resp = self._post([
            {"path": "app.py", "content": "eval('1')\n"},
            {"path": "app.js", "content": "eval('1');\n"},
            {"path": "notes.txt", "content": "hello\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["meta"]["files_analyzed"], 2)
        self.assertEqual(data["meta"]["skipped"],
                         [{"path": "notes.txt",
                           "reason": "unsupported file type"}])
        by_file = {}
        for f in data["findings"]:
            by_file.setdefault(f["file_path"], set()).add(f["source"])
        self.assertIn("ast", by_file["app.py"])
        self.assertNotIn("eslint", by_file["app.py"])
        self.assertIn("eslint", by_file["app.js"])
        self.assertNotIn("ast", by_file["app.js"])

    def test_python_only_request_runs_no_js_tools(self):
        """Python scans must not pay for (or depend on) the JS toolchain."""
        real_run = subprocess.run
        commands = []

        def spy(cmd, *args, **kwargs):
            commands.append(" ".join(str(c) for c in cmd))
            return real_run(cmd, *args, **kwargs)

        with patch("analyzer.subprocess.run", side_effect=spy):
            resp = self._post([
                {"path": "ok.py", "content": "x = 1\n"},
            ])
        self.assertEqual(resp.status_code, 200)
        joined = " || ".join(commands)
        for tool_marker in ("eslint", "ts_check", "semgrep"):
            self.assertNotIn(tool_marker, joined)
        
        self.assertIn("ruff", joined)
        self.assertIn("bandit", joined)

    def test_missing_node_reports_eslint_tool_error(self):
        with patch("analyzer.shutil.which", return_value=None):
            resp = self._post([
                {"path": "app.js", "content": "const x = 1;\n"},
            ])
        self.assertEqual(resp.status_code, 200)
        findings = resp.get_json()["findings"]
        self.assertTrue(
            any(f["source"] == "eslint" and f["rule"] == "TOOL_ERROR"
                for f in findings),
            f"expected an eslint TOOL_ERROR finding, got: {findings}",
        )

    def test_js_tool_timeout_reports_findings_not_crash(self):
        with patch("analyzer.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="x", timeout=30)):
            resp = self._post([
                {"path": "app.js", "content": "x;\n"},
            ])
        self.assertEqual(resp.status_code, 200)
        findings = resp.get_json()["findings"]
        timeouts = [f for f in findings if f["rule"] == "TOOL_TIMEOUT"]
        self.assertEqual({f["source"] for f in timeouts},
                         {"eslint", "semgrep"})
        for f in timeouts:
            self.assertNotIn("Traceback", f["description"])


class CheckSyntaxTests(AnalyzerTestCase):
    """POST /check-syntax: parse-only verdicts per file, no execution."""

    def _post_syntax(self, files):
        return self.client.post(
            "/check-syntax",
            data=json.dumps({"files": files}),
            headers={"Content-Type": "application/json"},
        )

    def test_python_ok_and_error(self):
        resp = self._post_syntax([
            {"path": "good.py", "content": "x = 1\n"},
            {"path": "bad.py", "content": "def foo(:\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        results = {r["path"]: r for r in resp.get_json()["results"]}
        self.assertTrue(results["good.py"]["ok"])
        self.assertFalse(results["bad.py"]["ok"])
        self.assertEqual(results["bad.py"]["line"], 1)
        self.assertTrue(results["bad.py"]["message"])

    def test_js_syntax_error_detected(self):
        resp = self._post_syntax([
            {"path": "bad.js", "content": "const x = ;\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        entry = resp.get_json()["results"][0]
        self.assertEqual(entry["path"], "bad.js")
        self.assertFalse(entry["ok"])
        self.assertIsInstance(entry["line"], int)
        self.assertTrue(entry["message"])

    def test_jsx_file_parses(self):
        resp = self._post_syntax([
            {"path": "ok.jsx",
             "content": "const A = () => <div className='x' />;\n"
                        "export default A;\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["results"][0]["ok"])

    def test_valid_ts_ok(self):
        resp = self._post_syntax([
            {"path": "ok.ts", "content": "export const n: number = 1;\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["results"][0]["ok"])

    def test_ts_syntax_error_detected(self):
        resp = self._post_syntax([
            {"path": "bad.tsx", "content": "export const C = () => <div>;\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        entry = resp.get_json()["results"][0]
        self.assertFalse(entry["ok"])
        self.assertTrue(entry["message"])

    def test_type_errors_are_not_syntax_errors(self):
        """--syntax-only: a pure type error must NOT fail the syntax gate."""
        resp = self._post_syntax([
            {"path": "typed.ts", "content": 'const n: number = "str";\n'},
        ])
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["results"][0]["ok"])

    def test_unsupported_files_excluded(self):
        resp = self._post_syntax([
            {"path": "README.md", "content": "# hi\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["results"], [])

    def test_missing_node_on_js_is_503_not_ok(self):
        with patch("analyzer.shutil.which", return_value=None):
            resp = self._post_syntax([
                {"path": "app.js", "content": "const x = 1;\n"},
            ])
        self.assertEqual(resp.status_code, 503)
        self.assertIn("error", resp.get_json())

    def test_python_only_needs_no_node(self):
        """The Python gate must keep working on machines without node."""
        with patch("analyzer.shutil.which", return_value=None):
            resp = self._post_syntax([
                {"path": "ok.py", "content": "x = 1\n"},
            ])
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["results"][0]["ok"])

    def test_path_traversal_rejected(self):
        resp = self._post_syntax([
            {"path": "../../etc/passwd", "content": "x\n"},
        ])
        self.assertEqual(resp.status_code, 400)


class ToolFailureTests(AnalyzerTestCase):
    """A dying/hung tool degrades to a TOOL_TIMEOUT finding, never a crash."""

    @patch("analyzer.subprocess.run")
    def test_tool_timeout_becomes_finding(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="ruff", timeout=30
        )
        resp = self._post([
            {"path": "ok.py", "content": "x = 1\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        findings = resp.get_json()["findings"]
        timeout_findings = [f for f in findings
                            if f["rule"] == "TOOL_TIMEOUT"]
        # Both ruff and bandit runners reported the timeout:
        self.assertEqual({f["source"] for f in timeout_findings},
                         {"ruff", "bandit"})
        for f in timeout_findings:
            self.assertNotIn("Traceback", f["description"])

    @patch("analyzer.subprocess.run")
    def test_tool_crash_becomes_finding(self, mock_run):
        mock_run.side_effect = OSError("boom")
        resp = self._post([
            {"path": "ok.py", "content": "x = 1\n"},
        ])
        self.assertEqual(resp.status_code, 200)
        rules = [f["rule"] for f in resp.get_json()["findings"]]
        self.assertIn("TOOL_ERROR", rules)


class TokenAuthTests(AnalyzerTestCase):
    """Shared-secret mode: with ANALYZER_TOKEN set, only the right token works."""

    def setUp(self):
        super().setUp()
        self._saved = app.config["ANALYZER_TOKEN"]
        app.config["ANALYZER_TOKEN"] = "s3cret-token"

    def tearDown(self):
        app.config["ANALYZER_TOKEN"] = self._saved

    FILES = [{"path": "a.py", "content": "x = 1\n"}]

    def test_missing_token_rejected_401(self):
        resp = self._post(self.FILES)
        self.assertEqual(resp.status_code, 401)

    def test_wrong_token_rejected_401(self):
        resp = self._post(self.FILES, token="wrong")
        self.assertEqual(resp.status_code, 401)

    def test_correct_token_accepted(self):
        resp = self._post(self.FILES, token="s3cret-token")
        self.assertEqual(resp.status_code, 200)

    def test_health_stays_open(self):
        """Liveness probes must not need the secret."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)


class InvalidInputTests(AnalyzerTestCase):
    """Validation and rejection."""

    def test_invalid_json_returns_400(self):
        resp = self.client.post(
            "/analyze",
            data=b"not json",
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_missing_files_returns_400(self):
        resp = self.client.post(
            "/analyze",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_files_list_returns_400(self):
        resp = self._post([])
        self.assertEqual(resp.status_code, 400)

    def test_too_many_files_returns_400(self):
        files = [
            {"path": f"f{i}.py", "content": "x=1\n"} for i in range(101)
        ]
        resp = self._post(files)
        self.assertEqual(resp.status_code, 400)

    def test_oversized_file_returns_400(self):
        big = "x" * 200_001
        resp = self._post([{"path": "big.py", "content": big}])
        self.assertEqual(resp.status_code, 400)

    def test_sensitive_env_rejected(self):
        resp = self._post([
            {"path": ".env", "content": "SECRET=abc\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_sensitive_pem_rejected(self):
        resp = self._post([
            {"path": "server.pem", "content": "-----BEGIN KEY-----\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_sensitive_id_rsa_rejected(self):
        resp = self._post([
            {"path": "id_rsa", "content": "PRIVATE KEY\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_path_traversal_rejected(self):
        resp = self._post([
            {"path": "../../etc/passwd", "content": "x\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_absolute_path_rejected(self):
        resp = self._post([
            {"path": "/etc/passwd", "content": "x\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_duplicate_path_rejected(self):
        resp = self._post([
            {"path": "a.py", "content": "x=1\n"},
            {"path": "a.py", "content": "y=2\n"},
        ])
        self.assertEqual(resp.status_code, 400)

    def test_non_string_content_rejected(self):
        resp = self._post([
            {"path": "a.py", "content": 42},
        ])
        self.assertEqual(resp.status_code, 400)


class HealthTests(AnalyzerTestCase):
    """Health endpoint."""

    def test_health_ok(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
