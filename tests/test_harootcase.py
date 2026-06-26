"""Integration and regression tests for HARootCase.py.

Stdlib-only (unittest), no committed fixture files: every test builds its
synthetic HAR JSON in a tempfile.TemporaryDirectory() so nothing ever lands
near the repo root, where main()'s own auto-discovery could pick it up.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "HARootCase.py")
sys.path.insert(0, REPO_ROOT)

import HARootCase as hc  # noqa: E402


def make_entry(url, method="GET", status=200, time_total=50.0, wait=10.0,
                mime="text/html", response_text="", request_query_text=None,
                response_headers=None, set_cookie=None, post_data_text=None,
                transfer_size=500, request_headers=None, dns=0, connect=0):
    """Build a single raw HAR 'entries[]' dict."""
    full_url = url + (f"?{request_query_text}" if request_query_text else "")
    headers = list(response_headers or [])
    if set_cookie is not None:
        headers.append({"name": "Set-Cookie", "value": set_cookie})
    request = {
        "method": method, "url": full_url,
        "headers": list(request_headers or []), "cookies": [], "queryString": [],
    }
    if post_data_text is not None:
        request["postData"] = {"mimeType": "text/plain", "text": post_data_text}
    return {
        "startedDateTime": "2026-01-01T00:00:00.000Z",
        "time": time_total,
        "request": request,
        "response": {
            "status": status, "statusText": "OK" if status == 200 else "ERR",
            "httpVersion": "HTTP/1.1",
            "headers": headers, "cookies": [],
            "content": {"size": transfer_size, "mimeType": mime, "text": response_text},
            "_transferSize": transfer_size,
        },
        "cache": {},
        "timings": {"blocked": 0, "dns": dns, "connect": connect, "ssl": -1,
                     "send": 0, "wait": wait, "receive": max(time_total - wait, 0)},
    }


def make_har(entries, on_content_load=100.0, on_load=200.0, page_url="http://example.com/"):
    """Wrap entries[] into a full HAR log dict with one page."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "pages": [{
                "startedDateTime": "2026-01-01T00:00:00.000Z",
                "id": "page_1", "title": page_url,
                "pageTimings": {"onContentLoad": on_content_load, "onLoad": on_load},
            }],
            "entries": entries,
        }
    }


def write_har(tmpdir, name, har_dict_or_text):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        if isinstance(har_dict_or_text, str):
            fh.write(har_dict_or_text)
        else:
            json.dump(har_dict_or_text, fh)
    return path


class TestParseHar(unittest.TestCase):
    def test_valid_minimal_har_round_trips(self):
        entries = [make_entry("http://example.com/")]
        har_dict = make_har(entries)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, "sample.har", har_dict)
            parsed = hc.parse_har(path)
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed.entries), 1)
        self.assertEqual(len(parsed.pages), 1)
        self.assertEqual(parsed.primary_domain, "example.com")

    def test_malformed_json_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, "bad.har", "{not valid json::")
            parsed = hc.parse_har(path)
        self.assertIsNone(parsed)

    def test_missing_file_returns_none(self):
        parsed = hc.parse_har("/nonexistent/path/does_not_exist.har")
        self.assertIsNone(parsed)


class TestHealthScore(unittest.TestCase):
    def test_all_healthy_fast_entries(self):
        entries = [make_entry("http://example.com/", status=200) for _ in range(6)]
        har_dict = make_har(entries)
        with tempfile.TemporaryDirectory() as tmp:
            har = hc.parse_har(write_har(tmp, "h.har", har_dict))
        hs = hc.compute_health_score(har)
        self.assertEqual(hs.score, 100)
        self.assertEqual(hs.label, hc.HealthLabel.HEALTHY)

    def test_5xx_errors_penalize_score(self):
        # 5xx penalty is capped at 30 points (min(errors_5xx * 10, 30)),
        # so 4 errors hits the cap: 100 - 30 = 70 (still the HEALTHY boundary).
        entries = (
            [make_entry("http://example.com/api/data", status=500) for _ in range(4)]
            + [make_entry("http://example.com/", status=200)]
        )
        har_dict = make_har(entries)
        with tempfile.TemporaryDirectory() as tmp:
            har = hc.parse_har(write_har(tmp, "h.har", har_dict))
        hs = hc.compute_health_score(har)
        self.assertEqual(hs.score, 70)
        self.assertEqual(hs.label, hc.HealthLabel.HEALTHY)

    def test_status_0_entries_penalize_score(self):
        entries = [make_entry("http://example.com/", status=0) for _ in range(6)]
        har_dict = make_har(entries)
        with tempfile.TemporaryDirectory() as tmp:
            har = hc.parse_har(write_har(tmp, "h.har", har_dict))
        hs = hc.compute_health_score(har)
        self.assertEqual(hs.score, 70)
        self.assertEqual(hs.label, hc.HealthLabel.HEALTHY)

    def test_null_page_timings_penalize_score(self):
        entries = [make_entry("http://example.com/", status=200) for _ in range(6)]
        har_dict = make_har(entries, on_content_load=None, on_load=None)
        with tempfile.TemporaryDirectory() as tmp:
            har = hc.parse_har(write_har(tmp, "h.har", har_dict))
        hs = hc.compute_health_score(har)
        self.assertEqual(hs.score, 60)
        self.assertEqual(hs.label, hc.HealthLabel.DEGRADED)

    def test_few_entries_penalize_score(self):
        entries = [make_entry("http://example.com/", status=200) for _ in range(3)]
        har_dict = make_har(entries)
        with tempfile.TemporaryDirectory() as tmp:
            har = hc.parse_har(write_har(tmp, "h.har", har_dict))
        hs = hc.compute_health_score(har)
        self.assertEqual(hs.score, 85)
        self.assertEqual(hs.label, hc.HealthLabel.HEALTHY)


class TestDifferentialAnalysis(unittest.TestCase):
    def setUp(self):
        ok_entries = [
            make_entry("http://example.com/"),
            make_entry("http://example.com/assets/index.abc123.js"),
            make_entry("http://example.com/api/users", status=200),
        ]
        ko_entries = [
            make_entry("http://example.com/"),
            make_entry("http://example.com/api/users", status=500),
        ]
        self.tmp = tempfile.TemporaryDirectory()
        ok_path = write_har(self.tmp.name, "ok.har", make_har(ok_entries))
        ko_path = write_har(self.tmp.name, "ko.har",
                             make_har(ko_entries, on_content_load=None, on_load=None))
        self.har_ok = hc.parse_har(ok_path)
        self.har_ko = hc.parse_har(ko_path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_in_ko_detected(self):
        findings = hc.differential_analysis(self.har_ok, self.har_ko)
        missing_findings = [f for f in findings if f.finding_type == "MISSING_IN_KO"]
        self.assertTrue(missing_findings, "expected a MISSING_IN_KO finding for the missing JS bundle")
        bundle_finding = next(f for f in missing_findings if "SPA-BUNDLE" in f.title)
        self.assertEqual(bundle_finding.severity, hc.Severity.CRITICAL)

    def test_status_mismatch_detected(self):
        findings = hc.differential_analysis(self.har_ok, self.har_ko)
        mismatch = [f for f in findings if f.finding_type == "STATUS_MISMATCH"]
        self.assertEqual(len(mismatch), 1)
        self.assertIn("GET /api/users", mismatch[0].detail)


class TestSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = hc.SecurityScanner()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _entries_from(self, entry_dicts):
        har_dict = make_har(entry_dicts)
        path = write_har(self.tmp.name, f"s{id(entry_dicts)}.har", har_dict)
        return hc.parse_har(path).entries

    def test_email_in_body_detected(self):
        entries = self._entries_from([
            make_entry("http://example.com/api/data",
                       response_text='{"contact": "someone@example.com"}'),
        ])
        findings = self.scanner.scan_pii(entries)
        self.assertTrue(any(f.finding_type == "PII_EMAIL" for f in findings))

    def test_credit_card_luhn_valid_detected(self):
        entries = self._entries_from([
            make_entry("http://example.com/api/data",
                       response_text="Card number: 4111111111111111 end"),
        ])
        findings = self.scanner.scan_pii(entries)
        self.assertTrue(any(f.finding_type == "PII_CREDIT_CARD" for f in findings))

    def test_credit_card_luhn_invalid_rejected(self):
        entries = self._entries_from([
            make_entry("http://example.com/api/data",
                       response_text="Card number: 4111111111111112 end"),
        ])
        findings = self.scanner.scan_pii(entries)
        self.assertFalse(any(f.finding_type == "PII_CREDIT_CARD" for f in findings))

    def test_api_key_in_url_detected(self):
        entries = self._entries_from([
            make_entry("http://example.com/api/data", request_query_text="api_key=SECRET123"),
        ])
        findings = self.scanner.scan_pii(entries)
        self.assertTrue(any(f.finding_type == "PII_API_KEY_IN_URL" for f in findings))

    def test_missing_security_headers_detected(self):
        entries = self._entries_from([
            make_entry("http://example.com/", status=200, mime="text/html"),
        ])
        findings = self.scanner.check_security_headers(entries)
        self.assertEqual(len(findings), len(hc.SecurityScanner.REQUIRED_SECURITY_HEADERS))

    def test_insecure_cookie_detected(self):
        entries = self._entries_from([
            make_entry("http://example.com/", set_cookie="session=abc123"),
        ])
        findings = self.scanner.check_cookies(entries)
        self.assertEqual(len(findings), 1)
        self.assertIn("Secure", findings[0].detail)

    def test_secure_cookie_not_flagged(self):
        entries = self._entries_from([
            make_entry("http://example.com/",
                       set_cookie="session=abc123; Secure; HttpOnly; SameSite=Strict"),
        ])
        findings = self.scanner.check_cookies(entries)
        self.assertEqual(findings, [])


def _load_kb():
    """Load the real on-disk knowledge base (not the mutable hc.KNOWLEDGE_BASE global)."""
    kb_path = os.path.join(REPO_ROOT, "har_known_issues.json")
    with open(kb_path, "r", encoding="utf-8") as fh:
        return json.load(fh)["patterns"]


class TestKnowledgeBasePatterns(unittest.TestCase):
    """Verifies har_known_issues.json patterns actually fire through RuleEngine."""

    def setUp(self):
        self.patterns = _load_kb()
        self.engine = hc.RuleEngine(self.patterns)
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _matches_for(self, entries, page_url="http://example.com/", **har_kwargs):
        path = write_har(self.tmp.name, f"k{id(entries)}.har",
                          make_har(entries, page_url=page_url, **har_kwargs))
        har = hc.parse_har(path)
        return self.engine.evaluate_all(har)

    def test_kb_loads_at_least_21_patterns(self):
        self.assertGreaterEqual(len(self.patterns), 21)
        ids = [p["id"] for p in self.patterns]
        self.assertEqual(len(ids), len(set(ids)), "duplicate pattern ids in KB")

    def test_backend_overload_5xx_still_fires(self):
        # Regression: an original (pre-expansion) pattern must still trigger.
        matches = self._matches_for([make_entry("http://example.com/api/data", status=500)])
        self.assertIn("BACKEND_OVERLOAD_5XX", [m.pattern_id for m in matches])

    def test_h1_hol_blocking_fires_on_many_h1_resources(self):
        entries = [make_entry(f"http://example.com/r{i}") for i in range(61)]
        matches = self._matches_for(entries)
        self.assertIn("H1_HOL_BLOCKING", [m.pattern_id for m in matches])

    def test_h1_hol_blocking_does_not_fire_below_threshold(self):
        entries = [make_entry(f"http://example.com/r{i}") for i in range(10)]
        matches = self._matches_for(entries)
        self.assertNotIn("H1_HOL_BLOCKING", [m.pattern_id for m in matches])

    def test_hsts_missing_fires_on_https_document(self):
        matches = self._matches_for(
            [make_entry("https://example.com/", status=200)],
            page_url="https://example.com/",
        )
        self.assertIn("HSTS_MISSING", [m.pattern_id for m in matches])

    def test_jwt_token_in_url_fires(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        matches = self._matches_for([
            make_entry("http://example.com/page", request_query_text=f"token={jwt}"),
        ])
        self.assertIn("JWT_TOKEN_IN_URL", [m.pattern_id for m in matches])

    def test_open_redirect_risk_fires(self):
        matches = self._matches_for([
            make_entry("http://example.com/go", status=302,
                       request_query_text="redirect=https://evil.example.org/phish"),
        ])
        self.assertIn("OPEN_REDIRECT_RISK", [m.pattern_id for m in matches])

    def test_rate_limit_429_fires(self):
        matches = self._matches_for([make_entry("http://example.com/api/data", status=429)])
        self.assertIn("RATE_LIMIT_429", [m.pattern_id for m in matches])

    def test_referrer_leak_third_party_fires(self):
        matches = self._matches_for([
            make_entry("http://thirdparty.com/pixel.gif",
                       request_headers=[{"name": "Referer",
                                          "value": "https://example.com/?session=abcd1234"}]),
        ])
        self.assertIn("REFERRER_LEAK_THIRD_PARTY", [m.pattern_id for m in matches])

    def test_slow_dns_resolution_fires(self):
        matches = self._matches_for([make_entry("http://example.com/", dns=350)])
        self.assertIn("SLOW_DNS_RESOLUTION", [m.pattern_id for m in matches])

    def test_slow_tcp_connect_fires(self):
        matches = self._matches_for([make_entry("http://example.com/", connect=350)])
        self.assertIn("SLOW_TCP_CONNECT", [m.pattern_id for m in matches])

    def test_third_party_resource_blocked_fires(self):
        matches = self._matches_for([
            make_entry("http://thirdparty.com/widget.js", status=0),
        ])
        self.assertIn("THIRD_PARTY_RESOURCE_BLOCKED", [m.pattern_id for m in matches])


class TestEndToEnd(unittest.TestCase):
    def _run(self, args, cwd=None):
        return subprocess.run(
            [sys.executable, SCRIPT_PATH, *args, "--no-html", "--no-open"],
            capture_output=True, text=True, cwd=cwd, timeout=30,
        )

    def test_healthy_fixture_exits_zero(self):
        entries = [make_entry("http://example.com/", status=200) for _ in range(6)]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, "healthy.har", make_har(entries))
            result = self._run([path])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_broken_fixture_standalone_mode_exits_zero(self):
        entries = (
            [make_entry("http://example.com/api/data", status=500) for _ in range(3)]
            + [make_entry("http://example.com/", status=0)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, "broken.har",
                              make_har(entries, on_content_load=None, on_load=None))
            result = self._run([path])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_differential_mode_exits_zero(self):
        ok_entries = [make_entry("http://example.com/", status=200) for _ in range(6)]
        ko_entries = [make_entry("http://example.com/", status=500) for _ in range(4)]
        with tempfile.TemporaryDirectory() as tmp:
            write_har(tmp, "a_healthy.har", make_har(ok_entries))
            write_har(tmp, "b_broken.har",
                      make_har(ko_entries, on_content_load=None, on_load=None))
            result = self._run([tmp])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_nonexistent_path_exits_nonzero(self):
        result = self._run(["/tmp/this_path_should_not_exist_xyz123/"])
        self.assertEqual(result.returncode, 1)

    def test_malformed_har_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, "bad.har", "{not valid json::")
            result = self._run([path])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)


class TestLocalAiSanitization(unittest.TestCase):
    def test_is_local_endpoint(self):
        for ok in ("http://localhost:11434/api/generate", "http://127.0.0.1:11434",
                   "http://[::1]:11434", "http://192.168.1.10:11434",
                   "http://10.0.0.5:11434", "http://172.16.4.2:11434"):
            self.assertTrue(hc.is_local_endpoint(ok), ok)
        for bad in ("http://8.8.8.8:11434", "https://api.openai.com/v1",
                    "http://example.com/api"):
            self.assertFalse(hc.is_local_endpoint(bad), bad)

    def test_redact_sensitive_text(self):
        txt = ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV "
               "email user.name@example.com card 4111 1111 1111 1111 "
               "Cookie: session=topsecretcookievalue")
        red = hc.redact_sensitive_text(txt)
        for leak in ("eyJhbGci", "user.name@example.com", "4111 1111",
                     "topsecretcookievalue"):
            self.assertNotIn(leak, red)
        self.assertIn(hc._REDACTED, red)

    def test_redact_query_params_in_free_text(self):
        red = hc.redact_sensitive_text(
            "GET https://api.x.com/p?token=SHORTSECRET&apikey=abc123&id=5")
        self.assertNotIn("SHORTSECRET", red)
        self.assertNotIn("abc123", red)
        self.assertIn("id=5", red)  # non-sensitive params preserved

    def test_redact_url(self):
        red = hc._redact_url(
            "https://api.x.com/v1/me?access_token=SECRET&page=2&email=a@b.com")
        self.assertNotIn("SECRET", red)
        self.assertIn("page=2", red)

    def test_sanitize_ai_value_recursive(self):
        data = {"a": ["token=DEADBEEFsecretvalue", {"b": "x@y.com"}], "n": 5}
        out = hc.sanitize_ai_value(data)
        blob = json.dumps(out)
        self.assertNotIn("DEADBEEFsecretvalue", blob)
        self.assertNotIn("x@y.com", blob)
        self.assertEqual(out["n"], 5)

    def test_validate_local_ai_har_result_coerces_schema(self):
        out = hc.validate_local_ai_har_result({
            "root_cause_probabile": "API 500",
            "confidenza": "ALTA",
            "cause_alternative": "una sola stringa",  # should become a list
            "priorita_remediation": [{"priorita": 1, "azione": "fix"}],
            "extra_ignored": "x",
        })
        self.assertEqual(out["cause_alternative"], ["una sola stringa"])
        self.assertIsInstance(out["evidenze_forti"], list)
        self.assertEqual(out["priorita_remediation"][0]["azione"], "fix")
        self.assertNotIn("extra_ignored", out)

    def test_validate_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            hc.validate_local_ai_har_result(["not", "a", "dict"])

    def test_parse_model_json_salvages_truncated(self):
        good = hc._parse_model_json('{"a": 1, "b": [1,2,3]}')
        self.assertEqual(good["a"], 1)
        # Trailing junk after a complete object is tolerated.
        salv = hc._parse_model_json('prefix {"a": 1} trailing garbage')
        self.assertEqual(salv["a"], 1)

    def test_render_html_unavailable(self):
        html = hc.render_local_ai_html_section(
            {"_unavailable_reason": "Ollama spento"})
        self.assertIn("Local AI Review non disponibile", html)
        self.assertIn("Ollama spento", html)

    def test_render_html_full(self):
        html = hc.render_local_ai_html_section({
            "root_cause_probabile": "API backend 500",
            "confidenza": "ALTA",
            "cause_alternative": ["timeout DB"],
            "priorita_remediation": [
                {"azione": "rollback", "impatto": "ALTO",
                 "complessita": "BASSA", "motivazione": "regressione"}],
            "executive_summary": "Errore lato server.",
        })
        self.assertIn("API backend 500", html)
        self.assertIn("rollback", html)
        self.assertIn("Usare come supporto", html)

    def test_strict_local_blocks_public_endpoint(self):
        class _Args:
            local_ai_endpoint = "http://8.8.8.8:11434/api/generate"
            local_ai_model = "llama3.1:8b"
            local_ai_strict_local = True
            local_ai_raw = False
            local_ai_timeout = 5
            local_ai_max_entries = 40
        res = hc.AnalysisResult(
            mode=hc.AnalysisMode.STANDALONE, parsed_hars=[], health_scores={})
        out = hc.run_local_ai_review(res, _Args())
        self.assertIn("_unavailable_reason", out)
        self.assertIn("non locale", out["_unavailable_reason"])


if __name__ == "__main__":
    unittest.main()
