#!/usr/bin/env python3

import argparse
import html as html_module
import json
import math
import os
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse
import webbrowser
from datetime import datetime

__version__ = "3.0.0"

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURAZIONE
# ═══════════════════════════════════════════════════════════════════════════════
LATENCY_THRESHOLD_MS = 1000
HIGH_LATENCY_WARN_MS = 500
BODY_SNIPPET_MAX = 2000
WATERFALL_MAX_ENTRIES = 200

# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI COLORS
# ═══════════════════════════════════════════════════════════════════════════════
USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

RED     = lambda t: _c("1;31", t)
YELLOW  = lambda t: _c("1;33", t)
GREEN   = lambda t: _c("1;32", t)
CYAN    = lambda t: _c("1;36", t)
BOLD    = lambda t: _c("1", t)
DIM     = lambda t: _c("2", t)
MAGENTA = lambda t: _c("1;35", t)

SEVERITY_ICON = {
    "CRITICAL": RED("[CRITICAL]"),
    "HIGH":     RED("[HIGH]    "),
    "WARNING":  YELLOW("[WARNING] "),
    "MEDIUM":   YELLOW("[MEDIUM]  "),
    "INFO":     DIM("[INFO]    "),
}

HEALTH_LABEL_STR = {
    "HEALTHY":  GREEN("HEALTHY"),
    "DEGRADED": YELLOW("DEGRADED"),
    "BROKEN":   RED("BROKEN"),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WARNING = "WARNING"
    MEDIUM = "MEDIUM"
    INFO = "INFO"

class HealthLabel(Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    BROKEN = "BROKEN"

class AnalysisMode(Enum):
    DIFFERENTIAL = "DIFFERENTIAL"
    STANDALONE = "STANDALONE"
    ALL_HEALTHY = "ALL_HEALTHY"

class FindingCategory(Enum):
    AVAILABILITY = "AVAILABILITY"
    PERFORMANCE = "PERFORMANCE"
    SECURITY = "SECURITY"

class ResourceType(Enum):
    API = "API"
    SPA_BUNDLE = "SPA-BUNDLE"
    SPA_CHUNK = "SPA-CHUNK"
    FONT = "FONT"
    IMAGE = "IMAGE"
    STYLESHEET = "STYLESHEET"
    SCRIPT = "SCRIPT"
    DOCUMENT = "DOCUMENT"
    EXTERNAL = "EXTERNAL"
    STATIC = "STATIC"


# ═══════════════════════════════════════════════════════════════════════════════
#  DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HarTimings:
    blocked: float = 0.0
    dns: float = 0.0
    connect: float = 0.0
    ssl: float = 0.0
    send: float = 0.0
    wait: float = 0.0
    receive: float = 0.0

@dataclass
class HarEntry:
    """Parsed representation of a single HAR entry."""
    url: str
    method: str
    status: int
    status_text: str
    http_version: str
    mime_type: str
    transfer_size: int
    body_size: int
    time_total: float
    timings: HarTimings
    resource_type: ResourceType
    is_cached: bool
    domain: str
    path: str
    request_headers: dict
    response_headers: dict
    request_cookies: list
    response_cookies: list
    response_error: str
    connection_id: str
    response_body_snippet: str = ""
    request_body_snippet: str = ""
    _raw: dict = field(default_factory=dict, repr=False)

    @property
    def entry_key(self) -> str:
        return f"{self.method} {self.path}"

@dataclass
class HarPage:
    page_id: str
    title: str
    on_content_load: Optional[float]
    on_load: Optional[float]

@dataclass
class ParsedHar:
    """Fully parsed HAR log."""
    file_path: str
    file_name: str
    pages: list
    entries: list
    primary_domain: str
    protocols: set

@dataclass
class HealthScore:
    score: int
    label: HealthLabel
    reasons: list

@dataclass
class Finding:
    """A single diagnostic finding."""
    severity: Severity
    category: FindingCategory
    finding_type: str
    title: str
    detail: str
    insight: str = ""
    solution: str = ""
    evidence: dict = field(default_factory=dict)
    kb_pattern_id: str = ""

@dataclass
class KBMatch:
    pattern_id: str
    pattern_name: str
    severity: str
    confidence: str
    evidence: dict
    diagnosis: str
    solutions: list
    references: list = field(default_factory=list)
    category: str = ""
    impact_score: int = 0

@dataclass
class PerformanceStats:
    ttfb_p50: float = 0.0
    ttfb_p90: float = 0.0
    ttfb_p99: float = 0.0
    download_p50: float = 0.0
    download_p90: float = 0.0
    download_p99: float = 0.0
    total_transfer_bytes: int = 0
    uncompressed_text_bytes: int = 0
    uncompressed_entries: list = field(default_factory=list)
    oversized_images: list = field(default_factory=list)

@dataclass
class SecurityReport:
    pii_findings: list = field(default_factory=list)
    header_findings: list = field(default_factory=list)
    cookie_findings: list = field(default_factory=list)

@dataclass
class AnalysisResult:
    """Complete analysis output."""
    mode: AnalysisMode
    parsed_hars: list
    health_scores: dict
    red_flags: list = field(default_factory=list)
    differential_findings: list = field(default_factory=list)
    kb_matches: list = field(default_factory=list)
    performance: dict = field(default_factory=dict)
    security: dict = field(default_factory=dict)
    root_cause_text: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS GENERICI
# ═══════════════════════════════════════════════════════════════════════════════

def short_url(url: str, maxlen: int = 90) -> str:
    if len(url) <= maxlen:
        return url
    return url[:maxlen - 3] + "..."

def get_url_path(url: str) -> str:
    return urlparse(url).path

def get_domain(url: str) -> str:
    return urlparse(url).netloc

def _entry_looks_like_document(path: str) -> bool:
    base = os.path.basename(path)
    if "." not in base:
        return True
    ext = base.rsplit(".", 1)[-1].lower()
    return ext in ("html", "htm", "php", "asp", "aspx", "jsp")

def _is_entry_cached(entry_raw: dict) -> bool:
    resp = entry_raw.get("response", {})
    return resp.get("_transferSize", -1) == 0 and entry_raw.get("time", 999) < 5

def discover_har_files(paths: list) -> list:
    """Scopre tutti i file .har dai path forniti."""
    result = []
    for p in paths:
        if os.path.isfile(p) and p.lower().endswith(".har"):
            result.append(os.path.abspath(p))
        elif os.path.isdir(p):
            for fname in sorted(os.listdir(p)):
                if fname.lower().endswith(".har"):
                    result.append(os.path.abspath(os.path.join(p, fname)))
    return result

def sanitize_dropped_paths(paths: list) -> list:
    cleaned = []
    for p in paths:
        p = p.strip().strip("'\"")
        p = p.replace("\\ ", " ")
        if p:
            cleaned.append(p)
    return cleaned

def percentile(values: list, p: float) -> float:
    """Compute p-th percentile using linear interpolation."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    if n == 1:
        return sorted_v[0]
    k = (n - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, n - 1)
    d = k - f
    return sorted_v[f] + d * (sorted_v[c] - sorted_v[f])


# ═══════════════════════════════════════════════════════════════════════════════
#  RESOURCE CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

_RESOURCE_PATTERNS = [
    ("API",        lambda u, p: any(seg in p for seg in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/"])),
    ("API",        lambda u, p: p.startswith("/console-web-server/")),
    ("SPA-BUNDLE", lambda u, p: "/assets/" in p and p.endswith((".js", ".css")) and any(
        k in p for k in ["index.", "vendor.", "chunk.", "main.", "app.", "bundle."])),
    ("SPA-CHUNK",  lambda u, p: "/assets/" in p and p.endswith((".js", ".css")) and
        any(c.isupper() for c in os.path.basename(p).split(".")[0])),
    ("FONT",       lambda u, p: p.endswith((".woff", ".woff2", ".ttf", ".otf", ".eot"))),
    ("IMAGE",      lambda u, p: p.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"))),
    ("STYLESHEET", lambda u, p: p.endswith(".css")),
    ("SCRIPT",     lambda u, p: p.endswith(".js")),
    ("DOCUMENT",   lambda u, p: _entry_looks_like_document(p)),
]

def classify_resource(url: str, path: str, domain: str, primary_domain: str) -> ResourceType:
    if primary_domain and domain and domain != primary_domain:
        return ResourceType.EXTERNAL
    for label, matcher in _RESOURCE_PATTERNS:
        if matcher(url, path):
            return ResourceType[label.replace("-", "_")]
    return ResourceType.STATIC

def detect_primary_domain(log_raw: dict) -> str:
    for page in log_raw.get("pages", []):
        title = page.get("title", "")
        if title.startswith("http"):
            return get_domain(title)
    entries = log_raw.get("entries", [])
    if entries:
        return get_domain(entries[0]["request"]["url"])
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
#  HAR PARSER — Raw JSON to Dataclasses
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_headers_dict(headers_list: list) -> dict:
    """Convert HAR headers array to lowercase-key dict."""
    result = {}
    for h in (headers_list or []):
        name = h.get("name", "").lower()
        if name:
            result[name] = h.get("value", "")
    return result

def _parse_timings(raw_timings: dict) -> HarTimings:
    def _val(key: str) -> float:
        v = raw_timings.get(key, -1)
        return max(0.0, float(v)) if v is not None and v >= 0 else 0.0
    return HarTimings(
        blocked=_val("blocked"), dns=_val("dns"), connect=_val("connect"),
        ssl=_val("ssl"), send=_val("send"), wait=_val("wait"), receive=_val("receive"),
    )

def _parse_entry(raw: dict, primary_domain: str) -> HarEntry:
    req = raw.get("request", {})
    resp = raw.get("response", {})
    content = resp.get("content", {})
    raw_timings = raw.get("timings", {})
    url = req.get("url", "")
    path = get_url_path(url)
    domain = get_domain(url)
    method = req.get("method", "GET")
    status = resp.get("status", 0)
    transfer_size = resp.get("_transferSize", content.get("size", -1))
    if transfer_size is None:
        transfer_size = -1
    cached = _is_entry_cached(raw)
    timings = _parse_timings(raw_timings)
    req_headers = _extract_headers_dict(req.get("headers", []))
    resp_headers = _extract_headers_dict(resp.get("headers", []))
    res_type = classify_resource(url, path, domain, primary_domain)

    # Body snippets for PII scanning
    resp_body = ""
    resp_text = content.get("text", "")
    if resp_text and isinstance(resp_text, str):
        resp_body = resp_text[:BODY_SNIPPET_MAX]
    req_body = ""
    post_data = req.get("postData", {})
    if post_data:
        req_text = post_data.get("text", "")
        if req_text and isinstance(req_text, str):
            req_body = req_text[:BODY_SNIPPET_MAX]

    return HarEntry(
        url=url, method=method, status=status,
        status_text=resp.get("statusText", ""),
        http_version=resp.get("httpVersion", ""),
        mime_type=content.get("mimeType", resp.get("content", {}).get("mimeType", "")),
        transfer_size=int(transfer_size) if transfer_size is not None else -1,
        body_size=content.get("size", -1) or -1,
        time_total=raw.get("time", 0) or 0,
        timings=timings, resource_type=res_type, is_cached=cached,
        domain=domain, path=path,
        request_headers=req_headers, response_headers=resp_headers,
        request_cookies=req.get("cookies", []),
        response_cookies=resp.get("cookies", []),
        response_error=resp.get("_error", "") or "",
        connection_id=str(raw.get("_connectionId", "")),
        response_body_snippet=resp_body,
        request_body_snippet=req_body,
        _raw=raw,
    )

def _parse_page(raw: dict) -> HarPage:
    pt = raw.get("pageTimings", {})
    return HarPage(
        page_id=raw.get("id", ""),
        title=raw.get("title", ""),
        on_content_load=pt.get("onContentLoad"),
        on_load=pt.get("onLoad"),
    )

def parse_har(path: str) -> Optional[ParsedHar]:
    """Load and parse a HAR file into structured dataclasses."""
    if not os.path.isfile(path):
        print(RED(f"  [ERRORE] File non trovato: {path}"))
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(RED(f"  [ERRORE] Impossibile decodificare {path}: {exc}"))
        return None

    log_raw = data.get("log", data)
    primary_domain = detect_primary_domain(log_raw)
    entries = [_parse_entry(e, primary_domain) for e in log_raw.get("entries", [])]
    pages = [_parse_page(p) for p in log_raw.get("pages", [])]
    protocols = {e.http_version.lower() for e in entries if e.http_version}

    return ParsedHar(
        file_path=path, file_name=os.path.basename(path),
        pages=pages, entries=entries,
        primary_domain=primary_domain, protocols=protocols,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE — Loading
# ═══════════════════════════════════════════════════════════════════════════════

KNOWLEDGE_BASE: list = []

def load_knowledge_base() -> tuple:
    """Carica la knowledge base da har_known_issues.json.
    Supports both normal execution and PyInstaller frozen bundles."""
    global KNOWLEDGE_BASE
    kb_paths = [
        os.path.join(_get_base_dir(), "har_known_issues.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "har_known_issues.json"),
        os.path.join(os.getcwd(), "har_known_issues.json"),
    ]
    # When frozen, also check the PyInstaller temp extraction dir
    if _is_frozen():
        meipass = getattr(sys, '_MEIPASS', '')
        if meipass:
            kb_paths.insert(0, os.path.join(meipass, "har_known_issues.json"))
    for kb_path in kb_paths:
        if os.path.isfile(kb_path):
            try:
                with open(kb_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                KNOWLEDGE_BASE = data.get("patterns", [])
                return len(KNOWLEDGE_BASE), kb_path
            except (json.JSONDecodeError, KeyError):
                pass
    return 0, None


# ═══════════════════════════════════════════════════════════════════════════════
#  DYNAMIC RULE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# Variables that are computed at the aggregate (whole-HAR) level
_AGGREGATE_VARS = frozenset({
    "protocol", "cached_resources", "network_resources",
    "html_refs_missing", "page_protocol", "null_timings",
})

def _num(v: Any) -> float:
    """Safe numeric conversion."""
    if v is None:
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0

def _is_missing_or_weak(actual: Any, threshold: Any) -> bool:
    """Check if Cache-Control is missing or has max-age < threshold."""
    if actual is None or actual == "":
        return True
    cc = str(actual).lower()
    match = re.search(r'max-age\s*=\s*(\d+)', cc)
    if not match:
        return True
    return int(match.group(1)) < int(threshold)

def _extract_cookie_flags(entry: HarEntry) -> list:
    """Extract flag names from Set-Cookie headers."""
    sc = entry.response_headers.get("set-cookie", "")
    if not sc:
        return []
    flags = []
    parts = sc.split(";")
    for part in parts[1:]:
        name = part.strip().split("=")[0].strip()
        if name:
            flags.append(name)
    return flags


_ENHANCED_DETECTOR_IDS = frozenset({"H2_MULTIPLEX_STALL"})

class RuleEngine:
    """Evaluates detect.logic expressions from the KB JSON."""

    def __init__(self, knowledge_base: list):
        self.patterns = knowledge_base

    def evaluate_all(self, parsed_har: ParsedHar,
                     ref_har: Optional[ParsedHar] = None) -> list:
        """Run all KB patterns against a parsed HAR. Returns KBMatch list."""
        aggregate = self._build_aggregate(parsed_har, ref_har)
        matches = []
        for pattern in self.patterns:
            detect = pattern.get("detect", {})
            logic = detect.get("logic")
            if not logic:
                continue
            match = self._evaluate_pattern(pattern, logic, aggregate, parsed_har)
            if match:
                matches.append(match)
        return matches

    def _build_aggregate(self, har: ParsedHar,
                         ref: Optional[ParsedHar] = None) -> dict:
        """Build aggregate context from the full HAR."""
        entries = har.entries
        agg = {}
        # Protocol
        is_h2 = any("h2" in p or "http/2" in p for p in har.protocols)
        agg["protocol"] = "h2" if is_h2 else ("http/1.1" if har.protocols else "unknown")
        agg["cached_resources"] = sum(1 for e in entries if e.is_cached)
        agg["network_resources"] = len(entries) - agg["cached_resources"]
        # Page protocol
        if har.pages and har.pages[0].title.startswith("http"):
            agg["page_protocol"] = urlparse(har.pages[0].title).scheme
        elif entries:
            agg["page_protocol"] = urlparse(entries[0].url).scheme
        else:
            agg["page_protocol"] = "unknown"
        # Null timings
        agg["null_timings"] = any(p.on_load is None for p in har.pages) if har.pages else False
        # HTML refs missing — need full body of first document entry, not snippet
        agg["html_refs_missing"] = False
        html_script_paths = []
        if entries:
            # Get the full response body from the raw entry for script tag analysis
            first_raw = entries[0]._raw
            first_body = first_raw.get("response", {}).get("content", {}).get("text", "")
            if first_body:
                script_tags = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', first_body)
                html_script_paths = script_tags
                if script_tags and ref:
                    ref_keys = {e.entry_key for e in ref.entries}
                    har_keys = {e.entry_key for e in entries}
                    for sp in script_tags:
                        for rk in ref_keys - har_keys:
                            if sp in rk:
                                agg["html_refs_missing"] = True
                                break
        agg["_html_script_paths"] = html_script_paths
        # Missing from OK
        if ref:
            ok_keys = {e.entry_key for e in ref.entries}
            ko_keys = {e.entry_key for e in entries}
            agg["_missing_from_ok"] = ok_keys - ko_keys
            agg["_missing_count"] = len(agg["_missing_from_ok"])
        else:
            agg["_missing_from_ok"] = set()
            agg["_missing_count"] = 0
        return agg

    def _evaluate_pattern(self, pattern: dict, logic: dict,
                          aggregate: dict, har: ParsedHar) -> Optional[KBMatch]:
        """Evaluate one KB pattern."""
        pid = pattern.get("id", "")

        # Patterns with enhanced detectors: always run the enhanced detector first
        # (it has more nuanced logic than the simple JSON rule)
        if pid in _ENHANCED_DETECTOR_IDS:
            enhanced = self._run_enhanced_detector(pattern, aggregate, har)
            if enhanced is not None:
                return enhanced
            # If enhanced detector returns None, fall through to normal eval

        is_aggregate = self._is_aggregate_logic(logic)

        if is_aggregate:
            if self._eval_logic(logic, aggregate, None):
                return self._build_match(pattern, "HIGH", {"aggregate_match": True})
            return None
        else:
            # Per-entry: find all matching entries
            matching_entries = []
            for entry in har.entries:
                if self._eval_logic(logic, aggregate, entry):
                    matching_entries.append(entry)
            if not matching_entries:
                return None
            count = len(matching_entries)
            total = len(har.entries)
            if count >= 5 or (total > 0 and count / total > 0.3):
                confidence = "HIGH"
            elif count >= 2:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            sample_urls = [short_url(e.url, 70) for e in matching_entries[:5]]
            return self._build_match(pattern, confidence, {
                "matching_entries": count,
                "total_entries": total,
                "sample_urls": sample_urls,
            })

    def _is_aggregate_logic(self, logic: dict) -> bool:
        """Check if all variables in the logic tree are aggregate-level."""
        vars_used = self._collect_vars(logic)
        return all(v in _AGGREGATE_VARS for v in vars_used)

    def _collect_vars(self, logic: dict) -> set:
        """Recursively collect all variable names from a logic tree."""
        result = set()
        if "and" in logic:
            for sub in logic["and"]:
                result |= self._collect_vars(sub)
        elif "or" in logic:
            for sub in logic["or"]:
                result |= self._collect_vars(sub)
        elif "var" in logic:
            result.add(logic["var"])
        return result

    def _eval_logic(self, logic: dict, aggregate: dict,
                    entry: Optional[HarEntry]) -> bool:
        """Recursively evaluate a logic tree."""
        if "and" in logic:
            return all(self._eval_logic(sub, aggregate, entry) for sub in logic["and"])
        if "or" in logic:
            return any(self._eval_logic(sub, aggregate, entry) for sub in logic["or"])
        return self._eval_condition(logic, aggregate, entry)

    def _eval_condition(self, cond: dict, aggregate: dict,
                        entry: Optional[HarEntry]) -> bool:
        """Evaluate a single {var, op, val} condition."""
        var_name = cond.get("var", "")
        op = cond.get("op", "eq")
        expected = cond.get("val")
        actual = self._resolve_var(var_name, aggregate, entry)
        return self._compare(actual, op, expected)

    def _resolve_var(self, var_path: str, aggregate: dict,
                     entry: Optional[HarEntry]) -> Any:
        """Resolve a variable path to its value."""
        # Check aggregate first
        if var_path in aggregate:
            return aggregate[var_path]
        if entry is None:
            return None
        # Per-entry resolution
        if var_path == "status":
            return entry.status
        if var_path == "mimeType":
            return entry.mime_type
        if var_path == "transferSize":
            return entry.transfer_size
        if var_path == "method":
            return entry.method
        if var_path == "type":
            return entry.resource_type.value.lower()
        if var_path == "error_text":
            return entry.response_error.lower()
        if var_path == "url_query":
            return urlparse(entry.url).query
        if var_path == "request_protocol":
            return urlparse(entry.url).scheme
        if var_path == "time_ssl":
            raw_timings = entry._raw.get("timings", {})
            raw_ssl = raw_timings.get("ssl", -1)
            # ssl=-1 in HAR means "not applicable" (connection reused), NOT failure.
            # Only treat as -1 (failure) if connection was fresh (connect > 0) and ssl is -1.
            raw_connect = raw_timings.get("connect", -1)
            if raw_ssl == -1 and (raw_connect is None or raw_connect <= 0):
                return 0  # reused connection, no SSL phase — not a failure
            return raw_ssl if raw_ssl is not None else -1
        if var_path == "cookie_flags":
            return _extract_cookie_flags(entry)
        if var_path.startswith("header."):
            header_name = var_path[7:].lower()
            val = entry.response_headers.get(header_name)
            if val is None:
                val = entry.request_headers.get(header_name)
            return val
        if var_path.startswith("timings."):
            field_name = var_path[8:]
            return getattr(entry.timings, field_name, None)
        return None

    def _compare(self, actual: Any, op: str, expected: Any) -> bool:
        """Apply a comparison operator."""
        if op == "eq":
            return actual == expected
        if op == "gt":
            return _num(actual) > _num(expected)
        if op == "gte":
            return _num(actual) >= _num(expected)
        if op == "lt":
            return _num(actual) < _num(expected)
        if op == "lte":
            return _num(actual) <= _num(expected)
        if op == "regex":
            try:
                return bool(re.search(str(expected), str(actual or "")))
            except re.error:
                return False
        if op == "contains":
            return str(expected).lower() in str(actual or "").lower()
        if op == "in":
            if isinstance(expected, list):
                actual_lower = str(actual or "").lower()
                return actual_lower in [str(x).lower() for x in expected]
            return False
        if op == "missing":
            if isinstance(expected, list):
                # Check if ANY of the expected values are missing from actual
                actual_flags = [str(f).lower() for f in (actual if isinstance(actual, list) else [])]
                return any(str(v).lower() not in actual_flags for v in expected)
            return actual is None or actual == ""
        if op == "missing_or_weak":
            return _is_missing_or_weak(actual, expected)
        if op == "exists":
            return actual is not None and actual != ""
        return False

    def _run_enhanced_detector(self, pattern: dict, aggregate: dict,
                               har: ParsedHar) -> Optional[KBMatch]:
        """Run enhanced detector for patterns that need deeper analysis."""
        pid = pattern.get("id", "")
        if pid == "H2_MULTIPLEX_STALL":
            return self._detect_h2_enhanced(pattern, aggregate, har)
        return None

    def _detect_h2_enhanced(self, pattern: dict, aggregate: dict,
                            har: ParsedHar) -> Optional[KBMatch]:
        """Enhanced H2 multiplexing stall detection."""
        entries = har.entries
        cached = aggregate.get("cached_resources", 0)
        network = aggregate.get("network_resources", 0)
        total = len(entries)

        # No HTTP errors (requests simply never fire)
        has_http_errors = any(e.status >= 400 or e.status == 0 for e in entries)
        if has_http_errors:
            return self._build_match(pattern, "LOW", {
                "note": "H2 detected but HTTP errors present — may not be pure multiplexing stall",
                "protocol": list(har.protocols),
            })

        # Check HTML script refs missing
        missing_scripts = False
        html_paths = aggregate.get("_html_script_paths", [])
        missing_from_ok = aggregate.get("_missing_from_ok", set())
        for sp in html_paths:
            for mk in missing_from_ok:
                if sp in mk:
                    missing_scripts = True
                    break

        network_ratio = network / max(total, 1)
        few_network = network_ratio < 0.2
        missing_count = aggregate.get("_missing_count", 0)

        null_timings = aggregate.get("null_timings", False)
        if not null_timings:
            return None

        if (missing_count > 5 and few_network) or missing_scripts:
            confidence = "HIGH" if missing_scripts else "MEDIUM"
            return self._build_match(pattern, confidence, {
                "protocol": list(har.protocols),
                "cached_ok": cached,
                "network_requests": network,
                "missing_resources": missing_count,
                "html_refs_missing": missing_scripts,
                "null_timings": null_timings,
            })
        return None

    def _build_match(self, pattern: dict, confidence: str,
                     evidence: dict) -> KBMatch:
        return KBMatch(
            pattern_id=pattern.get("id", ""),
            pattern_name=pattern.get("name", ""),
            severity=pattern.get("severity", "MEDIUM"),
            confidence=confidence,
            evidence=evidence,
            diagnosis=pattern.get("diagnosis", ""),
            solutions=pattern.get("solutions", []),
            references=pattern.get("references", []),
            category=pattern.get("category", ""),
            impact_score=pattern.get("impact_score", 0),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  HEALTH SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def compute_health_score(har: ParsedHar) -> HealthScore:
    """Calcola un punteggio di salute per un HAR (0-100)."""
    score = 100
    reasons = []
    entries = har.entries
    total = max(len(entries), 1)

    # pageTimings
    for page in har.pages:
        if page.on_load is None or page.on_content_load is None:
            score -= 40
            reasons.append("pageTimings nulli (pagina non completata)")
            break

    # HTTP errors
    errors_5xx = sum(1 for e in entries if e.status >= 500)
    errors_4xx = sum(1 for e in entries if 400 <= e.status < 500)
    status_0 = sum(1 for e in entries if e.status == 0)

    if errors_5xx:
        score -= min(errors_5xx * 10, 30)
        reasons.append(f"{errors_5xx} risposte 5xx (errore server)")
    if errors_4xx:
        score -= min(errors_4xx * 5, 20)
        reasons.append(f"{errors_4xx} risposte 4xx (errore client)")
    if status_0:
        score -= min(status_0 * 10, 30)
        reasons.append(f"{status_0} risposte con status 0 (bloccate/cancellate)")

    # Latency
    real_times = [e.time_total for e in entries if not e.is_cached and e.time_total > 0]
    if real_times:
        avg_time = sum(real_times) / len(real_times)
        slow_count = sum(1 for t in real_times if t > LATENCY_THRESHOLD_MS)
        if avg_time > LATENCY_THRESHOLD_MS:
            score -= 10
            reasons.append(f"Latenza media elevata ({avg_time:.0f}ms)")
        if slow_count > 3:
            score -= 5
            reasons.append(f"{slow_count} richieste lente (>{LATENCY_THRESHOLD_MS}ms)")

    # Few entries
    if total < 5:
        score -= 15
        reasons.append(f"Solo {total} richieste (caricamento probabilmente incompleto)")

    # response._error
    resp_errors = sum(1 for e in entries if e.response_error)
    if resp_errors:
        score -= min(resp_errors * 5, 20)
        reasons.append(f"{resp_errors} richieste con _error nel response")

    score = max(0, min(100, score))
    if score >= 70:
        label = HealthLabel.HEALTHY
    elif score >= 40:
        label = HealthLabel.DEGRADED
    else:
        label = HealthLabel.BROKEN

    return HealthScore(score=score, label=label, reasons=reasons)


# ═══════════════════════════════════════════════════════════════════════════════
#  RED FLAG ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_red_flags(har: ParsedHar) -> list:
    """Identifica red flags in un singolo file HAR."""
    findings = []

    for page in har.pages:
        if page.on_content_load is None or page.on_load is None:
            findings.append(Finding(
                severity=Severity.CRITICAL, category=FindingCategory.AVAILABILITY,
                finding_type="NULL_PAGE_TIMINGS",
                title="Page timings nulli",
                detail=f"Page '{page.page_id}': onContentLoad={page.on_content_load}, onLoad={page.on_load}",
                insight="Gli eventi DOMContentLoaded/onLoad non sono scattati. La pagina non ha completato il caricamento.",
                solution=(
                    "1. Aprire la Console del browser e verificare errori JS bloccanti.\n"
                    "2. Verificare nella tab Network se mancano risorse critiche.\n"
                    "3. Controllare se un Service Worker sta servendo una versione stale.\n"
                    "4. Verificare che il server stia restituendo l'HTML completo."
                ),
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO, category=FindingCategory.AVAILABILITY,
                finding_type="PAGE_TIMINGS_OK",
                title="Page timings OK",
                detail=f"Page '{page.page_id}': DOMContentLoaded={page.on_content_load:.0f}ms, onLoad={page.on_load:.0f}ms",
                insight="Caricamento pagina completato correttamente.",
            ))

    for entry in har.entries:
        status = entry.status
        url = entry.url
        wait = entry.timings.wait
        method = entry.method

        if status == 0:
            err_detail = f" Errore: {entry.response_error}" if entry.response_error else ""
            findings.append(Finding(
                severity=Severity.CRITICAL, category=FindingCategory.AVAILABILITY,
                finding_type="STATUS_0",
                title="Richiesta bloccata (status 0)",
                detail=f"Status 0 — {method} {short_url(url)}",
                insight=f"Richiesta bloccata o cancellata.{err_detail}",
                solution=(
                    "1. Verificare i CORS headers sul server.\n"
                    "2. Controllare Content Security Policy.\n"
                    "3. Verificare mixed-content (HTTP su pagina HTTPS).\n"
                    "4. Escludere ad-blocker o estensioni.\n"
                    "5. Verificare timeout di rete / DNS failure."
                ),
            ))
        elif status >= 500:
            findings.append(Finding(
                severity=Severity.CRITICAL, category=FindingCategory.AVAILABILITY,
                finding_type="HTTP_5XX",
                title=f"Errore server {status}",
                detail=f"HTTP {status} {entry.status_text} — {method} {short_url(url)}",
                insight=f"Errore server-side. TTFB: {wait:.0f}ms, totale: {entry.time_total:.0f}ms.",
                solution=(
                    "1. Controllare i log del server per questa URL.\n"
                    "2. Se 502/503/504: verificare stato upstream.\n"
                    "3. Se 500: cercare eccezioni non gestite.\n"
                    "4. Verificare se il problema e' intermittente o persistente."
                ),
            ))
        elif status >= 400:
            solutions_4xx = {
                401: "Verificare token/sessione di autenticazione (scaduto? assente?).",
                403: "Verificare permessi utente e ruoli. Controllare WAF/firewall rules.",
                404: "La risorsa non esiste. Verificare il path, controllare se il deploy e' completo.",
                405: "Method not allowed. Verificare il metodo HTTP corretto.",
                408: "Request timeout. Il server non ha ricevuto la richiesta in tempo.",
                429: "Rate limiting attivo. Ridurre la frequenza delle richieste.",
            }
            findings.append(Finding(
                severity=Severity.WARNING, category=FindingCategory.AVAILABILITY,
                finding_type="HTTP_4XX",
                title=f"Errore client {status}",
                detail=f"HTTP {status} {entry.status_text} — {method} {short_url(url)}",
                insight=f"Errore lato client. TTFB: {wait:.0f}ms.",
                solution=solutions_4xx.get(status, "Verificare la correttezza della richiesta."),
            ))

        if wait > LATENCY_THRESHOLD_MS:
            findings.append(Finding(
                severity=Severity.WARNING, category=FindingCategory.PERFORMANCE,
                finding_type="HIGH_LATENCY",
                title="Alta latenza TTFB",
                detail=f"TTFB={wait:.0f}ms (soglia {LATENCY_THRESHOLD_MS}ms) — {method} {short_url(url)}",
                insight="Il server ha impiegato troppo tempo a rispondere.",
                solution=(
                    "1. Profilare l'endpoint lato backend.\n"
                    "2. Verificare connection pool o cold start.\n"
                    "3. Considerare caching server-side.\n"
                    "4. Verificare DNS e TLS handshake."
                ),
            ))
        elif entry.time_total > LATENCY_THRESHOLD_MS and status == 200:
            findings.append(Finding(
                severity=Severity.INFO, category=FindingCategory.PERFORMANCE,
                finding_type="SLOW_DOWNLOAD",
                title="Download lento",
                detail=f"Download: {entry.time_total:.0f}ms (TTFB={wait:.0f}ms) — {method} {short_url(url)}",
                insight="Il server ha risposto rapidamente ma il trasferimento e' lento.",
                solution="1. Abilitare compressione gzip/brotli.\n2. Verificare la dimensione del payload.\n3. Controllare la banda di rete.",
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityScanner:
    """Scansione proattiva di sicurezza su entry HAR."""

    PII_PATTERNS = {
        "email": re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
        "credit_card": re.compile(r'\b(\d[ \-]*?){13,19}\b'),
        "api_key_in_url": re.compile(
            r'(?i)(api_key|apikey|access_token|secret|password|passwd|pwd|auth_token|private_key)=[^&\s]+'
        ),
        "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),
        "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    }

    # Costanti numeriche tecniche note da ignorare nel rilevamento carte di credito
    _KNOWN_NUMERIC_CONSTANTS = frozenset({
        "9007199254740991",   # Number.MAX_SAFE_INTEGER
        "9007199254740992",   # Number.MAX_SAFE_INTEGER + 1
    })

    # Chiavi JSON che indicano contesto tecnico (non PII)
    _TECHNICAL_JSON_KEYS = re.compile(
        r'(?i)(timestamp|time|date|id|transferSize|start|end|version|creation'
        r'|duration|size|offset|index|count|length|height|width|expire|ttl|epoch|modified|created)'
    )

    # Endpoint di configurazione/sessione dove le email sono attese
    _CONFIG_EMAIL_PATHS = re.compile(
        r'(?i)/api/(configuration|config|version|session|me|user/profile|auth/me)'
    )

    REQUIRED_SECURITY_HEADERS = {
        "content-security-policy": "Content-Security-Policy (CSP)",
        "strict-transport-security": "Strict-Transport-Security (HSTS)",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }

    @staticmethod
    def _luhn_check(number_str: str) -> bool:
        """Verifica checksum di Luhn su una stringa di sole cifre."""
        digits = [int(d) for d in number_str]
        # Partendo dalla penultima cifra, raddoppia ogni seconda cifra da destra
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        return sum(digits) % 10 == 0

    @staticmethod
    def _is_unix_timestamp_ms(digits: str) -> bool:
        """Ritorna True se la stringa di cifre sembra un timestamp Unix in millisecondi.
        Range coperto: 2001-09-09 ~ 2033-05-18 (10^12 .. 2*10^12)."""
        if len(digits) == 13 and digits[0] in ('1', '2'):
            try:
                val = int(digits)
                # 1_000_000_000_000 (Sep 2001) .. 2_100_000_000_000 (~2036)
                return 1_000_000_000_000 <= val <= 2_100_000_000_000
            except ValueError:
                return False
        return False

    def _is_technical_json_context(self, text: str, match_start: int) -> bool:
        """Controlla se il match si trova come valore di una chiave JSON tecnica."""
        # Cerca indietro dal match per trovare un pattern  "key" : <valore>
        window_start = max(0, match_start - 80)
        before = text[window_start:match_start]
        # Trova l'ultima chiave JSON-like prima del numero
        key_match = re.search(r'["\'](\w+)["\']\s*:\s*["\']?\s*$', before)
        if key_match and self._TECHNICAL_JSON_KEYS.search(key_match.group(1)):
            return True
        return False

    def _is_false_positive_cc(self, text: str, match: re.Match) -> bool:
        """Restituisce True se il match di carta di credito è un falso positivo."""
        raw = match.group()
        digits = re.sub(r'[\s\-]', '', raw)

        # Ignora costanti tecniche note
        if digits in self._KNOWN_NUMERIC_CONSTANTS:
            return True

        # Ignora timestamp Unix in millisecondi
        if self._is_unix_timestamp_ms(digits):
            return True

        # Controlla contesto JSON (chiave tecnica)
        if self._is_technical_json_context(text, match.start()):
            return True

        # Verifica checksum di Luhn — se fallisce, non è una carta valida
        if not self._luhn_check(digits):
            return True

        return False

    def scan_all(self, entries: list) -> SecurityReport:
        return SecurityReport(
            pii_findings=self.scan_pii(entries),
            header_findings=self.check_security_headers(entries),
            cookie_findings=self.check_cookies(entries),
        )

    def scan_pii(self, entries: list) -> list:
        findings = []
        seen = set()
        for entry in entries:
            # Scan URL query string
            query = urlparse(entry.url).query
            if query:
                self._scan_text(query, "URL query", entry, findings, seen)
            # Scan request body
            if entry.request_body_snippet:
                self._scan_text(entry.request_body_snippet, "Request body", entry, findings, seen)
            # Scan request headers (Authorization etc.)
            for hname, hval in entry.request_headers.items():
                if hname in ("authorization", "cookie", "x-api-key"):
                    # Don't flag standard auth headers as PII — they're expected
                    # But scan for JWT/bearer in unexpected places
                    pass
            # Scan response body snippet
            if entry.response_body_snippet:
                self._scan_text(entry.response_body_snippet, "Response body", entry, findings, seen)
        return findings

    def _scan_text(self, text: str, location: str, entry: HarEntry,
                   findings: list, seen: set) -> None:
        for pii_type, pattern in self.PII_PATTERNS.items():
            for match in pattern.finditer(text):
                # --- Filtro falsi positivi carte di credito ---
                if pii_type == "credit_card" and self._is_false_positive_cc(text, match):
                    continue

                # --- Filtro email in endpoint di configurazione/sessione ---
                if pii_type == "email" and self._CONFIG_EMAIL_PATHS.search(entry.path):
                    continue

                matched_val = match.group()[:30]
                dedup_key = f"{pii_type}:{matched_val}:{entry.path}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(Finding(
                    severity=Severity.CRITICAL if pii_type in ("credit_card", "api_key_in_url") else Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    finding_type=f"PII_{pii_type.upper()}",
                    title=f"PII rilevato: {pii_type}",
                    detail=f"[{location}] {pii_type}: '{matched_val}...' in {short_url(entry.url, 60)}",
                    insight=f"Dato sensibile ({pii_type}) trovato in {location}.",
                    solution="Spostare dati sensibili nel body (POST) o header Authorization. Ruotare le credenziali se esposte.",
                ))

    def check_security_headers(self, entries: list) -> list:
        findings = []
        checked_domains = set()
        for entry in entries:
            if entry.resource_type != ResourceType.DOCUMENT or entry.status != 200:
                continue
            if entry.domain in checked_domains:
                continue
            checked_domains.add(entry.domain)
            for header_key, header_label in self.REQUIRED_SECURITY_HEADERS.items():
                if header_key not in entry.response_headers:
                    findings.append(Finding(
                        severity=Severity.MEDIUM, category=FindingCategory.SECURITY,
                        finding_type=f"MISSING_HEADER_{header_key.upper().replace('-', '_')}",
                        title=f"Header di sicurezza mancante: {header_label}",
                        detail=f"Header '{header_label}' assente su {entry.domain}",
                        insight=f"Il documento HTML non include l'header {header_label}.",
                        solution=f"Aggiungere l'header {header_label} nella configurazione del web server.",
                    ))
        return findings

    def check_cookies(self, entries: list) -> list:
        findings = []
        seen_cookies = set()
        for entry in entries:
            sc = entry.response_headers.get("set-cookie", "")
            if not sc:
                continue
            # Parse cookie name
            cookie_name = sc.split("=")[0].strip() if "=" in sc else "unknown"
            if cookie_name in seen_cookies:
                continue
            seen_cookies.add(cookie_name)
            sc_lower = sc.lower()
            missing_flags = []
            if "secure" not in sc_lower:
                missing_flags.append("Secure")
            if "httponly" not in sc_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in sc_lower:
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append(Finding(
                    severity=Severity.HIGH, category=FindingCategory.SECURITY,
                    finding_type="COOKIE_INSECURE",
                    title=f"Cookie insicuro: {cookie_name}",
                    detail=f"Cookie '{cookie_name}' manca: {', '.join(missing_flags)} (domain: {entry.domain})",
                    insight=f"Cookie senza {', '.join(missing_flags)} e' vulnerabile.",
                    solution=f"Impostare '{'; '.join(missing_flags)}' per il cookie '{cookie_name}'.",
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  PERFORMANCE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class PerformanceAnalyzer:
    """Analisi approfondita delle performance."""

    def analyze(self, entries: list) -> PerformanceStats:
        # TTFB (only non-cached with valid wait)
        ttfb_values = [e.timings.wait for e in entries
                       if not e.is_cached and e.timings.wait > 0]
        # Download time (receive)
        dl_values = [e.timings.receive for e in entries
                     if not e.is_cached and e.timings.receive > 0]
        # Total transfer
        total_bytes = sum(e.transfer_size for e in entries if e.transfer_size > 0)
        # Uncompressed text resources
        uncompressed = []
        uncompressed_bytes = 0
        for e in entries:
            if e.transfer_size <= 1024:
                continue
            mime = e.mime_type.lower()
            is_text = any(t in mime for t in ["text/", "json", "javascript", "xml", "css"])
            if not is_text:
                continue
            if "content-encoding" not in e.response_headers:
                uncompressed.append(e)
                uncompressed_bytes += e.transfer_size
        # Oversized images
        oversized = []
        for e in entries:
            if e.transfer_size <= 512000:
                continue
            mime = e.mime_type.lower()
            if any(t in mime for t in ["image/jpeg", "image/png", "image/gif", "image/bmp"]):
                oversized.append(e)

        return PerformanceStats(
            ttfb_p50=percentile(ttfb_values, 50),
            ttfb_p90=percentile(ttfb_values, 90),
            ttfb_p99=percentile(ttfb_values, 99),
            download_p50=percentile(dl_values, 50),
            download_p90=percentile(dl_values, 90),
            download_p99=percentile(dl_values, 99),
            total_transfer_bytes=total_bytes,
            uncompressed_text_bytes=uncompressed_bytes,
            uncompressed_entries=uncompressed,
            oversized_images=oversized,
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  DIFFERENTIAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _cat_priority(cat: str) -> int:
    order = {"SPA-BUNDLE": 0, "SPA-CHUNK": 1, "SCRIPT": 2, "DOCUMENT": 3,
             "API": 4, "STYLESHEET": 5, "STATIC": 6, "IMAGE": 7,
             "FONT": 8, "EXTERNAL": 9}
    return order.get(cat, 50)

def differential_analysis(har_ok: ParsedHar, har_ko: ParsedHar) -> list:
    """Confronta un HAR sano con uno malato."""
    findings = []
    name_ok = har_ok.file_name
    name_ko = har_ko.file_name

    ok_map = OrderedDict()
    for e in har_ok.entries:
        ok_map.setdefault(e.entry_key, []).append(e)
    ko_map = OrderedDict()
    for e in har_ko.entries:
        ko_map.setdefault(e.entry_key, []).append(e)

    ok_keys = set(ok_map.keys())
    ko_keys = set(ko_map.keys())

    # Missing in KO
    missing_in_ko = ok_keys - ko_keys
    if missing_in_ko:
        by_cat = {}
        for key in sorted(missing_in_ko):
            cat = ok_map[key][0].resource_type.value
            by_cat.setdefault(cat, []).append(key)

        for cat, keys in sorted(by_cat.items(), key=lambda x: _cat_priority(x[0])):
            count = sum(len(ok_map[k]) for k in keys)
            is_critical = cat in ("SPA-BUNDLE", "SPA-CHUNK", "API", "DOCUMENT", "SCRIPT")
            detail_lines = "\n".join(f"  - {k}" for k in keys)

            if cat in ("SPA-BUNDLE", "SPA-CHUNK"):
                solution = (
                    "PUNTO DI ROTTURA PROBABILE:\n"
                    "I bundle JS dell'applicazione SPA non sono stati caricati.\n"
                    "1. Confrontare l'HTML tra OK e KO.\n"
                    "2. Controllare Console per errori JS bloccanti.\n"
                    "3. Verificare Content-Security-Policy.\n"
                    "4. Invalidare la cache del browser.\n"
                    "5. Verificare che i file siano presenti sul server."
                )
            elif cat == "API":
                solution = (
                    f"{count} chiamate API non effettuate nel file KO.\n"
                    "Probabilmente CONSEGUENZA del mancato caricamento dei bundle JS.\n"
                    "1. Risolvere prima il mancato caricamento dei bundle.\n"
                    "2. Verificare errore di autenticazione.\n"
                    "3. Verificare i CORS headers."
                )
            elif cat == "DOCUMENT":
                solution = (
                    "Documento HTML non caricato correttamente.\n"
                    "1. Verificare risposta del server (redirect? auth?).\n"
                    "2. Controllare DNS e raggiungibilita'.\n"
                    "3. Verificare load balancer / reverse proxy."
                )
            elif cat == "EXTERNAL":
                solution = "Risorse di terze parti non caricate. Impatto generalmente basso."
            else:
                solution = "Risorse statiche mancanti. Verificare se caricate on-demand dall'app JS."

            findings.append(Finding(
                severity=Severity.CRITICAL if is_critical else Severity.WARNING,
                category=FindingCategory.AVAILABILITY,
                finding_type="MISSING_IN_KO",
                title=f"Risorse mancanti [{cat}]",
                detail=f"[{cat}] {len(keys)} endpoint ({count} richieste) presenti in {name_ok} ma ASSENTI in {name_ko}:\n{detail_lines}",
                insight=f"Risorse di tipo {cat} non richieste nel file problematico.",
                solution=solution,
            ))

    # Extra in KO
    extra_in_ko = ko_keys - ok_keys
    if extra_in_ko:
        detail_lines = "\n".join(f"  - {k}" for k in sorted(extra_in_ko))
        findings.append(Finding(
            severity=Severity.INFO, category=FindingCategory.AVAILABILITY,
            finding_type="EXTRA_IN_KO",
            title="Richieste extra nel KO",
            detail=f"{len(extra_in_ko)} richieste presenti SOLO in {name_ko}:\n{detail_lines}",
            insight="Richieste aggiuntive nel file problematico (retry? redirect?).",
            solution="Verificare se sono tentativi di retry o redirect anomali.",
        ))

    # Status mismatch
    for key in sorted(ok_keys & ko_keys):
        ok_s = ok_map[key][0].status
        ko_s = ko_map[key][0].status
        if ok_s != ko_s:
            findings.append(Finding(
                severity=Severity.CRITICAL, category=FindingCategory.AVAILABILITY,
                finding_type="STATUS_MISMATCH",
                title="Status mismatch",
                detail=f"{key}: status {name_ok}={ok_s} vs {name_ko}={ko_s}",
                insight="Stessa richiesta, risposta diversa.",
                solution=(
                    f"Endpoint restituisce {ok_s} nel caso sano e {ko_s} nel problematico.\n"
                    "1. Confrontare headers e body tra i due file.\n"
                    "2. Verificare stato del server al momento della cattura KO.\n"
                    "3. Controllare token/sessione."
                ),
            ))

        # Timing degradation
        ok_t = ok_map[key][0].time_total
        ko_t = ko_map[key][0].time_total
        if ok_t > 0 and ko_t > 0:
            ratio = ko_t / ok_t
            if ratio > 3 and ko_t > HIGH_LATENCY_WARN_MS:
                findings.append(Finding(
                    severity=Severity.WARNING, category=FindingCategory.PERFORMANCE,
                    finding_type="TIMING_DEGRADATION",
                    title="Degradazione timing",
                    detail=f"{key}: {name_ok}={ok_t:.0f}ms vs {name_ko}={ko_t:.0f}ms ({ratio:.1f}x)",
                    insight="Degradazione significativa della latenza.",
                    solution="1. Verificare carico del server.\n2. Controllare performance backend.\n3. Verificare rete.",
                ))

    # Delta entries
    ok_count = len(har_ok.entries)
    ko_count = len(har_ko.entries)
    if ko_count < ok_count * 0.5:
        findings.append(Finding(
            severity=Severity.CRITICAL, category=FindingCategory.AVAILABILITY,
            finding_type="INCOMPLETE_LOAD",
            title="Caricamento incompleto",
            detail=f"Entries: {name_ok}={ok_count}, {name_ko}={ko_count} (delta: {ko_count - ok_count:+d})",
            insight=f"Il file KO contiene solo {ko_count}/{ok_count} richieste ({ko_count/max(ok_count,1)*100:.0f}%).",
            solution="Caricamento interrotto. Verificare risorse MISSING_IN_KO di tipo SPA-BUNDLE.",
        ))
    else:
        findings.append(Finding(
            severity=Severity.INFO, category=FindingCategory.AVAILABILITY,
            finding_type="ENTRY_COUNT",
            title="Conteggio entries",
            detail=f"Entries: {name_ok}={ok_count}, {name_ko}={ko_count} (delta: {ko_count - ok_count:+d})",
            insight="Numero di richieste comparabile.",
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  ROOT CAUSE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_problems(har: ParsedHar) -> list:
    """Rileva pattern di problemi comuni."""
    problems = []
    entries = har.entries

    errors_5xx = [e for e in entries if e.status >= 500]
    if errors_5xx:
        urls = ", ".join(short_url(e.url, 50) for e in errors_5xx[:3])
        problems.append({
            "title": f"{len(errors_5xx)} errori server (5xx)",
            "description": f"  URL colpite: {urls}",
            "solution": (
                "1. Controllare i log del server applicativo.\n"
                "2. Verificare stato servizi downstream (DB, cache).\n"
                "3. Controllare risorse del server (CPU, memoria).\n"
                "4. Se 502/504: verificare timeout del reverse proxy."
            ),
        })

    errors_4xx = [e for e in entries if 400 <= e.status < 500 and "favicon" not in e.url.lower()]
    if errors_4xx:
        urls = ", ".join(short_url(e.url, 50) for e in errors_4xx[:3])
        problems.append({
            "title": f"{len(errors_4xx)} errori client (4xx)",
            "description": f"  URL colpite: {urls}",
            "solution": (
                "1. HTTP 401/403: verificare token/sessione.\n"
                "2. HTTP 404: verificare che le risorse esistano.\n"
                "3. Controllare redirect a URL errate."
            ),
        })

    blocked = [e for e in entries if e.status == 0]
    if blocked:
        urls = ", ".join(short_url(e.url, 50) for e in blocked[:3])
        problems.append({
            "title": f"{len(blocked)} richieste bloccate (status 0)",
            "description": f"  URL colpite: {urls}",
            "solution": (
                "1. Verificare CORS headers.\n"
                "2. Controllare Content-Security-Policy.\n"
                "3. Verificare connettivita' di rete.\n"
                "4. Escludere interferenze di estensioni."
            ),
        })

    slow = [e for e in entries if e.timings.wait > LATENCY_THRESHOLD_MS * 2]
    if slow:
        urls = ", ".join(short_url(e.url, 50) for e in slow[:3])
        avg_wait = sum(e.timings.wait for e in slow) / len(slow)
        problems.append({
            "title": f"{len(slow)} richieste con latenza estrema (TTFB medio: {avg_wait:.0f}ms)",
            "description": f"  URL colpite: {urls}",
            "solution": (
                "1. Profilare gli endpoint backend.\n"
                "2. Verificare slow query log.\n"
                "3. Controllare carico del server.\n"
                "4. Valutare caching."
            ),
        })

    for page in har.pages:
        if page.on_load is None:
            problems.append({
                "title": "Pagina non completamente caricata (pageTimings nulli)",
                "description": f"  Page ID: {page.page_id}",
                "solution": (
                    "1. Verificare che tutti gli script critici vengano caricati.\n"
                    "2. Controllare Console per errori JS.\n"
                    "3. Verificare assenza di loop infiniti."
                ),
            })
            break

    return problems


def build_root_cause_standalone(har: ParsedHar) -> str:
    lines = [
        "", BOLD("=" * 80),
        BOLD(f"  ROOT CAUSE ANALYSIS — {har.file_name}"),
        BOLD("=" * 80),
    ]
    problems = _detect_problems(har)
    if not problems:
        lines.append(f"\n  {YELLOW('Nessun pattern di errore chiaro identificato.')}")
        lines.append("  Analizzare manualmente il waterfall e i red flags sopra.\n")
    else:
        lines.append("")
        for i, p in enumerate(problems, 1):
            lines.append(f"  {RED(f'PROBLEMA #{i}')}: {p['title']}")
            lines.append(f"  {p['description']}")
            lines.append(f"\n  {CYAN('SOLUZIONE')}:")
            for sol_line in p["solution"].split("\n"):
                lines.append(f"    {sol_line}")
            lines.append("")
    lines.append(BOLD("=" * 80))
    return "\n".join(lines)


def build_root_cause_diff(har_ok: ParsedHar, har_ko: ParsedHar) -> str:
    lines = [
        "", BOLD("=" * 80),
        BOLD("  ROOT CAUSE ANALYSIS — VERDETTO DIFFERENZIALE"),
        BOLD("=" * 80),
    ]
    name_ok = har_ok.file_name
    name_ko = har_ko.file_name

    ok_keys = {e.entry_key for e in har_ok.entries}
    ko_keys = {e.entry_key for e in har_ko.entries}
    missing = ok_keys - ko_keys

    missing_by_cat = {}
    for key in missing:
        for e in har_ok.entries:
            if e.entry_key == key:
                missing_by_cat.setdefault(e.resource_type.value, []).append(key)
                break

    null_timings = any(p.on_load is None for p in har_ko.pages) if har_ko.pages else False
    ko_errors = [e for e in har_ko.entries if e.status >= 400 or e.status == 0]
    has_missing_bundles = bool(missing_by_cat.get("SPA-BUNDLE") or missing_by_cat.get("SPA-CHUNK"))
    has_missing_api = bool(missing_by_cat.get("API"))
    has_status_mismatch = False
    for key in ok_keys & ko_keys:
        ok_e = next(e for e in har_ok.entries if e.entry_key == key)
        ko_e = next(e for e in har_ko.entries if e.entry_key == key)
        if ok_e.status != ko_e.status:
            has_status_mismatch = True
            break

    diag = RED("DIAGNOSI")

    if has_missing_bundles and null_timings:
        bundle_keys = sorted(missing_by_cat.get("SPA-BUNDLE", []) + missing_by_cat.get("SPA-CHUNK", []))
        entry_point = bundle_keys[0] if bundle_keys else "bundle JS principale"
        num_missing = len(missing)
        ok_count = len(har_ok.entries)
        ko_count = len(har_ko.entries)
        catena = BOLD("Catena causale ricostruita")
        colpevole = BOLD("Richiesta colpevole")
        colp_val = RED(entry_point)
        azioni = BOLD("Azioni correttive (in ordine di priorita')")
        ok_tag = GREEN("OK")
        fail_tag = RED("FAIL")
        a1 = CYAN("Confrontare l'HTML")
        a2 = CYAN("Console del browser")
        a3 = CYAN("Content-Security-Policy")
        a4 = CYAN("Cache / Service Worker")
        a5 = CYAN("Deploy")
        lines.append(f"""
  {diag}: Mancato caricamento del bundle applicativo (SPA entry-point).

  {catena}:
    1. HTML della pagina caricato dal server          -> {ok_tag}
    2. Risorse statiche di base (CSS, JS legacy)      -> {ok_tag} (dalla cache)
    3. {RED('Il browser NON richiede il bundle SPA')}    -> {fail_tag}
    4. L'applicazione SPA non si monta nel DOM        -> nessun rendering
    5. Nessuna chiamata API successiva                -> la pagina resta vuota
    6. Eventi onLoad/DOMContentLoaded non scattano    -> pageTimings = null

  {colpevole}: {colp_val}
    - Caricato normalmente nel file sano ({name_ok})
    - Completamente ASSENTE nel file problematico ({name_ko})
    - {num_missing} risorse totali mancanti ({ko_count}/{ok_count} entries)

  {azioni}:
    1. {a1}: confrontare il body della prima risposta HTML tra i due file.
    2. {a2}: verificare errori JS nei file caricati prima del bundle.
    3. {a3}: verificare se una policy CSP blocca il caricamento.
    4. {a4}: svuotare la cache o disabilitare il Service Worker.
    5. {a5}: verificare che i file del bundle siano presenti sul server.
""")
    elif ko_errors:
        err_details = []
        for e in ko_errors[:5]:
            err_details.append(f"    - HTTP {e.status}: {e.method} {short_url(e.url, 70)}")
        err_list = "\n".join(err_details)
        lines.append(f"""
  {diag}: Errori HTTP nelle richieste del file KO.

  Richieste con errore:
{err_list}

  {BOLD('Azioni correttive')}:
    1. Verificare i log del server per le URL con errore.
    2. Confrontare headers di richiesta tra OK e KO.
    3. Se 5xx: controllare stato del backend.
    4. Se 4xx: verificare sessione/autenticazione.
""")
    elif has_missing_api and not has_missing_bundles:
        lines.append(f"""
  {diag}: Chiamate API non effettuate nel file KO.

  Il bundle JS si carica ma le chiamate API successive non partono.

  {BOLD('Azioni correttive')}:
    1. Verificare errori JS nella Console dopo il caricamento.
    2. Controllare errore di autenticazione (401/403).
    3. Verificare variabili di configurazione (API base URL, token).
    4. Controllare se un redirect impedisce il flusso.
""")
    elif has_status_mismatch:
        lines.append(f"""
  {diag}: Risposte HTTP diverse per le stesse richieste.

  Vedere la sezione STATUS_MISMATCH sopra.

  {BOLD('Azioni correttive')}:
    1. Verificare stato del server al momento della cattura KO.
    2. Confrontare token di autenticazione.
    3. Verificare deploy o modifica di configurazione tra le due catture.
""")
    else:
        problems = _detect_problems(har_ko)
        if problems:
            for p in problems:
                lines.append(f"\n  {diag}: {p['title']}")
                lines.append(f"  {p['description']}")
                lines.append(f"\n  {CYAN('SOLUZIONE')}:")
                for sol_line in p["solution"].split("\n"):
                    lines.append(f"    {sol_line}")
        else:
            lines.append(f"\n  {YELLOW('DIAGNOSI')}: Nessun pattern di errore dominante identificato.")
            lines.append("  Differenze sottili tra i due file. Analisi manuale consigliata.")

    lines.append("")
    lines.append(BOLD("=" * 80))
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

def print_section(title: str, findings: list):
    print()
    print(BOLD("─" * 80))
    print(BOLD(f"  {title}"))
    print(BOLD("─" * 80))
    if not findings:
        print(GREEN("  Nessuna anomalia rilevata."))
        return
    for i, f in enumerate(findings, 1):
        sev = SEVERITY_ICON.get(f.severity.value, f.severity.value)
        print(f"\n  {sev} #{i}: {f.finding_type}")
        for line in f.detail.split("\n"):
            print(f"    {line}")
        if f.insight:
            print(f"\n    {CYAN('Insight')}: {f.insight}")
        if f.solution:
            print(f"    {MAGENTA('Soluzione')}:")
            for line in f.solution.split("\n"):
                print(f"      {line}")


def print_waterfall(har: ParsedHar, label: str):
    entries = har.entries
    if not entries:
        return
    print()
    proto_summary = ", ".join(sorted(p for p in har.protocols if p))
    print(BOLD(f"  Waterfall — {label} ({len(entries)} richieste) [{proto_summary}]"))
    print(f"  {'#':>3}  {'Status':>6}  {'Proto':>6}  {'Time':>9}  {'Size':>9}  {'Cache':>5}  {'Type':>10}  URL")
    print(f"  {'─'*3}  {'─'*6}  {'─'*6}  {'─'*9}  {'─'*9}  {'─'*5}  {'─'*10}  {'─'*40}")

    display_entries = entries[:WATERFALL_MAX_ENTRIES]
    for i, e in enumerate(display_entries, 1):
        proto = e.http_version
        if proto.startswith("http/"):
            proto = proto.replace("http/", "h")
        path = e.path
        if len(path) > 50:
            path = "..." + path[-47:]

        status_str = str(e.status)
        if e.status >= 400 or e.status == 0:
            status_str = RED(status_str)

        cache_str = DIM("cache") if e.is_cached else ""
        t_size = e.transfer_size
        size_str = (f"{t_size:>7}B" if t_size > 0
                    else DIM("     0B") if t_size == 0
                    else DIM("    n/a"))
        time_str = f"{e.time_total:>7.1f}ms"
        if e.time_total > LATENCY_THRESHOLD_MS:
            time_str = RED(time_str)
        elif e.time_total > HIGH_LATENCY_WARN_MS:
            time_str = YELLOW(time_str)

        rtype = e.resource_type.value
        print(f"  {i:>3}  {status_str:>6}  {proto:>6}  {time_str}  {size_str}  {cache_str:>5}  {rtype:>10}  {path}")

    if len(entries) > WATERFALL_MAX_ENTRIES:
        print(DIM(f"  ... (mostrati {WATERFALL_MAX_ENTRIES} di {len(entries)} entries)"))


def print_kb_matches(matches: list):
    if not matches:
        return
    print()
    print(BOLD("─" * 80))
    print(BOLD(f"  {MAGENTA('KNOWLEDGE BASE')} — Pattern noti rilevati ({len(matches)} match)"))
    print(BOLD("─" * 80))

    for i, m in enumerate(matches, 1):
        conf_color = GREEN if m.confidence == "HIGH" else YELLOW if m.confidence == "MEDIUM" else DIM
        conf_str = conf_color(f"[{m.confidence}]")
        print(f"\n  {RED(f'MATCH #{i}')}: {BOLD(m.pattern_name)} {conf_str}")
        print(f"    Pattern ID: {m.pattern_id} | Severity: {m.severity} | Category: {m.category}")
        if m.impact_score:
            print(f"    Impact Score: {m.impact_score}/100")

        if m.evidence:
            print(f"    {DIM('Evidence')}:")
            for k, v in m.evidence.items():
                if isinstance(v, set):
                    v = list(v)
                print(f"      {k}: {v}")

        print(f"\n    {CYAN('Diagnosi KB')}:")
        for line in m.diagnosis.split("\n"):
            print(f"      {line}")

        print(f"\n    {MAGENTA('Soluzioni')}:")
        for sol in m.solutions:
            prio = sol.get("priority", "?")
            complexity = sol.get("complexity", "")
            cmplx_str = f" [{complexity}]" if complexity else ""
            print(f"\n      {BOLD(f'#{prio}')}{cmplx_str}. {CYAN(sol['action'])}")
            for line in sol.get("detail", "").split("\n"):
                print(f"         {line}")

        if m.references:
            print(f"\n    {DIM('Riferimenti')}:")
            for ref in m.references:
                print(f"      - {ref}")


def print_performance(stats: PerformanceStats, label: str):
    print()
    print(BOLD("─" * 80))
    print(BOLD(f"  PERFORMANCE — {label}"))
    print(BOLD("─" * 80))

    print(f"\n  {BOLD('Latenza (TTFB)')}:")
    print(f"    P50: {stats.ttfb_p50:>8.1f}ms")
    print(f"    P90: {stats.ttfb_p90:>8.1f}ms")
    p99_str = f"{stats.ttfb_p99:>8.1f}ms"
    if stats.ttfb_p99 > LATENCY_THRESHOLD_MS:
        p99_str = RED(p99_str)
    print(f"    P99: {p99_str}")

    print(f"\n  {BOLD('Content Download')}:")
    print(f"    P50: {stats.download_p50:>8.1f}ms")
    print(f"    P90: {stats.download_p90:>8.1f}ms")
    print(f"    P99: {stats.download_p99:>8.1f}ms")

    total_kb = stats.total_transfer_bytes / 1024
    print(f"\n  {BOLD('Trasferimento totale')}: {total_kb:,.1f} KB")

    if stats.uncompressed_entries:
        saving_kb = stats.uncompressed_text_bytes * 0.7 / 1024
        print(f"\n  {YELLOW('Compressione mancante')}:")
        print(f"    {len(stats.uncompressed_entries)} risorse testo senza Content-Encoding")
        print(f"    Bytes non compressi: {stats.uncompressed_text_bytes / 1024:,.1f} KB")
        print(f"    Risparmio stimato (~70%): {saving_kb:,.1f} KB")
        for e in stats.uncompressed_entries[:5]:
            print(f"      - {short_url(e.url, 60)} ({e.transfer_size / 1024:.1f} KB)")
        if len(stats.uncompressed_entries) > 5:
            print(DIM(f"      ... e altri {len(stats.uncompressed_entries) - 5}"))

    if stats.oversized_images:
        print(f"\n  {YELLOW('Immagini non ottimizzate')} (> 500 KB):")
        for e in stats.oversized_images:
            print(f"    - {short_url(e.url, 60)} ({e.transfer_size / 1024:.1f} KB, {e.mime_type})")
        print(f"    Suggerimento: convertire in WebP/AVIF per ridurre ~30% delle dimensioni.")


def print_security(report: SecurityReport, label: str):
    all_findings = report.pii_findings + report.header_findings + report.cookie_findings
    if not all_findings:
        return
    print()
    print(BOLD("─" * 80))
    print(BOLD(f"  SECURITY SCAN — {label}"))
    print(BOLD("─" * 80))

    if report.pii_findings:
        print(f"\n  {RED('PII / Dati Sensibili')} ({len(report.pii_findings)} trovati):")
        for f in report.pii_findings:
            sev = SEVERITY_ICON.get(f.severity.value, "")
            print(f"    {sev} {f.detail}")

    if report.header_findings:
        print(f"\n  {YELLOW('Security Headers Mancanti')} ({len(report.header_findings)} trovati):")
        for f in report.header_findings:
            print(f"    - {f.detail}")

    if report.cookie_findings:
        print(f"\n  {YELLOW('Cookie Insicuri')} ({len(report.cookie_findings)} trovati):")
        for f in report.cookie_findings:
            print(f"    - {f.detail}")


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR (Enterprise Edition)
# ═══════════════════════════════════════════════════════════════════════════════

class HtmlReportGenerator:
    """Generates a standalone HTML report with Executive Summary, Score Card,
    and Technical Deep Dive sections. Inline CSS for full portability."""

    SEVERITY_COLORS = {
        "CRITICAL": "#dc3545", "HIGH": "#e85d04", "WARNING": "#ffc107",
        "MEDIUM": "#fd7e14", "INFO": "#6c757d",
    }
    HEALTH_COLORS = {
        "HEALTHY": "#28a745", "DEGRADED": "#ffc107", "BROKEN": "#dc3545",
    }
    TIMING_COLORS = {
        "blocked": "#ccc", "dns": "#4caf50", "connect": "#ff9800",
        "ssl": "#9c27b0", "send": "#2196f3", "wait": "#f44336", "receive": "#00bcd4",
    }

    def generate(self, result: AnalysisResult, output_path: str):
        """Generate and write HTML report."""
        html_content = self._build_html(result)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

    def _esc(self, text: str) -> str:
        return html_module.escape(str(text))

    def _build_html(self, result: AnalysisResult) -> str:
        parts = [
            "<!DOCTYPE html>",
            '<html lang="it">',
            self._render_head(),
            "<body>",
            self._render_header(result),
        ]

        # ── A. EXECUTIVE SUMMARY ──
        parts.append(self._render_executive_summary(result))

        # ── B. SCORE CARDS ──
        parts.append(self._render_score_cards(result))

        # ── C. TECHNICAL DEEP DIVE ──
        parts.append('<div id="technical-deep-dive">')
        parts.append('<h2 class="section-title">Technical Deep Dive</h2>')

        # Waterfalls per HAR
        for har in result.parsed_hars:
            parts.append(self._render_waterfall_svg(har))

        # Findings with evidence
        if result.red_flags:
            parts.append(self._render_findings_deep("Red Flags", result.red_flags))
        if result.differential_findings:
            parts.append(self._render_findings_deep("Analisi Differenziale", result.differential_findings))

        # KB matches
        if result.kb_matches:
            parts.append(self._render_kb_matches(result.kb_matches))

        # Performance
        for fname, stats in result.performance.items():
            parts.append(self._render_performance(stats, fname))

        # Security
        for fname, sec in result.security.items():
            parts.append(self._render_security(sec, fname))

        # Root cause
        if result.root_cause_text:
            parts.append(self._render_root_cause(result.root_cause_text))

        parts.append('</div>')  # close technical-deep-dive

        parts.append(self._render_footer())
        parts.append("</body></html>")
        return "\n".join(parts)

    # ─── HEAD & CSS ───────────────────────────────────────────────────────────

    def _render_head(self) -> str:
        return """<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAR Analyzer Pro — Report</title>
<style>
:root {
  --bg: #f5f7fa; --fg: #1a1a2e; --card-bg: #ffffff; --border: #e2e8f0;
  --accent: #3b82f6; --critical: #dc3545; --warning: #f59e0b;
  --success: #10b981; --info: #6b7280; --high: #e85d04; --medium: #fd7e14;
  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --mono: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  --shadow: 0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg); color: var(--fg); line-height: 1.6; padding: 24px; max-width: 1400px; margin: 0 auto; }
h1 { font-size: 2rem; margin-bottom: 8px; letter-spacing: -0.02em; }
h2 { font-size: 1.4rem; margin: 28px 0 16px; padding-bottom: 8px; }
h3 { font-size: 1.1rem; margin: 16px 0 8px; }
.section-title { border-bottom: 3px solid var(--accent); color: var(--accent); text-transform: uppercase; font-size: 1rem; letter-spacing: 0.05em; }

/* Header */
.header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%); color: white; padding: 32px 40px; border-radius: 16px; margin-bottom: 28px; box-shadow: var(--shadow-lg); }
.header h1 { color: white; font-size: 1.8rem; }
.header .subtitle { color: #94a3b8; font-size: 0.9rem; margin-top: 4px; }

/* Cards */
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: var(--shadow); }

/* Badges */
.badge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; color: white; letter-spacing: 0.03em; }
.badge-critical { background: var(--critical); }
.badge-high { background: var(--high); }
.badge-warning { background: var(--warning); color: #1a1a2e; }
.badge-medium { background: var(--medium); }
.badge-info { background: var(--info); }
.badge-healthy { background: var(--success); }
.badge-degraded { background: var(--warning); color: #1a1a2e; }
.badge-broken { background: var(--critical); }

/* Executive Summary */
.exec-summary { background: linear-gradient(135deg, #eff6ff 0%, #f0fdf4 100%); border: 1px solid #bfdbfe; border-radius: 12px; padding: 28px; margin-bottom: 24px; }
.exec-summary h2 { border: none; color: #1e40af; margin-top: 0; font-size: 1.3rem; }
.exec-summary .summary-text { font-size: 1.05rem; line-height: 1.8; color: #374151; margin: 12px 0; }
.exec-summary .summary-text.all-good { color: #065f46; }
.exec-summary .remediation { margin-top: 16px; }
.exec-summary .remediation h3 { color: #b45309; font-size: 1rem; margin-bottom: 8px; }
.exec-summary .remediation ul { margin-left: 20px; }
.exec-summary .remediation li { margin-bottom: 6px; color: #4b5563; }
.exec-summary .remediation li strong { color: #1e40af; }

/* Score Cards */
.scores-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 28px; }
.score-card { background: var(--card-bg); border-radius: 16px; padding: 24px; text-align: center; box-shadow: var(--shadow); border-top: 4px solid var(--border); position: relative; overflow: hidden; }
.score-card .file-name { font-size: 0.85rem; color: var(--info); margin-bottom: 12px; font-weight: 500; word-break: break-all; }
.score-gauge { position: relative; width: 140px; height: 140px; margin: 0 auto 12px; }
.score-gauge svg { transform: rotate(-90deg); }
.score-gauge .score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; font-weight: 800; }
.score-gauge .score-label { position: absolute; top: 68%; left: 50%; transform: translate(-50%, 0); font-size: 0.7rem; font-weight: 600; letter-spacing: 0.08em; }
.score-reasons { font-size: 0.8rem; color: var(--info); text-align: left; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); }
.score-reasons li { margin-bottom: 4px; }

/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 8px 0; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { background: #f1f5f9; font-weight: 600; position: sticky; top: 0; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--info); }
tr:hover { background: #f8fafc; }
td.mono { font-family: var(--mono); font-size: 0.8rem; }
.url-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Accordions */
details { margin: 10px 0; }
details > summary { cursor: pointer; font-weight: 600; padding: 12px 16px; background: #f1f5f9; border-radius: 8px; border: 1px solid var(--border); list-style: none; display: flex; align-items: center; gap: 8px; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "\\25B6"; font-size: 0.7rem; transition: transform 0.2s; }
details[open] > summary::before { transform: rotate(90deg); }
details > summary:hover { background: #e2e8f0; }
details > .detail-content { padding: 16px; border: 1px solid var(--border); border-top: none; border-radius: 0 0 8px 8px; background: var(--card-bg); }

/* Finding cards */
.finding-card { border: 1px solid var(--border); border-radius: 8px; margin: 10px 0; overflow: hidden; }
.finding-header { padding: 12px 16px; background: #f8fafc; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.finding-body { padding: 14px 16px; }
.finding-body .insight { color: #475569; font-style: italic; margin: 8px 0; }
.finding-body .evidence-table { margin-top: 10px; }
.finding-body .evidence-table th { background: #fef3c7; }

/* Solution & Diagnosis cards */
.solution-card { background: #ecfdf5; border-left: 4px solid var(--success); padding: 14px 16px; margin: 10px 0; border-radius: 0 8px 8px 0; }
.solution-card h4 { margin-bottom: 6px; color: #065f46; }
.solution-card p { color: #374151; font-size: 0.9rem; }
.diagnosis-card { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 14px 16px; margin: 10px 0; border-radius: 0 8px 8px 0; }
.diagnosis-card strong { color: #92400e; }

/* KB match */
.kb-match { border: 2px solid var(--critical); border-radius: 12px; padding: 20px; margin: 16px 0; background: #fef2f2; }
.kb-match h3 { margin-top: 0; }

/* Waterfall */
.waterfall-container { overflow-x: auto; margin: 12px 0; background: white; border-radius: 8px; padding: 8px; border: 1px solid var(--border); }
.legend { display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0; font-size: 0.8rem; }
.legend-item { display: flex; align-items: center; gap: 4px; }
.legend-swatch { width: 16px; height: 10px; border-radius: 2px; }

/* Stats */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 12px 0; }
.stat-card { background: white; border: 1px solid var(--border); border-radius: 10px; padding: 14px; text-align: center; box-shadow: var(--shadow); }
.stat-value { font-size: 1.4rem; font-weight: 700; }
.stat-label { font-size: 0.75rem; color: var(--info); text-transform: uppercase; letter-spacing: 0.04em; }

/* Footer */
.footer { margin-top: 40px; padding: 20px; text-align: center; color: var(--info); font-size: 0.8rem; border-top: 2px solid var(--border); }

/* Misc */
pre { background: #f1f5f9; padding: 14px; border-radius: 8px; overflow-x: auto; font-family: var(--mono); font-size: 0.8rem; white-space: pre-wrap; border: 1px solid var(--border); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
@media print {
  .header { background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { padding: 0; }
  .score-card, .card, .finding-card, .kb-match { break-inside: avoid; }
}
</style>
</head>"""

    # ─── HEADER ───────────────────────────────────────────────────────────────

    def _render_header(self, result: AnalysisResult) -> str:
        mode_str = result.mode.value
        n_files = len(result.parsed_hars)
        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        return f"""<div class="header">
<h1>HAR Analyzer Pro</h1>
<div class="subtitle">Modalita: {self._esc(mode_str)} &middot; {n_files} file analizzati &middot; v{__version__} &middot; {now}</div>
</div>"""

    # ─── A. EXECUTIVE SUMMARY ─────────────────────────────────────────────────

    def _render_executive_summary(self, result: AnalysisResult) -> str:
        parts = ['<div class="exec-summary">', '<h2>Executive Summary</h2>']

        # Determine overall health
        scores = result.health_scores
        broken_files = [n for n, hs in scores.items() if hs.label == HealthLabel.BROKEN]
        degraded_files = [n for n, hs in scores.items() if hs.label == HealthLabel.DEGRADED]
        healthy_files = [n for n, hs in scores.items() if hs.label == HealthLabel.HEALTHY]

        all_findings = result.red_flags + result.differential_findings
        critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)

        # Generate plain-language summary
        if not broken_files and not degraded_files:
            summary = (
                "Tutti i file HAR analizzati risultano in buona salute. "
                "Non sono stati rilevati problemi critici di disponibilita, performance o sicurezza. "
                "Il sito web o l'applicazione funziona correttamente al momento della cattura."
            )
            parts.append(f'<p class="summary-text all-good">{summary}</p>')
        else:
            # Build summary based on findings
            lines = []
            if broken_files:
                file_list = ", ".join(f"<strong>{self._esc(f)}</strong>" for f in broken_files)
                lines.append(
                    f"L'analisi ha rilevato <strong>problemi gravi</strong> nei seguenti file: {file_list}. "
                    "Questi file presentano un caricamento della pagina significativamente compromesso."
                )
            if degraded_files:
                file_list = ", ".join(f"<strong>{self._esc(f)}</strong>" for f in degraded_files)
                lines.append(
                    f"I seguenti file mostrano <strong>prestazioni degradate</strong>: {file_list}."
                )
            if critical_count > 0:
                lines.append(
                    f"Sono state identificate <strong>{critical_count} anomalie critiche</strong> "
                    f"e <strong>{high_count} anomalie ad alta priorita</strong> che richiedono attenzione immediata."
                )

            # Add specific problem descriptions from KB matches
            for m in result.kb_matches:
                if m.severity in ("CRITICAL", "HIGH"):
                    lines.append(f"<strong>{self._esc(m.pattern_name)}</strong>: {self._esc(m.diagnosis[:200])}")

            # Add root cause summary (strip ANSI)
            if result.mode == AnalysisMode.DIFFERENTIAL and broken_files:
                # Try to extract the key diagnosis from differential analysis
                missing_bundles = [f for f in result.differential_findings
                                   if f.finding_type == "MISSING_IN_KO" and "SPA-BUNDLE" in f.title]
                if missing_bundles:
                    lines.append(
                        "Il problema principale sembra essere il <strong>mancato caricamento dei bundle JavaScript</strong> "
                        "dell'applicazione. La pagina non riesce a montare l'interfaccia utente, "
                        "causando una schermata bianca o incompleta."
                    )

            parts.append('<p class="summary-text">' + " ".join(lines) + '</p>')

            # Remediation bullets
            remediation_items = self._collect_remediation(result)
            if remediation_items:
                parts.append('<div class="remediation">')
                parts.append('<h3>Azioni Correttive Suggerite</h3>')
                parts.append('<ul>')
                for item in remediation_items:
                    parts.append(f'<li>{item}</li>')
                parts.append('</ul>')
                parts.append('</div>')

        # Security quick note
        all_sec = []
        for sec in result.security.values():
            all_sec.extend(sec.pii_findings)
            all_sec.extend(sec.cookie_findings)
        if all_sec:
            parts.append(
                f'<p class="summary-text" style="margin-top:12px;color:#92400e;">'
                f'Nota di sicurezza: rilevati <strong>{len(all_sec)} problemi di sicurezza</strong> '
                f'(dati sensibili, cookie insicuri). Vedere la sezione Technical Deep Dive per i dettagli.</p>'
            )

        parts.append('</div>')
        return "\n".join(parts)

    def _collect_remediation(self, result: AnalysisResult) -> list:
        """Collect unique remediation items from KB matches and findings."""
        items = []
        seen = set()

        # Priority 1: KB match solutions
        for m in result.kb_matches:
            for sol in m.solutions:
                key = sol.get("action", "")
                if key and key not in seen:
                    seen.add(key)
                    priority = sol.get("priority", 99)
                    complexity = sol.get("complexity", "")
                    cmplx = f" (complessita: {complexity})" if complexity else ""
                    items.append((priority, f"<strong>{self._esc(key)}</strong>{cmplx} &mdash; {self._esc(sol.get('detail', '')[:150])}"))

        # Priority 2: Critical finding solutions
        for f in result.red_flags + result.differential_findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.solution:
                first_line = f.solution.split("\n")[0].strip()
                if first_line and first_line not in seen:
                    seen.add(first_line)
                    items.append((50, self._esc(first_line)))

        # Sort by priority, take top 8
        items.sort(key=lambda x: x[0])
        return [item[1] for item in items[:8]]

    # ─── B. SCORE CARDS ──────────────────────────────────────────────────────

    def _render_score_cards(self, result: AnalysisResult) -> str:
        parts = ['<div class="scores-container">']
        for har in result.parsed_hars:
            hs = result.health_scores.get(har.file_name)
            if not hs:
                continue
            color = self.HEALTH_COLORS.get(hs.label.value, "#666")
            parts.append(self._render_single_score_card(har.file_name, hs, color))
        parts.append('</div>')
        return "\n".join(parts)

    def _render_single_score_card(self, file_name: str, hs: HealthScore, color: str) -> str:
        score = hs.score
        label = hs.label.value

        # SVG circular gauge
        radius = 54
        circumference = 2 * 3.14159 * radius
        filled = circumference * (score / 100)
        empty = circumference - filled

        # Background track color
        track_color = "#e2e8f0"

        reasons_html = ""
        if hs.reasons:
            items = "".join(f"<li>{self._esc(r)}</li>" for r in hs.reasons)
            reasons_html = f'<ul class="score-reasons">{items}</ul>'

        badge_cls = "badge-broken" if label == "BROKEN" else "badge-degraded" if label == "DEGRADED" else "badge-healthy"

        return f"""<div class="score-card" style="border-top-color:{color}">
<div class="file-name">{self._esc(file_name)}</div>
<div class="score-gauge">
<svg width="140" height="140" viewBox="0 0 140 140">
<circle cx="70" cy="70" r="{radius}" fill="none" stroke="{track_color}" stroke-width="10"/>
<circle cx="70" cy="70" r="{radius}" fill="none" stroke="{color}" stroke-width="10"
  stroke-dasharray="{filled:.1f} {empty:.1f}" stroke-linecap="round"/>
</svg>
<div class="score-text" style="color:{color}">{score}</div>
<div class="score-label"><span class="badge {badge_cls}">{label}</span></div>
</div>
{reasons_html}
</div>"""

    # ─── C. TECHNICAL DEEP DIVE ──────────────────────────────────────────────

    def _render_waterfall_svg(self, har: ParsedHar) -> str:
        entries = har.entries[:WATERFALL_MAX_ENTRIES]
        if not entries:
            return ""
        max_time = max(e.time_total for e in entries) if entries else 1
        if max_time <= 0:
            max_time = 1

        row_h = 18
        label_w = 260
        bar_w = 700
        svg_w = label_w + bar_w + 40
        svg_h = (len(entries) + 2) * row_h + 30

        lines = [
            f'<details open><summary>Waterfall &mdash; {self._esc(har.file_name)} ({len(har.entries)} richieste)</summary>',
            '<div class="detail-content">',
            '<div class="legend">',
        ]
        for name, color in self.TIMING_COLORS.items():
            lines.append(f'<div class="legend-item"><div class="legend-swatch" style="background:{color}"></div>{name}</div>')
        lines.append('</div>')
        lines.append(f'<div class="waterfall-container"><svg width="{svg_w}" height="{svg_h}" xmlns="http://www.w3.org/2000/svg" style="font-family:monospace;font-size:11px;">')
        lines.append(f'<rect width="{svg_w}" height="{svg_h}" fill="white"/>')

        lines.append(f'<text x="4" y="14" font-weight="bold"># St URL</text>')
        lines.append(f'<text x="{label_w}" y="14" font-weight="bold">0ms</text>')
        mid_ms = max_time / 2
        lines.append(f'<text x="{label_w + bar_w // 2}" y="14" text-anchor="middle">{mid_ms:.0f}ms</text>')
        lines.append(f'<text x="{label_w + bar_w}" y="14" text-anchor="end">{max_time:.0f}ms</text>')

        for idx, e in enumerate(entries):
            y = (idx + 1) * row_h + 16
            status_color = "#dc3545" if (e.status >= 400 or e.status == 0) else "#333"
            path_display = e.path
            if len(path_display) > 30:
                path_display = "..." + path_display[-27:]
            label_text = f"{idx+1:>3} {e.status:>3} {path_display}"
            lines.append(f'<text x="4" y="{y}" fill="{status_color}">{self._esc(label_text)}</text>')

            if e.time_total > 0:
                timing_fields = ["blocked", "dns", "connect", "ssl", "send", "wait", "receive"]
                offset = 0.0
                for tf in timing_fields:
                    dur = getattr(e.timings, tf, 0)
                    if dur <= 0:
                        continue
                    x = label_w + (offset / max_time) * bar_w
                    w = max((dur / max_time) * bar_w, 1)
                    color = self.TIMING_COLORS.get(tf, "#999")
                    lines.append(f'<rect x="{x:.1f}" y="{y - 10}" width="{w:.1f}" height="10" fill="{color}" rx="1"><title>{tf}: {dur:.1f}ms</title></rect>')
                    offset += dur

        lines.append('</svg></div>')
        if len(har.entries) > WATERFALL_MAX_ENTRIES:
            lines.append(f'<p style="color:var(--info);font-size:0.8rem;">Mostrati {WATERFALL_MAX_ENTRIES} di {len(har.entries)} entries.</p>')
        lines.append('</div></details>')
        return "\n".join(lines)

    def _render_findings_deep(self, title: str, findings: list) -> str:
        """Render findings with full detail cards and evidence."""
        if not findings:
            return ""
        # Count by severity
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        sev_summary = " &middot; ".join(f'<span class="badge badge-{s.lower()}">{s}: {c}</span>' for s, c in sev_counts.items())

        parts = [
            f'<details open><summary>{self._esc(title)} ({len(findings)}) {sev_summary}</summary>',
            '<div class="detail-content">',
        ]
        for i, f in enumerate(findings, 1):
            sev = f.severity.value
            badge_cls = f"badge-{sev.lower()}"
            sev_color = self.SEVERITY_COLORS.get(sev, "#666")

            parts.append(f'<div class="finding-card" style="border-left: 3px solid {sev_color}">')
            parts.append(f'<div class="finding-header">')
            parts.append(f'<span class="badge {badge_cls}">{sev}</span>')
            parts.append(f'<strong>#{i} {self._esc(f.finding_type)}</strong>')
            if f.category:
                parts.append(f'<span class="badge badge-info">{self._esc(f.category.value)}</span>')
            parts.append('</div>')
            parts.append('<div class="finding-body">')

            # Detail (pre-formatted for multi-line)
            detail_html = self._esc(f.detail).replace("\n", "<br>")
            parts.append(f'<p>{detail_html}</p>')

            # Insight
            if f.insight:
                parts.append(f'<p class="insight">{self._esc(f.insight)}</p>')

            # Solution
            if f.solution:
                sol_html = self._esc(f.solution).replace("\n", "<br>")
                parts.append(f'<div class="solution-card"><h4>Soluzione</h4><p>{sol_html}</p></div>')

            # Evidence (from finding.evidence dict if present)
            if f.evidence:
                parts.append('<details><summary>Evidenza tecnica</summary>')
                parts.append('<div class="detail-content"><table class="evidence-table">')
                parts.append('<thead><tr><th>Chiave</th><th>Valore</th></tr></thead><tbody>')
                for k, v in f.evidence.items():
                    if isinstance(v, (list, set)):
                        v = ", ".join(str(x) for x in v)
                    parts.append(f'<tr><td><strong>{self._esc(str(k))}</strong></td><td class="mono">{self._esc(str(v)[:300])}</td></tr>')
                parts.append('</tbody></table></div></details>')

            parts.append('</div></div>')  # close finding-body, finding-card

        parts.append('</div></details>')
        return "\n".join(parts)

    def _render_kb_matches(self, matches: list) -> str:
        parts = [
            '<details open><summary>Knowledge Base &mdash; Pattern Rilevati (' + str(len(matches)) + ')</summary>',
            '<div class="detail-content">',
        ]
        for m in matches:
            sev_color = self.SEVERITY_COLORS.get(m.severity, "#666")
            parts.append(f'<div class="kb-match" style="border-color:{sev_color}">')
            parts.append(f'<h3>{self._esc(m.pattern_name)} <span class="badge" style="background:{sev_color}">{m.severity}</span> <span class="badge badge-info">{m.confidence}</span></h3>')
            parts.append(f'<p><strong>Pattern ID:</strong> {self._esc(m.pattern_id)} | <strong>Impact:</strong> {m.impact_score}/100 | <strong>Categoria:</strong> {self._esc(m.category)}</p>')
            parts.append(f'<div class="diagnosis-card"><strong>Diagnosi:</strong> {self._esc(m.diagnosis)}</div>')
            for sol in m.solutions:
                cmplx = f" <span class='badge badge-info'>{sol.get('complexity', '')}</span>" if sol.get('complexity') else ""
                detail_html = self._esc(sol.get("detail", "")).replace("\n", "<br>")
                parts.append(f'<div class="solution-card"><h4>#{sol.get("priority", "?")} {self._esc(sol["action"])}{cmplx}</h4><p>{detail_html}</p></div>')
            if m.evidence:
                parts.append('<details><summary>Evidenza tecnica</summary><div class="detail-content"><table>')
                for k, v in m.evidence.items():
                    if isinstance(v, (set, list)):
                        v = ", ".join(str(x) for x in v)
                    parts.append(f'<tr><td><strong>{self._esc(str(k))}</strong></td><td class="mono">{self._esc(str(v)[:300])}</td></tr>')
                parts.append('</table></div></details>')
            if m.references:
                refs = " | ".join(f'<a href="{self._esc(r)}" target="_blank">{self._esc(r)}</a>' for r in m.references)
                parts.append(f'<p style="font-size:0.8rem;margin-top:8px;">Riferimenti: {refs}</p>')
            parts.append('</div>')
        parts.append('</div></details>')
        return "\n".join(parts)

    def _render_performance(self, stats: PerformanceStats, label: str) -> str:
        saving_kb = stats.uncompressed_text_bytes * 0.7 / 1024 if stats.uncompressed_text_bytes else 0
        parts = [f'<details open><summary>Performance &mdash; {self._esc(label)}</summary><div class="detail-content">']
        parts.append('<div class="stats-grid">')
        for name, val in [("TTFB P50", stats.ttfb_p50), ("TTFB P90", stats.ttfb_p90),
                          ("TTFB P99", stats.ttfb_p99), ("Download P50", stats.download_p50),
                          ("Download P90", stats.download_p90), ("Download P99", stats.download_p99)]:
            color = "var(--critical)" if val > LATENCY_THRESHOLD_MS else "var(--fg)"
            parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{color}">{val:.0f}ms</div><div class="stat-label">{name}</div></div>')
        parts.append(f'<div class="stat-card"><div class="stat-value">{stats.total_transfer_bytes/1024:,.0f} KB</div><div class="stat-label">Trasferimento Totale</div></div>')
        if stats.uncompressed_entries:
            parts.append(f'<div class="stat-card"><div class="stat-value" style="color:var(--warning)">{saving_kb:,.0f} KB</div><div class="stat-label">Risparmio Compressione</div></div>')
        parts.append('</div>')
        if stats.uncompressed_entries:
            parts.append(f'<p><strong>{len(stats.uncompressed_entries)}</strong> risorse testo senza compressione ({stats.uncompressed_text_bytes/1024:,.1f} KB).</p>')
            parts.append('<table><thead><tr><th>URL</th><th>Size (KB)</th></tr></thead><tbody>')
            for e in stats.uncompressed_entries[:10]:
                parts.append(f'<tr><td class="url-cell mono">{self._esc(short_url(e.url, 80))}</td><td>{e.transfer_size/1024:.1f}</td></tr>')
            parts.append('</tbody></table>')
            if len(stats.uncompressed_entries) > 10:
                parts.append(f'<p style="color:var(--info);font-size:0.8rem;">...e altri {len(stats.uncompressed_entries) - 10}</p>')
        if stats.oversized_images:
            parts.append(f'<p style="margin-top:12px;"><strong>{len(stats.oversized_images)}</strong> immagini &gt; 500 KB:</p>')
            parts.append('<table><thead><tr><th>URL</th><th>Size (KB)</th><th>Tipo</th></tr></thead><tbody>')
            for e in stats.oversized_images:
                parts.append(f'<tr><td class="url-cell mono">{self._esc(short_url(e.url, 80))}</td><td>{e.transfer_size/1024:.1f}</td><td>{self._esc(e.mime_type)}</td></tr>')
            parts.append('</tbody></table>')
            parts.append('<p style="color:var(--info);font-size:0.85rem;">Suggerimento: convertire in WebP/AVIF per ridurre ~30% delle dimensioni.</p>')
        parts.append('</div></details>')
        return "\n".join(parts)

    def _render_security(self, report: SecurityReport, label: str) -> str:
        all_f = report.pii_findings + report.header_findings + report.cookie_findings
        if not all_f:
            return ""
        parts = [f'<details open><summary>Security &mdash; {self._esc(label)} ({len(all_f)} findings)</summary><div class="detail-content">']
        if report.pii_findings:
            parts.append('<h3 style="color:var(--critical);">PII / Dati Sensibili</h3>')
            for f in report.pii_findings:
                parts.append(f'<div class="finding-card" style="border-left:3px solid var(--critical);"><div class="finding-header"><span class="badge badge-{f.severity.value.lower()}">{f.severity.value}</span> <strong>{self._esc(f.finding_type)}</strong></div><div class="finding-body"><p>{self._esc(f.detail)}</p>')
                if f.solution:
                    parts.append(f'<div class="solution-card"><p>{self._esc(f.solution)}</p></div>')
                parts.append('</div></div>')
        if report.header_findings:
            parts.append('<h3 style="color:var(--warning);">Security Headers Mancanti</h3><ul>')
            for f in report.header_findings:
                parts.append(f'<li>{self._esc(f.detail)}</li>')
            parts.append('</ul>')
        if report.cookie_findings:
            parts.append('<h3 style="color:var(--warning);">Cookie Insicuri</h3>')
            for f in report.cookie_findings:
                parts.append(f'<div class="finding-card" style="border-left:3px solid var(--high);"><div class="finding-header"><span class="badge badge-high">HIGH</span> <strong>{self._esc(f.finding_type)}</strong></div><div class="finding-body"><p>{self._esc(f.detail)}</p>')
                if f.solution:
                    parts.append(f'<div class="solution-card"><p>{self._esc(f.solution)}</p></div>')
                parts.append('</div></div>')
        parts.append('</div></details>')
        return "\n".join(parts)

    def _render_root_cause(self, text: str) -> str:
        ansi_escape = re.compile(r'\033\[[0-9;]*m')
        clean = ansi_escape.sub('', text)
        return f'<details open><summary>Root Cause Analysis</summary><div class="detail-content"><pre>{self._esc(clean)}</pre></div></details>'

    def _render_footer(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f'<div class="footer">Generato da HAR Analyzer Pro v{__version__} &mdash; {now}</div>'


# ═══════════════════════════════════════════════════════════════════════════════
#  PYINSTALLER HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _is_frozen() -> bool:
    """Detect if running as a PyInstaller bundle."""
    return getattr(sys, 'frozen', False)


def _get_base_dir() -> str:
    """Get the base directory for resource loading.
    When frozen (PyInstaller), uses the temp extraction dir for bundled data.
    Otherwise uses the script's directory."""
    if _is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _get_default_output_dir() -> str:
    """Get the default output directory for the HTML report.
    Uses the directory of the first analyzed file, or the current working directory."""
    if _is_frozen():
        return os.path.dirname(sys.executable)
    return os.getcwd()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    had_critical_error = False

    try:
        # ── Smart argv handling for drag & drop ──
        # When files are dragged onto the executable, they appear in sys.argv[1:]
        # We need to distinguish between drag&drop files and CLI flags
        raw_args = sys.argv[1:]
        dragged_files = []
        cli_args = []

        for arg in raw_args:
            # If arg looks like a file path (not a flag), treat as dragged file
            cleaned = arg.strip().strip("'\"").replace("\\ ", " ")
            if cleaned and not cleaned.startswith("-") and (
                cleaned.lower().endswith(".har")
                or os.path.isdir(cleaned)
                or os.path.isfile(cleaned)
                or cleaned.endswith(os.sep)
                or cleaned.endswith("/")
            ):
                dragged_files.append(cleaned)
            else:
                cli_args.append(arg)

        # Parse only CLI flags (not file paths) through argparse
        parser = argparse.ArgumentParser(
            description="HAR Analyzer Pro — Enterprise-grade HAR analysis tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "Esempi:\n"
                "  python3 har_analyzer_pro.py                           # auto-discovery\n"
                "  python3 har_analyzer_pro.py file1.har file2.har       # file specifici\n"
                "  python3 har_analyzer_pro.py HAR/                      # tutti i .har nella cartella\n"
                "  python3 har_analyzer_pro.py --latency 2000 *.har      # soglia custom\n"
                "  python3 har_analyzer_pro.py --no-html                 # solo console\n"
            ),
        )
        parser.add_argument("paths", nargs="*", default=[],
                            help="File .har o directory (default: directory corrente)")
        parser.add_argument("--latency", type=int, default=1000,
                            help="Soglia latenza in ms (default: 1000)")
        parser.add_argument("--html", metavar="OUTPUT", default=None,
                            help="Path specifico per il report HTML (default: auto-generato)")
        parser.add_argument("--no-html", action="store_true",
                            help="Non generare il report HTML")
        parser.add_argument("--no-open", action="store_true",
                            help="Non aprire automaticamente il report nel browser")
        parser.add_argument("--no-security", action="store_true",
                            help="Salta l'analisi di sicurezza")
        parser.add_argument("--no-performance", action="store_true",
                            help="Salta l'analisi delle performance")
        args = parser.parse_args(cli_args)

        # Merge dragged files with parsed paths
        all_paths = dragged_files + args.paths
        if not all_paths:
            # No files specified — auto-discovery in current directory or ask
            base = _get_base_dir()
            cwd = os.getcwd()
            # Try base dir first (where the executable/script lives), then cwd
            candidates = [base]
            if cwd != base:
                candidates.append(cwd)
            # Also try common subdirectories
            for d in candidates:
                har_subdir = os.path.join(d, "HAR")
                if os.path.isdir(har_subdir):
                    candidates.append(har_subdir)

            found_any = False
            for candidate in candidates:
                test_files = discover_har_files([candidate])
                if test_files:
                    all_paths = [candidate]
                    found_any = True
                    break

            if not found_any:
                print(YELLOW("\n  Nessun file .har trovato nella directory corrente."))
                print("  Trascina i file .har sull'eseguibile oppure specifica il percorso.\n")
                user_input = input("  Inserisci il percorso (file o cartella): ").strip().strip("'\"").replace("\\ ", " ")
                if user_input:
                    all_paths = [user_input]
                else:
                    print(RED("  Nessun percorso fornito. Uscita."))
                    return

        all_paths = sanitize_dropped_paths(all_paths)

        global LATENCY_THRESHOLD_MS
        LATENCY_THRESHOLD_MS = args.latency

        # ── Banner ──
        print(BOLD("\n╔══════════════════════════════════════════════════════════════════════════════╗"))
        print(BOLD("║           HAR ANALYZER PRO — Enterprise-Grade Diagnostics v" + __version__ + "          ║"))
        print(BOLD("╚══════════════════════════════════════════════════════════════════════════════╝"))

        # ── Knowledge Base ──
        kb_count, kb_path = load_knowledge_base()
        if kb_count:
            print(f"  Knowledge Base: {GREEN(f'{kb_count} pattern')} caricati da {os.path.basename(kb_path)}")
        else:
            print(f"  Knowledge Base: {DIM('non trovata (har_known_issues.json)')}")

        # ── Discovery ──
        har_files = discover_har_files(all_paths)
        if not har_files:
            print(RED("\n  Nessun file .har trovato nei path specificati."))
            print(f"  Path cercati: {', '.join(all_paths)}")
            had_critical_error = True
            return

        print(f"\n  Trovati {BOLD(str(len(har_files)))} file HAR:")
        for f in har_files:
            print(f"    - {os.path.basename(f)}")

        # ── Parse & Health Score ──
        parsed_hars = []
        health_scores = {}

        print(f"\n  {BOLD('Health Scoring')}:")
        for path in har_files:
            har = parse_har(path)
            if har is None:
                continue
            hs = compute_health_score(har)
            parsed_hars.append(har)
            health_scores[har.file_name] = hs

            label = HEALTH_LABEL_STR.get(hs.label.value, hs.label.value)
            reasons = "; ".join(hs.reasons) if hs.reasons else "nessun problema rilevato"
            print(f"    {label} [{hs.score:>3}/100] {har.file_name}")
            if hs.reasons:
                print(f"             {DIM(reasons)}")

        if not parsed_hars:
            print(RED("\n  Nessun file HAR valido caricato."))
            had_critical_error = True
            return

        # ── Classify ──
        healthy = [h for h in parsed_hars if health_scores[h.file_name].label == HealthLabel.HEALTHY]
        degraded = [h for h in parsed_hars if health_scores[h.file_name].label == HealthLabel.DEGRADED]
        broken = [h for h in parsed_hars if health_scores[h.file_name].label == HealthLabel.BROKEN]
        problematic = degraded + broken

        print(f"\n  {BOLD('Classificazione automatica')}:")
        print(f"    HEALTHY:  {len(healthy)} file")
        print(f"    DEGRADED: {len(degraded)} file")
        print(f"    BROKEN:   {len(broken)} file")

        if healthy and problematic:
            mode = AnalysisMode.DIFFERENTIAL
            print(f"\n  {BOLD('Modalita')}: {GREEN('ANALISI DIFFERENZIALE')}")
        elif problematic:
            mode = AnalysisMode.STANDALONE
            print(f"\n  {BOLD('Modalita')}: {YELLOW('ANALISI STANDALONE')}")
        else:
            mode = AnalysisMode.ALL_HEALTHY
            print(f"\n  {BOLD('Modalita')}: {GREEN('TUTTI SANI')}")

        # ── Initialize engines ──
        engine = RuleEngine(KNOWLEDGE_BASE) if KNOWLEDGE_BASE else None
        scanner = SecurityScanner() if not args.no_security else None
        perf_analyzer = PerformanceAnalyzer() if not args.no_performance else None

        # ── Build result ──
        result = AnalysisResult(
            mode=mode, parsed_hars=parsed_hars, health_scores=health_scores,
        )

        # ── Analyze ──
        if mode == AnalysisMode.ALL_HEALTHY:
            for h in parsed_hars:
                print_waterfall(h, h.file_name)
                rf = analyze_red_flags(h)
                rf_filtered = [f for f in rf if f.severity != Severity.INFO]
                if rf_filtered:
                    print_section(f"RED FLAGS — {h.file_name}", rf_filtered)
                    result.red_flags.extend(rf_filtered)
                else:
                    print(f"\n  {GREEN('Nessuna anomalia')} in {h.file_name}")

                if perf_analyzer:
                    stats = perf_analyzer.analyze(h.entries)
                    result.performance[h.file_name] = stats
                    print_performance(stats, h.file_name)
                if scanner:
                    sec = scanner.scan_all(h.entries)
                    result.security[h.file_name] = sec
                    print_security(sec, h.file_name)

            print(f"\n  {GREEN('Tutti i file HAR risultano sani.')}\n")

        elif mode == AnalysisMode.STANDALONE:
            for h in problematic:
                print_waterfall(h, h.file_name)
                rf = analyze_red_flags(h)
                result.red_flags.extend(rf)
                print_section(f"RED FLAGS — {h.file_name}", rf)
                rc = build_root_cause_standalone(h)
                result.root_cause_text += rc + "\n"
                print(rc)

                if engine:
                    kb_matches = engine.evaluate_all(h)
                    result.kb_matches.extend(kb_matches)
                    print_kb_matches(kb_matches)
                if perf_analyzer:
                    stats = perf_analyzer.analyze(h.entries)
                    result.performance[h.file_name] = stats
                    print_performance(stats, h.file_name)
                if scanner:
                    sec = scanner.scan_all(h.entries)
                    result.security[h.file_name] = sec
                    print_security(sec, h.file_name)

        elif mode == AnalysisMode.DIFFERENTIAL:
            ref = healthy[0]
            for h in problematic:
                print(f"\n{BOLD('━' * 80)}")
                print(BOLD(f"  ANALISI: {h.file_name} (KO) vs {ref.file_name} (OK)"))
                print(BOLD("━" * 80))

                print_waterfall(h, f"{h.file_name} [KO]")
                print_waterfall(ref, f"{ref.file_name} [OK]")

                rf_ko = analyze_red_flags(h)
                result.red_flags.extend(rf_ko)
                print_section(f"RED FLAGS — {h.file_name} [KO]", rf_ko)

                rf_ok = analyze_red_flags(ref)
                rf_ok_problems = [f for f in rf_ok if f.severity != Severity.INFO]
                if rf_ok_problems:
                    print_section(f"RED FLAGS — {ref.file_name} [OK]", rf_ok_problems)

                diff = differential_analysis(ref, h)
                result.differential_findings.extend(diff)
                print_section(f"ANALISI DIFFERENZIALE ({ref.file_name} vs {h.file_name})", diff)

                rc = build_root_cause_diff(ref, h)
                result.root_cause_text += rc + "\n"
                print(rc)

                if engine:
                    kb_matches = engine.evaluate_all(h, ref_har=ref)
                    result.kb_matches.extend(kb_matches)
                    print_kb_matches(kb_matches)
                if perf_analyzer:
                    stats = perf_analyzer.analyze(h.entries)
                    result.performance[h.file_name] = stats
                    print_performance(stats, h.file_name)
                if scanner:
                    sec = scanner.scan_all(h.entries)
                    result.security[h.file_name] = sec
                    print_security(sec, h.file_name)

        # ── HTML Report (always generated unless --no-html) ──
        if not args.no_html:
            if args.html:
                html_path = args.html
            else:
                # Auto-generate output path next to the first HAR file
                first_har_dir = os.path.dirname(har_files[0]) if har_files else _get_default_output_dir()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                html_path = os.path.join(first_har_dir, f"har_report_{timestamp}.html")

            html_gen = HtmlReportGenerator()
            html_gen.generate(result, html_path)
            html_abs = os.path.abspath(html_path)
            print(f"\n  {GREEN('Report HTML generato')}: {html_abs}")

            # Auto-open in default browser
            if not args.no_open:
                try:
                    webbrowser.open(f"file://{html_abs}")
                    print(f"  {GREEN('Report aperto nel browser.')}")
                except Exception:
                    print(f"  {YELLOW('Impossibile aprire il browser. Apri manualmente:')} {html_abs}")

        print(BOLD("\n>>> Analisi completata.\n"))

    except KeyboardInterrupt:
        print(YELLOW("\n\n  Analisi interrotta dall'utente.\n"))
        had_critical_error = True
    except Exception as exc:
        print(RED(f"\n  ERRORE CRITICO: {exc}\n"))
        import traceback
        traceback.print_exc()
        had_critical_error = True
    finally:
        # Console persistence: keep window open if running as frozen executable
        # so the user can read the output before the terminal window closes
        if _is_frozen():
            try:
                input("\nPremi Invio per uscire...")
            except EOFError:
                pass


if __name__ == "__main__":
    main()
