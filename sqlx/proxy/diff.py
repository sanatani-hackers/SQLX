"""
sqlx/proxy/diff.py
~~~~~~~~~~~~~~~~~~
Diff utilities for comparing HTTP requests and responses.
Used by the compare_requests tool and /compare dashboard command.
"""
from __future__ import annotations
import difflib
from typing import Dict

from sqlx.proxy.request import HttpRequest
from sqlx.proxy.response import HttpResponse


def diff_responses(r1: HttpResponse, r2: HttpResponse,
                   context_lines: int = 3) -> str:
    """Unified diff of two response bodies."""
    lines1 = r1.body.splitlines()
    lines2 = r2.body.splitlines()
    diff = list(difflib.unified_diff(
        lines1, lines2,
        fromfile=f"HTTP {r1.status} ({r1.body_length} bytes)",
        tofile=f"HTTP {r2.status} ({r2.body_length} bytes)",
        n=context_lines, lineterm="",
    ))
    return "\n".join(diff) if diff else "Responses are identical"


def diff_requests(r1: HttpRequest, r2: HttpRequest) -> str:
    """Human-readable diff of method, URL, headers, and body."""
    lines = []
    if r1.method != r2.method:
        lines.append(f"Method: {r1.method} → {r2.method}")
    if r1.url != r2.url:
        lines.append(f"URL:\n  - {r1.url}\n  + {r2.url}")
    for h in sorted(set(r1.headers) | set(r2.headers)):
        v1 = r1.headers.get(h, "(absent)")
        v2 = r2.headers.get(h, "(absent)")
        if v1 != v2:
            lines.append(f"Header {h}: {v1!r} → {v2!r}")
    if r1.body != r2.body:
        body_diff = list(difflib.unified_diff(
            r1.body.splitlines(), r2.body.splitlines(),
            fromfile="Request 1 body", tofile="Request 2 body", lineterm="",
        ))
        lines.append("Body diff:")
        lines.extend(body_diff[:30])
    return "\n".join(lines) if lines else "Requests are identical"


def status_changed(r1: HttpResponse, r2: HttpResponse) -> bool:
    return r1.status != r2.status


def length_changed_significantly(r1: HttpResponse, r2: HttpResponse,
                                  threshold_pct: float = 0.10) -> bool:
    """True if body length differs by more than threshold_pct (default 10%)."""
    if r1.body_length == 0:
        return r2.body_length > 0
    return abs(r1.body_length - r2.body_length) / r1.body_length > threshold_pct


def injection_signal_detected(baseline: HttpResponse,
                               test: HttpResponse) -> Dict:
    """Quick heuristic: did this response pair show an injection signal?"""
    signals = []
    if status_changed(baseline, test):
        signals.append(f"Status changed: {baseline.status} → {test.status}")
    if length_changed_significantly(baseline, test):
        delta = test.body_length - baseline.body_length
        signals.append(f"Body length changed by {delta:+d} bytes")
    return {
        "signals":     signals,
        "has_signal":  bool(signals),
        "confidence":  min(1.0, len(signals) * 0.4),
    }
