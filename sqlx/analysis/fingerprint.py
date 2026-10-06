"""
sqlx/analysis/fingerprint.py
─────────────────────────────
HTTP response fingerprinting utilities.

Classes
-------
WAFFingerprinter
    Analyses an HTTP response dict and detects known WAF signatures.
TechFingerprinter
    Detects server-side technologies from response headers.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Internal WAF rule definitions
# ---------------------------------------------------------------------------

_WAF_RULES: list[dict[str, Any]] = [
    {
        "name": "Cloudflare",
        "checks": [
            # cf-ray header is the definitive indicator
            lambda s, h, b: "cf-ray" in h,
            # Server: cloudflare
            lambda s, h, b: "cloudflare" in h.get("server", "").lower(),
            # __cfduid / __cf_bm cookies
            lambda s, h, b: "cloudflare" in h.get("set-cookie", "").lower(),
        ],
        "weight": 1.0,
    },
    {
        "name": "Akamai",
        "checks": [
            lambda s, h, b: "akamai" in h.get("server", "").lower(),
            lambda s, h, b: any(
                k.lower().startswith("x-akamai") for k in h
            ),
            lambda s, h, b: "akamaighost" in h.get("server", "").lower(),
            lambda s, h, b: "x-check-cacheable" in h,
        ],
        "weight": 1.0,
    },
    {
        "name": "Imperva / Incapsula",
        "checks": [
            lambda s, h, b: "incap_ses" in h.get("set-cookie", "").lower(),
            lambda s, h, b: "visid_incap" in h.get("set-cookie", "").lower(),
            lambda s, h, b: "incapsula" in h.get("x-iinfo", "").lower(),
            lambda s, h, b: "imperva" in h.get("server", "").lower(),
        ],
        "weight": 1.0,
    },
    {
        "name": "AWS WAF",
        "checks": [
            lambda s, h, b: "x-amzn-requestid" in h,
            lambda s, h, b: "x-amzn-trace-id" in h,
            lambda s, h, b: "awselb" in h.get("server", "").lower(),
            lambda s, h, b: "aws" in h.get("x-powered-by", "").lower(),
        ],
        "weight": 1.0,
    },
    {
        "name": "ModSecurity",
        "checks": [
            lambda s, h, b: "mod_security" in b.lower(),
            lambda s, h, b: "modsecurity" in b.lower(),
            lambda s, h, b: "mod_security" in h.get("server", "").lower(),
            lambda s, h, b: "not acceptable" in b.lower() and s == 406,
        ],
        "weight": 0.9,
    },
    {
        "name": "Generic WAF",
        "checks": [
            lambda s, h, b: s in (403, 406)
            and bool(
                re.search(
                    r"\b(blocked|forbidden|access denied|request denied"
                    r"|security policy|automated|bot detected)\b",
                    b,
                    re.IGNORECASE,
                )
            ),
        ],
        "weight": 0.5,  # lower confidence — generic pattern
    },
]

# Normalise header names to lowercase for all lookups
_BODY_BLOCK_RE = re.compile(
    r"\b(blocked|forbidden|access.?denied|request.?denied"
    r"|security.?policy|automated|bot.?detected)\b",
    re.IGNORECASE,
)


class WAFFingerprinter:
    """Detect WAF presence from a parsed HTTP response.

    Parameters
    ----------
    None — instantiate once and call :meth:`analyse` repeatedly.
    """

    def analyse(
        self,
        response: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a fingerprint result for *response*.

        Parameters
        ----------
        response:
            Dict with keys:
              - ``status``      (int)  HTTP status code
              - ``headers``     (dict) Header name → value (any case)
              - ``body_text``   (str)  Response body as plain text

        Returns
        -------
        dict
            ``{detected, waf_name, confidence, indicators}``
        """
        status: int = int(response.get("status", 200))
        raw_headers: dict = response.get("headers", {}) or {}
        body: str = response.get("body_text", "") or ""

        # Normalise header keys to lowercase
        headers: dict[str, str] = {
            k.lower(): str(v) for k, v in raw_headers.items()
        }

        best_name: str | None = None
        best_confidence: float = 0.0
        indicators: list[str] = []

        for rule in _WAF_RULES:
            hits = [
                check(status, headers, body)
                for check in rule["checks"]
            ]
            hit_count = sum(hits)
            if hit_count == 0:
                continue

            # Confidence: fraction of passing checks × rule weight
            confidence = (hit_count / len(rule["checks"])) * rule["weight"]

            # Collect human-readable indicator strings
            for idx, (passed, check) in enumerate(
                zip(hits, rule["checks"])
            ):
                if passed:
                    indicator = f"{rule['name']} check #{idx + 1}"
                    indicators.append(indicator)

            if confidence > best_confidence:
                best_confidence = confidence
                best_name = rule["name"]

        detected = best_confidence > 0.0
        return {
            "detected": detected,
            "waf_name": best_name if detected else None,
            "confidence": round(best_confidence, 3),
            "indicators": indicators,
        }


# ---------------------------------------------------------------------------
# Technology fingerprinting
# ---------------------------------------------------------------------------

_TECH_PATTERNS: list[tuple[str, list[tuple[str, str | None]]]] = [
    # (technology_name, [(header, pattern_or_None_to_match_any_value)])
    ("Apache", [("server", r"apache")]),
    ("nginx", [("server", r"nginx")]),
    ("IIS", [("server", r"iis|microsoft-iis")]),
    ("PHP", [
        ("x-powered-by", r"php"),
        ("set-cookie", r"phpsessid"),
    ]),
    ("ASP.NET", [
        ("x-powered-by", r"asp\.net"),
        ("x-aspnet-version", None),
        ("x-aspnetmvc-version", None),
    ]),
    ("LiteSpeed", [("server", r"litespeed")]),
    ("Caddy", [("server", r"caddy")]),
    ("Gunicorn", [("server", r"gunicorn")]),
    ("Uvicorn", [("server", r"uvicorn")]),
    ("Tomcat", [("server", r"tomcat|apache-coyote")]),
    ("Jetty", [("server", r"jetty")]),
    ("Node.js", [("x-powered-by", r"express|node")]),
    ("Ruby on Rails", [("x-powered-by", r"phusion|passenger")]),
]


class TechFingerprinter:
    """Detect server-side technologies from HTTP response headers.

    Parameters
    ----------
    None — instantiate once and call :meth:`analyse` repeatedly.
    """

    def analyse(
        self,
        response: dict[str, Any],
    ) -> dict[str, list[str]]:
        """Return detected technologies.

        Parameters
        ----------
        response:
            Dict with at least a ``headers`` key (dict of header name → value).

        Returns
        -------
        dict
            ``{technologies: list[str]}``
        """
        raw_headers: dict = response.get("headers", {}) or {}
        headers: dict[str, str] = {
            k.lower(): str(v).lower() for k, v in raw_headers.items()
        }

        found: list[str] = []
        for tech, checks in _TECH_PATTERNS:
            for header, pattern in checks:
                value = headers.get(header, "")
                if value and (
                    pattern is None
                    or re.search(pattern, value, re.IGNORECASE)
                ):
                    if tech not in found:
                        found.append(tech)
                    break  # matched this tech — move to next

        return {"technologies": found}
