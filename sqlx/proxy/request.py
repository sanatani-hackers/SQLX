"""
sqlx/proxy/request.py
~~~~~~~~~~~~~~~~~~~~~
Typed HTTP request dataclass used throughout the proxy and analysis layers.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import (
    parse_qs, urlencode, urlparse, urlunparse,
)


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "HttpRequest":
        return cls(
            method=d.get("method", "GET").upper(),
            url=d.get("url", ""),
            headers=d.get("headers", {}),
            body=d.get("body", "") or "",
        )

    def to_dict(self) -> dict:
        return {
            "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body,
        }

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        return urlparse(self.url).path

    @property
    def query_params(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.url).query)

    @property
    def body_params(self) -> dict:
        ct = self.headers.get("Content-Type", "").lower()
        if "application/x-www-form-urlencoded" in ct:
            return parse_qs(self.body)
        if "application/json" in ct:
            try:
                return json.loads(self.body)
            except Exception:
                return {}
        return {}

    def with_param(self, key: str, value: str) -> "HttpRequest":
        """Return a copy with a query or body parameter replaced."""
        if self.method.upper() == "GET":
            parsed = urlparse(self.url)
            params = {k: v[0] if isinstance(v, list) else v
                      for k, v in self.query_params.items()}
            params[key] = value
            new_url = urlunparse(parsed._replace(query=urlencode(params)))
            return HttpRequest(self.method, new_url, dict(self.headers), self.body)
        else:
            params = {k: v[0] if isinstance(v, list) else v
                      for k, v in parse_qs(self.body).items()}
            params[key] = value
            return HttpRequest(self.method, self.url,
                               dict(self.headers), urlencode(params))

    def injectable_params(self) -> List[str]:
        """Return parameter names that are potential injection points."""
        params = list(self.query_params.keys())
        if self.method.upper() in ("POST", "PUT", "PATCH"):
            bp = self.body_params
            if isinstance(bp, dict):
                params.extend(bp.keys())
        return params

    def __repr__(self) -> str:
        return f"HttpRequest({self.method} {self.url[:60]})"
