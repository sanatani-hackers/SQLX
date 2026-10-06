"""
sqlx/proxy/response.py
~~~~~~~~~~~~~~~~~~~~~~
Typed HTTP response dataclass used throughout the proxy and analysis layers.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    latency_ms: float = 0.0

    @classmethod
    def from_dict(cls, d: dict) -> "HttpResponse":
        return cls(
            status=int(d.get("status", 0)),
            headers=d.get("headers", {}),
            body=d.get("body", "") or d.get("body_text", "") or "",
            latency_ms=float(d.get("latency_ms", 0)),
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status, "headers": self.headers,
            "body": self.body, "latency_ms": self.latency_ms,
        }

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def body_length(self) -> int:
        return len(self.body)

    @property
    def content_type(self) -> str:
        return self.header("content-type") or ""

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        return next(
            (v for k, v in self.headers.items() if k.lower() == name.lower()),
            None,
        )

    def __repr__(self) -> str:
        return f"HttpResponse(HTTP {self.status}, {self.body_length} bytes)"
