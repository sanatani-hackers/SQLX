"""
sqlx/proxy/transformer.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Request transformer chain — applies ordered transform functions to
HTTP requests in transit through the proxy.
Useful for injecting test payloads, replacing params, or adding headers.
"""
from __future__ import annotations
import logging
from typing import Callable, List, Tuple

from sqlx.proxy.request import HttpRequest

logger = logging.getLogger(__name__)
TransformFn = Callable[[HttpRequest], HttpRequest]


class RequestTransformer:
    """Applies an ordered chain of transform functions to HTTP requests."""

    def __init__(self):
        self._transforms: List[Tuple[str, TransformFn]] = []

    def add(self, name: str, fn: TransformFn) -> "RequestTransformer":
        self._transforms.append((name, fn))
        return self

    def remove(self, name: str) -> None:
        self._transforms = [(n, f) for n, f in self._transforms if n != name]

    def clear(self) -> None:
        self._transforms.clear()

    def list_transforms(self) -> List[str]:
        return [name for name, _ in self._transforms]

    def apply(self, request: HttpRequest) -> HttpRequest:
        """Apply all transforms in order. Errors in a single transform are logged and skipped."""
        for name, fn in self._transforms:
            try:
                request = fn(request)
            except Exception as exc:
                logger.warning("Transform %r failed: %s", name, exc)
        return request

    # ── built-in transform factories ──────────────────────────────────────

    @staticmethod
    def replace_param(param: str, value: str) -> TransformFn:
        """Replace a query / body parameter value."""
        def _fn(req: HttpRequest) -> HttpRequest:
            return req.with_param(param, value)
        return _fn

    @staticmethod
    def add_header(name: str, value: str) -> TransformFn:
        """Add or override a request header."""
        def _fn(req: HttpRequest) -> HttpRequest:
            headers = dict(req.headers)
            headers[name] = value
            return HttpRequest(req.method, req.url, headers, req.body)
        return _fn

    @staticmethod
    def remove_header(name: str) -> TransformFn:
        """Remove a header by name (case-insensitive)."""
        def _fn(req: HttpRequest) -> HttpRequest:
            headers = {k: v for k, v in req.headers.items()
                       if k.lower() != name.lower()}
            return HttpRequest(req.method, req.url, headers, req.body)
        return _fn

    @staticmethod
    def append_to_param(param: str, suffix: str) -> TransformFn:
        """Append a string to an existing parameter value."""
        def _fn(req: HttpRequest) -> HttpRequest:
            params = req.query_params
            if param in params:
                existing = params[param][0] if isinstance(params[param], list) else params[param]
                return req.with_param(param, existing + suffix)
            return req
        return _fn
