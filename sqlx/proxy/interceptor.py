"""
sqlx/proxy/interceptor.py
─────────────────────────
Pipeline-style HTTP request interceptor built around composable transform
functions.

A *transform function* has the signature::

    def transform(req_data: dict) -> dict: ...

It receives the current request dict and must return an (optionally modified)
request dict.  Transforms are applied sequentially in the order they were
registered, giving a clear, predictable pipeline.

Built-in factory functions
--------------------------
:func:`add_header_transform`
    Returns a transform that injects (or overwrites) a single HTTP header.

:func:`replace_body_transform`
    Returns a transform that performs a string replacement in the request body.

Example usage::

    interceptor = RequestInterceptor()

    # Inject an auth token into every request
    interceptor.add_transform(add_header_transform("X-Auth-Token", "abc123"))

    # Swap a placeholder in the body for a live value
    interceptor.add_transform(replace_body_transform("{{TARGET}}", "admin"))

    modified_req = interceptor.apply(original_req)
"""

from __future__ import annotations

from typing import Callable, List


# Type alias for clarity
TransformFn = Callable[[dict], dict]


# ────────────────────────────────────────────────────────────────────────── #
#  Built-in transform factories                                              #
# ────────────────────────────────────────────────────────────────────────── #


def add_header_transform(key: str, value: str) -> TransformFn:
    """Return a transform that injects (or replaces) a request header.

    Parameters
    ----------
    key:
        Header name (case-sensitive as stored in the dict).
    value:
        Header value to set.

    Returns
    -------
    TransformFn
        A transform function that adds/overwrites *key* → *value* in the
        ``headers`` sub-dict of the request dict.

    Example
    -------
    >>> transform = add_header_transform("X-Custom", "hello")
    >>> req = {"method": "GET", "url": "http://example.com", "headers": {}}
    >>> transform(req)["headers"]["X-Custom"]
    'hello'
    """
    def _transform(req_data: dict) -> dict:
        req_data = dict(req_data)  # shallow copy to avoid mutating the original
        headers = dict(req_data.get("headers", {}))
        headers[key] = value
        req_data["headers"] = headers
        return req_data

    _transform.__name__ = f"add_header({key!r})"
    _transform.__qualname__ = f"add_header_transform.<locals>._transform[{key!r}]"
    return _transform


def replace_body_transform(old: str, new: str) -> TransformFn:
    """Return a transform that replaces occurrences of *old* with *new* in the body.

    The body is treated as a UTF-8 string for the replacement.  If the body
    is stored as bytes it is decoded before replacement and re-encoded
    afterwards (errors replaced).  If the body is absent or empty the
    request dict is returned unchanged.

    Parameters
    ----------
    old:
        Substring to search for in the body.
    new:
        Replacement string.

    Returns
    -------
    TransformFn
        A transform function that performs the string substitution on the
        ``body`` field of the request dict.

    Example
    -------
    >>> transform = replace_body_transform("{{PAYLOAD}}", "' OR '1'='1")
    >>> req = {"method": "POST", "url": "http://x.com", "headers": {},
    ...        "body": "username={{PAYLOAD}}&pass=x"}
    >>> transform(req)["body"]
    "username=' OR '1'='1&pass=x"
    """
    def _transform(req_data: dict) -> dict:
        req_data = dict(req_data)  # shallow copy
        body = req_data.get("body", "")

        # Normalise to str for replacement
        if isinstance(body, (bytes, bytearray)):
            body_str = body.decode("utf-8", errors="replace")
            was_bytes = True
        else:
            body_str = str(body) if body is not None else ""
            was_bytes = False

        if old in body_str:
            body_str = body_str.replace(old, new)
            req_data["body"] = (
                body_str.encode("utf-8") if was_bytes else body_str
            )
        return req_data

    _transform.__name__ = f"replace_body({old!r}→{new!r})"
    _transform.__qualname__ = (
        f"replace_body_transform.<locals>._transform[{old!r}→{new!r}]"
    )
    return _transform


# ────────────────────────────────────────────────────────────────────────── #
#  RequestInterceptor                                                        #
# ────────────────────────────────────────────────────────────────────────── #


class RequestInterceptor:
    """Sequential pipeline of request transform functions.

    Transforms are applied in registration order.  Each transform receives
    the output of the previous one, allowing transforms to compose cleanly.

    Parameters
    ----------
    transforms:
        Optional initial list of :data:`TransformFn` callables to seed the
        pipeline with.  Additional transforms can be appended later via
        :meth:`add_transform`.
    """

    def __init__(self, transforms: List[TransformFn] | None = None) -> None:
        self._transforms: List[TransformFn] = list(transforms or [])

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def add_transform(self, fn: TransformFn) -> "RequestInterceptor":
        """Append a transform function to the end of the pipeline.

        Parameters
        ----------
        fn:
            A callable with signature ``(req_data: dict) -> dict``.

        Returns
        -------
        RequestInterceptor
            *self*, to allow fluent chaining::

                interceptor.add_transform(t1).add_transform(t2)

        Raises
        ------
        TypeError
            If *fn* is not callable.
        """
        if not callable(fn):
            raise TypeError(
                f"transform must be callable, got {type(fn).__name__!r}"
            )
        self._transforms.append(fn)
        return self

    def apply(self, req_data: dict) -> dict:
        """Run all registered transforms against *req_data* in order.

        Parameters
        ----------
        req_data:
            The request dict to transform.  The original dict is never
            mutated; each transform is responsible for copying if it
            modifies fields.

        Returns
        -------
        dict
            The final request dict after all transforms have been applied.
            If no transforms are registered, a shallow copy of *req_data* is
            returned.

        Raises
        ------
        TypeError
            If any transform returns a non-dict value.
        """
        result: dict = dict(req_data)  # start with a copy
        for fn in self._transforms:
            result = fn(result)
            if not isinstance(result, dict):
                raise TypeError(
                    f"Transform {fn!r} returned {type(result).__name__!r}; "
                    "expected dict"
                )
        return result

    # ------------------------------------------------------------------ #
    #  Dunder helpers                                                      #
    # ------------------------------------------------------------------ #

    def __len__(self) -> int:
        """Return the number of registered transforms."""
        return len(self._transforms)

    def __repr__(self) -> str:  # pragma: no cover
        names = [getattr(fn, "__name__", repr(fn)) for fn in self._transforms]
        return f"<RequestInterceptor transforms={names}>"
