import pytest
from sqlx.proxy.request import HttpRequest
from sqlx.proxy.response import HttpResponse
from sqlx.proxy.diff import diff_requests, status_changed
from sqlx.proxy.transformer import RequestTransformer

def test_http_request_parsing():
    req = HttpRequest("GET", "http://example.com/api?id=1&sort=desc", {"User-Agent": "test"})
    assert req.host == "example.com"
    assert req.path == "/api"
    assert "id" in req.query_params
    assert req.query_params["id"] == ["1"]

def test_http_request_with_param():
    req = HttpRequest("GET", "http://example.com/api?id=1")
    new_req = req.with_param("id", "2")
    assert new_req.url == "http://example.com/api?id=2"

def test_transformer():
    transformer = RequestTransformer()
    transformer.add("replace_id", RequestTransformer.replace_param("id", "999"))
    
    req = HttpRequest("GET", "http://example.com/api?id=1")
    req2 = transformer.apply(req)
    assert req2.query_params["id"] == ["999"]

def test_diff_responses():
    r1 = HttpResponse(200, {}, "hello world")
    r2 = HttpResponse(500, {}, "hello error")
    assert status_changed(r1, r2) is True
