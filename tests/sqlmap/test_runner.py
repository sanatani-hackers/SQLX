import pytest
from sqlx.sqlmap.adapter import SQLMapConfig
from sqlx.sqlmap.options import validate_args, ensure_safe_defaults

def test_sqlmap_config_builder():
    cfg = SQLMapConfig("http://test.com")
    cfg.level(3).risk(2).tamper("space2comment").dbs()
    args = cfg.build()
    
    assert "-u" in args
    assert "http://test.com" in args
    assert "--batch" in args
    assert "--level" in args
    assert "3" in args
    assert "--tamper" in args
    assert "space2comment" in args
    assert "--dbs" in args

def test_validate_args():
    # Safe args
    res = validate_args(["-u", "http://test.com", "--batch", "--dbs"])
    assert res["valid"] is True
    assert res["is_safe"] is True
    
    # Destructive args
    res = validate_args(["-u", "http://test.com", "--dump-all"])
    assert res["is_safe"] is False
    assert "--dump-all" in res["destructive"]
    
    # Interactive args
    res = validate_args(["-u", "http://test.com", "--wizard"])
    assert res["valid"] is False
    assert "--wizard" in res["interactive"]

def test_ensure_safe_defaults():
    args = ["-u", "http://test.com", "--wizard"]
    safe = ensure_safe_defaults(args)
    assert "--wizard" not in safe
    assert "--batch" in safe
