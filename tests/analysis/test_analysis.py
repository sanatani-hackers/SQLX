import pytest
from sqlx.analysis.response import ResponseAnalyser
from sqlx.analysis.timing import TimingAnalyser

def test_response_analyser_sql_error():
    body = "<html>Warning: mysql_fetch_array() expects parameter 1</html>"
    ra = ResponseAnalyser(status=200, headers={}, body=body)
    assert ra.has_sql_error() is True
    assert ra.has_waf_block() is False
    
def test_response_analyser_waf():
    body = "<html>Your request has been blocked by Cloudflare</html>"
    ra = ResponseAnalyser(status=403, headers={}, body=body)
    assert ra.has_waf_block() is True
    assert ra.is_suspicious() is True

def test_response_analyser_dbms_hints():
    body = "ORA-00933: SQL command not properly ended"
    ra = ResponseAnalyser(status=500, headers={}, body=body)
    assert ra.has_sql_error() is True
    assert "Oracle" in ra.extract_dbms_hints()

def test_timing_analyser():
    timing = TimingAnalyser(baseline_threshold_ms=5000, z_score_threshold=3)
    
    # Establish baseline
    timing.add_baseline_many([100, 110, 95, 105, 100])
    
    # Not anomalous
    anom, reason = timing.is_anomalous(150)
    assert anom is False
    
    # Z-score anomalous (e.g. 300ms is well above the 100ms baseline stdev)
    anom, reason = timing.is_anomalous(300)
    assert anom is True
    assert "z-score" in reason
    
    # Absolute threshold anomalous
    anom, reason = timing.is_anomalous(6000)
    assert anom is True
    assert "threshold" in reason
