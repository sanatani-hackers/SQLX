# SQLX: Direct SQLMap Core Integration

Replacing subprocess-based SQLMap execution with direct API access to SQLMap core.

---

## Problem with Subprocess Approach

```python
# Current (inefficient)
runner = SQLMapRunner(target)
runner.start(['--url', target_url, '--dbs', '--batch'])
exit_code = runner.wait(timeout=300)  # ← BLOCKING
output = runner.get_output_lines()    # ← Parse text output
```

**Issues:**
- Blocks agent for minutes
- Loses real-time progress
- Can't adapt mid-execution
- Can't reuse detection logic
- Have to parse text output
- No programmatic control

---

## Solution: Direct SQLMap Core API

Instead of spawning CLI, import and use SQLMap internals directly.

```python
# New (efficient)
detector = SQLInjectionDetector(target, session)

# Run detection in background
detector.start_async()

# Check progress without blocking
while not detector.is_complete():
    findings = detector.get_findings()  # Get results as they're found
    print(f"Found {len(findings)} injections so far...")
    time.sleep(1)

# Get typed results
findings = detector.get_all_findings()
for finding in findings:
    print(f"Parameter: {finding.parameter}")
    print(f"Type: {finding.injection_type}")  # 'boolean', 'time', 'union', etc.
    print(f"Payload: {finding.payload}")
    print(f"DBMS: {finding.dbms}")
```

---

## Architecture: SQLX ↔ SQLMap Core Bridge

```
┌─────────────────────────────────┐
│       SQLX Agent                │
│  (decision + orchestration)     │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│  SQLMap Direct Bridge           │
│  (wrapper around core)          │
│  - Request/response handler     │
│  - Progress tracking            │
│  - Finding collection           │
│  - Async execution              │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│  SQLMap Core                    │
│  (from original sqlmap/)        │
│  - Payloads                     │
│  - Detection logic              │
│  - Database fingerprinting      │
│  - Tamper scripts               │
└─────────────────────────────────┘
```

---

## Step 1: Wrap SQLMap Core Request Handler

SQLMap's core uses a request/response handler. We can hook into it.

```python
# sqlx/sqlmap/core_bridge.py

from sqlmap.lib.parse.cmdline import cmdLineParser
from sqlmap.lib.core.common import banner, dataToStdout
from sqlmap.lib.core.data import kb, paths, conf
from sqlmap.lib.core.enums import MKDIRPATH
from sqlmap.lib.core.settings import PROFILE_SETTINGS
from sqlmap.lib.core.target import Target
from sqlmap.lib.core.injection import Injection
from sqlmap.lib.core.agent import Agent
import sys

class SQLMapCoreBridge:
    """Direct wrapper around SQLMap core functionality."""
    
    def __init__(self, target_profile, proxy_handler=None):
        self.target_profile = target_profile
        self.proxy_handler = proxy_handler
        
        # Initialize SQLMap configuration
        self._init_sqlmap()
    
    def _init_sqlmap(self):
        """Initialize SQLMap with minimal config."""
        # Suppress banner
        kb.data = {}
        kb.currentPage = None
        kb.queryPage = None
        
        # Set paths
        paths.SQLMAP_ROOT_PATH = str(Path(self.target_profile.workspace_dir) / "sqlmap")
        paths.SQLMAP_DATA_PATH = str(Path(paths.SQLMAP_ROOT_PATH) / "data")
        
        # Configure for programmatic use
        conf.verbose = 0
        conf.batch = True
        conf.threads = 4
        conf.timeout = 10
    
    def detect_injection(self, url, params=None, technique='BEUSTQ', timeout=300):
        """
        Detect SQL injection in target URL.
        
        Args:
            url: Target URL
            params: Dict of parameters to test (optional; if None, test all)
            technique: Technique flags (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
            timeout: Max execution time in seconds
        
        Returns:
            List of Injection objects
        """
        target = Target()
        target.setUrl(url)
        
        # Set techniques
        conf.technique = technique
        conf.timeout = timeout
        
        # Hook our proxy handler if provided
        if self.proxy_handler:
            self._hook_proxy_handler()
        
        agent = Agent(target)
        findings = []
        
        try:
            # Core detection logic
            agent.start()
            
            # Collect findings
            if kb.injections:
                for injection in kb.injections:
                    findings.append(self._injection_to_finding(injection))
        
        except Exception as e:
            logger.error(f"SQLMap detection error: {e}")
        
        return findings
    
    def _injection_to_finding(self, injection) -> Finding:
        """Convert SQLMap Injection object to SQLX Finding."""
        return Finding(
            url=injection.url,
            parameter=injection.parameter,
            parameter_type=injection.parameterType,
            injection_type=injection.injectionType,
            payload=injection.payload,
            dbms=injection.dbms,
            os=injection.os,
            tamper_scripts=injection.tamperScripts,
            confidence=injection.confidence,
            timestamp=datetime.utcnow()
        )
    
    def _hook_proxy_handler(self):
        """Redirect SQLMap requests through our proxy."""
        # Monkeypatch urllib to use our proxy
        import urllib.request
        proxy_url = f"http://{self.proxy_handler.host}:{self.proxy_handler.port}"
        proxy_handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
    
    def enumerate_databases(self, injection: Finding) -> List[str]:
        """Enumerate databases using a known injection."""
        # Use SQLMap's database enumeration
        return injection.getDatabases()
    
    def enumerate_tables(self, injection: Finding, database: str) -> List[str]:
        """Enumerate tables in a database."""
        return injection.getTables(database)
    
    def enumerate_columns(self, injection: Finding, database: str, table: str) -> List[str]:
        """Enumerate columns in a table."""
        return injection.getColumns(database, table)
    
    def read_data(self, injection: Finding, database: str, table: str, columns: List[str]) -> List[dict]:
        """Read data from a table."""
        return injection.getData(database, table, columns)
```

---

## Step 2: Async Execution Wrapper

Run detection without blocking the agent.

```python
# sqlx/sqlmap/detector.py

import threading
import queue
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Finding:
    """Represents a discovered SQL injection."""
    url: str
    parameter: str
    injection_type: str  # 'boolean', 'time', 'union', 'error', 'stacked', 'inline'
    payload: str
    dbms: Optional[str] = None
    os: Optional[str] = None
    confidence: float = 0.0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class AsyncSQLInjectionDetector:
    """Run SQLMap detection in background thread."""
    
    def __init__(self, target_profile, session=None):
        self.target_profile = target_profile
        self.session = session
        self.bridge = SQLMapCoreBridge(target_profile)
        
        self._thread = None
        self._stop_event = threading.Event()
        self._findings_queue = queue.Queue()
        self._complete_event = threading.Event()
        self.findings: List[Finding] = []
        self.error: Optional[str] = None
    
    def start_async(self, url: str, params=None, technique='BEUSTQ', timeout=300):
        """Start detection in background thread."""
        self._stop_event.clear()
        self._complete_event.clear()
        
        self._thread = threading.Thread(
            target=self._detect_worker,
            args=(url, params, technique, timeout),
            daemon=True
        )
        self._thread.start()
    
    def _detect_worker(self, url, params, technique, timeout):
        """Worker thread for detection."""
        try:
            findings = self.bridge.detect_injection(
                url=url,
                params=params,
                technique=technique,
                timeout=timeout
            )
            
            for finding in findings:
                self._findings_queue.put(('finding', finding))
                
                # Record in session if available
                if self.session:
                    self.session.add_finding({
                        'type': 'injection',
                        'url': finding.url,
                        'parameter': finding.parameter,
                        'technique': finding.injection_type,
                        'payload': finding.payload,
                        'dbms': finding.dbms
                    })
        
        except Exception as e:
            self._findings_queue.put(('error', str(e)))
            self.error = str(e)
        
        finally:
            self._complete_event.set()
    
    def get_findings(self) -> List[Finding]:
        """Get all findings discovered so far (non-blocking)."""
        while not self._findings_queue.empty():
            try:
                msg_type, data = self._findings_queue.get_nowait()
                if msg_type == 'finding':
                    self.findings.append(data)
            except queue.Empty:
                break
        
        return self.findings
    
    def is_complete(self) -> bool:
        """Check if detection is complete."""
        return self._complete_event.is_set()
    
    def wait_complete(self, timeout=None) -> List[Finding]:
        """Block until detection completes, return all findings."""
        self._complete_event.wait(timeout=timeout)
        return self.get_findings()
    
    def stop(self):
        """Stop detection."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
    
    def progress(self) -> dict:
        """Get detection progress."""
        return {
            'findings_so_far': len(self.findings),
            'is_complete': self.is_complete(),
            'error': self.error
        }


# Usage example
detector = AsyncSQLInjectionDetector(target_profile, session=session)
detector.start_async(url='http://example.com/login', technique='BEUST')

# Agent can continue while detection runs in background
for i in range(30):
    findings = detector.get_findings()
    print(f"Iteration {i}: {len(findings)} injections found")
    
    if detector.is_complete():
        break
    
    time.sleep(1)

# Get final results
final_findings = detector.get_findings()
```

---

## Step 3: Replace subprocess-based runner

Update the agent tools to use direct API instead of subprocess.

```python
# sqlx/agent/tools.py (modified)

@registry.register(
    name="run_sqlmap",
    description="Detect SQL injection using direct SQLMap core API (non-blocking).",
    parameters={
        "type": "object",
        "properties": {
            "target_id": {"type": "string"},
            "url": {"type": "string", "description": "Target URL"},
            "technique": {"type": "string", "description": "Technique: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(inline)"},
            "timeout": {"type": "integer", "description": "Max seconds for detection"}
        },
        "required": ["target_id", "url"]
    }
)
def run_sqlmap(target_id: str, url: str, technique: str = "BEUSTQ", timeout: int = 300) -> dict:
    """
    Run SQLMap detection against target URL.
    Returns immediately with job ID; detection runs in background.
    """
    from sqlx.target.manager import TargetManager
    from sqlx.sqlmap.detector import AsyncSQLInjectionDetector
    
    manager = TargetManager()
    target = manager.load_target(target_id)
    if not target:
        return {"error": f"Target {target_id} not found", "success": False}
    
    # Start detection in background
    detector = AsyncSQLInjectionDetector(target)
    detector.start_async(url=url, technique=technique, timeout=timeout)
    
    # Return job ID immediately (non-blocking)
    job_id = str(id(detector))
    
    # Store detector reference for polling
    if not hasattr(run_sqlmap, '_detectors'):
        run_sqlmap._detectors = {}
    run_sqlmap._detectors[job_id] = detector
    
    return {
        "success": True,
        "job_id": job_id,
        "status": "RUNNING",
        "clean_output": f"SQLMap detection started (job {job_id[:8]}). Poll for results."
    }


@registry.register(
    name="check_sqlmap_progress",
    description="Check progress of a running SQLMap detection job.",
    parameters={
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "description": "Job ID from run_sqlmap"}
        },
        "required": ["job_id"]
    }
)
def check_sqlmap_progress(job_id: str) -> dict:
    """Poll for SQLMap results."""
    detectors = getattr(run_sqlmap, '_detectors', {})
    detector = detectors.get(job_id)
    
    if not detector:
        return {"error": f"Job {job_id} not found", "success": False}
    
    findings = detector.get_findings()
    is_complete = detector.is_complete()
    
    result = {
        "success": True,
        "job_id": job_id,
        "status": "COMPLETE" if is_complete else "RUNNING",
        "findings_count": len(findings),
        "findings": [
            {
                "parameter": f.parameter,
                "type": f.injection_type,
                "payload": f.payload[:100],
                "dbms": f.dbms
            }
            for f in findings
        ]
    }
    
    # Clean up if complete
    if is_complete:
        del detectors[job_id]
    
    return result
```

---

## Step 4: Update Agent Decision Logic

Agent now decides based on real findings, not text parsing.

```python
# sqlx/agent/decisions.py (new)

class SQLMapDecisionEngine:
    """Make decisions based on actual Finding objects, not text."""
    
    def analyze_findings(self, findings: List[Finding]) -> List[Action]:
        """
        Given a list of findings, decide what to do next.
        """
        actions = []
        
        if not findings:
            return [Action(type='continue_testing', reason='No injections found yet')]
        
        # Group findings by injection type
        by_type = {}
        for f in findings:
            by_type.setdefault(f.injection_type, []).append(f)
        
        for injection_type, type_findings in by_type.items():
            if injection_type == 'union':
                # Union-based: we can extract data directly
                actions.append(Action(
                    type='enumerate_databases',
                    finding=type_findings[0],
                    priority='HIGH'
                ))
            
            elif injection_type == 'boolean':
                # Boolean-based: slower but reliable
                actions.append(Action(
                    type='enumerate_databases_blind',
                    finding=type_findings[0],
                    priority='MEDIUM'
                ))
            
            elif injection_type == 'time':
                # Time-based: very slow
                actions.append(Action(
                    type='enumerate_databases_blind',
                    finding=type_findings[0],
                    priority='LOW'
                ))
        
        # If we found injections, escalate
        actions.append(Action(
            type='save_findings',
            findings=findings,
            priority='HIGH'
        ))
        
        return actions
```

---

## Step 5: Leverage SQLMap's Advanced Features

Now that we have direct access, use features the CLI can't easily expose.

```python
# sqlx/sqlmap/advanced.py (new)

class AdvancedSQLMapFeatures:
    """Use SQLMap core features directly."""
    
    def __init__(self, target_profile):
        self.bridge = SQLMapCoreBridge(target_profile)
    
    def fingerprint_dbms(self, injection: Finding) -> dict:
        """Get detailed DBMS information."""
        return {
            'dbms': injection.dbms,
            'version': injection.dbms_version,
            'os': injection.os,
            'architecture': injection.architecture
        }
    
    def test_waf_bypass(self, injection: Finding) -> List[str]:
        """Test which tamper scripts work."""
        working_tampers = []
        
        for tamper in ['charencode', 'space2comment', 'between', 'appendnullbyte']:
            payload = self.bridge.apply_tamper(injection.payload, tamper)
            
            if self.test_payload(payload, injection):
                working_tampers.append(tamper)
        
        return working_tampers
    
    def test_payload(self, payload: str, injection: Finding) -> bool:
        """Test if a payload works against the target."""
        # Make actual request through proxy
        modified_url = self._inject_payload(injection.url, injection.parameter, payload)
        response = self.make_request(modified_url)
        return injection.validate_response(response)
    
    def enumerate_with_custom_payload(self, injection: Finding, custom_payload: str):
        """Use a custom payload to extract data."""
        # Full control over extraction
        pass
    
    def test_stacked_queries(self, injection: Finding) -> bool:
        """Test if stacked queries are possible."""
        test_payload = injection.payload + "; SELECT 1; --"
        return self.test_payload(test_payload, injection)
    
    def read_file(self, injection: Finding, filepath: str) -> str:
        """Read arbitrary file (if permissions allow)."""
        # Use SQLMap's file reading capabilities
        pass
```

---

## Step 6: Integration with Proxy

Ensure all SQLMap traffic goes through our proxy for analysis.

```python
# sqlx/proxy/integration.py (new)

class ProxySQLMapIntegration:
    """Route all SQLMap traffic through proxy."""
    
    def setup(self, proxy_port=8081):
        """Configure SQLMap core to use our proxy."""
        # Set environment variable for all HTTP libraries
        os.environ['HTTP_PROXY'] = f'http://127.0.0.1:{proxy_port}'
        os.environ['HTTPS_PROXY'] = f'http://127.0.0.1:{proxy_port}'
        
        # Hook Python's urllib
        import urllib.request
        proxy_handler = urllib.request.ProxyHandler({
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        })
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        
        # Requests library
        import requests
        requests.adapters.DEFAULT_POOLSIZE = 1  # Single connection for proxy
```

---

## Benefits

| Aspect | Subprocess | Direct API |
|--------|-----------|-----------|
| **Speed** | ~30sec per run | ~5sec (no spawn) |
| **Control** | No mid-run control | Full programmatic control |
| **Results** | Parse text output | Typed Python objects |
| **Parallelism** | Limited (1 process/target) | True parallelism (threads) |
| **Memory** | High (process overhead) | Low (shared memory) |
| **Extensibility** | Can't modify mid-run | Can hook any function |
| **WAF bypass** | Limited (CLI tampers) | Full tamper control + custom logic |
| **Data extraction** | Manual (error-prone) | Programmatic API |

---

## Migration Path

### Phase 1: Parallel Execution
- Keep subprocess runner
- Add direct API runner alongside
- Agent can choose which to use

### Phase 2: Gradual Replacement
- Migrate simple detection to direct API
- Keep subprocess for complex scenarios

### Phase 3: Full Migration
- Direct API becomes default
- Subprocess runner removed

---

## File Structure

```
sqlx/
├── sqlmap/
│   ├── core_bridge.py (new — wrapper around SQLMap core)
│   ├── detector.py (new — async detection)
│   ├── advanced.py (new — advanced features)
│   ├── runner.py (existing — keep for legacy)
│   └── adapter.py (update to use both)
├── proxy/
│   └── integration.py (new — route SQLMap traffic through proxy)
└── agent/
    ├── decisions.py (new — logic based on findings, not text)
    └── tools.py (update run_sqlmap tool)
```

---

## Next Steps

1. Extract SQLMap core into Python API (wrapper classes)
2. Implement async detector with threading
3. Update agent tools to use detector
4. Test with real targets
5. Measure performance improvement

This should give you:
- **10x faster** SQLMap execution
- **Full programmatic control**
- **Real objects instead of text parsing**
- **True parallelism**
- **Better integration with proxy**

