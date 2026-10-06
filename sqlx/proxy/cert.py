"""
sqlx/proxy/cert.py
~~~~~~~~~~~~~~~~~~
Lightweight Certificate Authority for HTTPS MITM interception.
Generates a Root CA on first run, and dynamic leaf certificates for domains.
Uses standard openssl CLI.
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

# We store certs in ~/.sqlx/certs/ by default
CERT_DIR = Path.home() / ".sqlx" / "certs"
CA_KEY = CERT_DIR / "ca.key"
CA_CERT = CERT_DIR / "ca.crt"

def ensure_ca_exists():
    """Ensure the Root CA exists, create if it doesn't."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY.exists() and CA_CERT.exists():
        return

    # Generate Root CA Private Key
    subprocess.run(
        ["openssl", "genrsa", "-out", str(CA_KEY), "2048"],
        check=True, capture_output=True
    )
    # Generate Root CA Certificate
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-days", "3650",
        "-key", str(CA_KEY), "-out", str(CA_CERT),
        "-subj", "/CN=SQLX MITM Proxy CA/O=SQLX/C=US"
    ], check=True, capture_output=True)
    
    print(f"\n[+] Created new Proxy CA at {CA_CERT}")
    print(f"[!] Please install this CA in your browser to trust intercepted HTTPS traffic.")

def get_cert_for_domain(domain: str) -> Path:
    """
    Generate and return the path to a combined cert+key PEM file for a specific domain.
    """
    ensure_ca_exists()
    
    # Strip port if present
    domain = domain.split(":")[0]
    
    cert_path = CERT_DIR / f"{domain}.pem"
    if cert_path.exists():
        return cert_path

    key_path = CERT_DIR / f"{domain}.key"
    req_path = CERT_DIR / f"{domain}.csr"
    crt_path = CERT_DIR / f"{domain}.crt"

    try:
        # 1. Generate Domain Key
        subprocess.run(["openssl", "genrsa", "-out", str(key_path), "2048"], 
                       check=True, capture_output=True)
        
        # 2. Generate CSR
        subprocess.run([
            "openssl", "req", "-new", "-key", str(key_path), "-out", str(req_path),
            "-subj", f"/CN={domain}/O=SQLX Intercept/C=US"
        ], check=True, capture_output=True)
        
        # 3. Sign with CA
        subprocess.run([
            "openssl", "x509", "-req", "-days", "365",
            "-in", str(req_path), "-CA", str(CA_CERT), "-CAkey", str(CA_KEY),
            "-set_serial", str(int(os.urandom(8).hex(), 16)), "-out", str(crt_path)
        ], check=True, capture_output=True)
        
        # 4. Combine key and crt into one pem for Python SSL
        with open(cert_path, "wb") as pem:
            pem.write(key_path.read_bytes())
            pem.write(crt_path.read_bytes())
            
        return cert_path
    finally:
        # Cleanup temp files
        for p in (key_path, req_path, crt_path):
            if p.exists():
                p.unlink()
