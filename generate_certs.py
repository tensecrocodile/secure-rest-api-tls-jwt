#!/usr/bin/env python3
"""
Generate self-signed TLS/SSL certificates for development
Usage: python generate_certs.py
"""

import os
import subprocess
from pathlib import Path

def generate_self_signed_cert():
    """Generate self-signed certificate and private key"""
    
    # Create certs directory
    cert_dir = Path('certs')
    cert_dir.mkdir(exist_ok=True)
    
    cert_file = cert_dir / 'server.crt'
    key_file = cert_dir / 'server.key'
    
    print("[*] Generating self-signed TLS certificate...")
    
    try:
        # Generate private key and certificate
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', str(key_file),
            '-out', str(cert_file),
            '-days', '365',
            '-nodes',
            '-subj', '/C=US/ST=State/L=City/O=Organization/CN=localhost'
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        # Fix permissions
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
        
        print(f"[✓] Certificate generated: {cert_file}")
        print(f"[✓] Private key generated: {key_file}")
        print("\n[*] Certificate Details:")
        print("    Validity: 365 days")
        print("    Algorithm: RSA 4096")
        print("    Common Name: localhost")
        print("\n[!] WARNING: This is a self-signed certificate for development only!")
        print("[!] Add it to your trusted certificates on the client side.\n")
        
    except FileNotFoundError:
        print("[!] OpenSSL not found!")
        print("[!] Install OpenSSL to generate certificates:")
        print("    Windows: https://slproweb.com/products/Win32OpenSSL.html")
        print("    macOS: brew install openssl")
        print("    Linux: sudo apt-get install openssl")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Error generating certificate: {e}")
        return False
    
    return True

if __name__ == '__main__':
    success = generate_self_signed_cert()
    exit(0 if success else 1)
