#!/usr/bin/env python3
"""Generate an expired certificate for testing BAD_CERT rejection."""
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_cert_path: str = "certs/ca-cert.pem", ca_key_path: str = "certs/ca-key.pem"):
    """Load CA certificate and private key."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key


def generate_expired_cert():
    """Generate an expired certificate signed by our CA."""
    
    print("[*] Loading CA...")
    ca_cert, ca_key = load_ca()
    
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate that expired 30 days ago
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, "expired-user"),
    ])
    
    now = datetime.now(timezone.utc)
    not_valid_before = now - timedelta(days=60)  # Started 60 days ago
    not_valid_after = now - timedelta(days=30)   # Expired 30 days ago
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)  # Expired!
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("expired-user")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    os.makedirs("certs", exist_ok=True)
    
    # Save expired certificate
    with open("certs/expired-cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open("certs/expired-key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    print("[+] Generated expired certificate:")
    print("    certs/expired-cert.pem")
    print("    certs/expired-key.pem")
    print(f"[!] Valid from: {not_valid_before}")
    print(f"[!] Expired on: {not_valid_after} (30 days ago)")
    print("[!] This cert should be rejected as expired!")


if __name__ == "__main__":
    generate_expired_cert()
