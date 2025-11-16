#!/usr/bin/env python3
"""Generate a rogue self-signed certificate for testing BAD_CERT rejection."""
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_rogue_cert():
    """Generate a self-signed certificate NOT signed by our CA."""
    
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "alice"),  # Impersonate alice!
    ])
    
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # Self-signed, not by our CA
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("alice")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())  # Self-signed!
    )
    
    os.makedirs("certs", exist_ok=True)
    
    # Save rogue certificate
    with open("certs/rogue-cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open("certs/rogue-key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    print("[+] Generated rogue self-signed certificate:")
    print("    certs/rogue-cert.pem")
    print("    certs/rogue-key.pem")
    print("[!] This cert is NOT signed by your CA and should be rejected!")


if __name__ == "__main__":
    generate_rogue_cert()
