"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_cert_path: str, ca_key_path: str):
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


def generate_cert(
    cn: str,
    output_prefix: str,
    ca_cert_path: str = "certs/ca-cert.pem",
    ca_key_path: str = "certs/ca-key.pem",
    key_size: int = 2048,
    validity_days: int = 365
):
    """
    Generate a certificate signed by the Root CA.
    
    Args:
        cn: Common Name (e.g., "server.local" or "client.local")
        output_prefix: Output file prefix (e.g., "certs/server")
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        key_size: RSA key size in bits
        validity_days: Certificate validity period in days
    """
    print(f"[*] Loading CA certificate and key...")
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path)
    
    print(f"[*] Generating {key_size}-bit RSA key pair for '{cn}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    print(f"[*] Creating certificate for '{cn}' signed by CA...")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    os.makedirs(os.path.dirname(output_prefix) or ".", exist_ok=True)
    
    key_path = f"{output_prefix}-key.pem"
    cert_path = f"{output_prefix}-cert.pem"
    
    print(f"[*] Saving private key to {key_path}")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    print(f"[*] Saving certificate to {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[+] Certificate generated successfully!")
    print(f"    CN: {cn}")
    print(f"    Certificate: {cert_path}")
    print(f"    Private Key: {key_path}")
    print(f"    Valid for: {validity_days} days")
    print(f"\n[!] WARNING: Keep private key secure and do NOT commit to git!")


def main():
    parser = argparse.ArgumentParser(description="Generate certificate signed by Root CA")
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (e.g., server.local, client.local)"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output file prefix (e.g., certs/server)"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca-cert.pem",
        help="Path to CA certificate (default: certs/ca-cert.pem)"
    )
    parser.add_argument(
        "--ca-key",
        default="certs/ca-key.pem",
        help="Path to CA private key (default: certs/ca-key.pem)"
    )
    parser.add_argument(
        "--keysize",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Validity period in days (default: 365)"
    )
    
    args = parser.parse_args()
    generate_cert(
        args.cn,
        args.out,
        args.ca_cert,
        args.ca_key,
        args.keysize,
        args.days
    )


if __name__ == "__main__":
    main()
