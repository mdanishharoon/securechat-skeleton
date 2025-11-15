"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import argparse
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca(name: str, output_dir: str = "certs", key_size: int = 2048, validity_days: int = 3650):
    """
    Generate a self-signed Root CA certificate and private key.
    
    Args:
        name: Common Name for the CA (e.g., "FAST-NU Root CA")
        output_dir: Directory to save cert and key
        key_size: RSA key size in bits
        validity_days: Certificate validity period in days
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Generating {key_size}-bit RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    print(f"[*] Creating self-signed certificate for '{name}'...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    key_path = os.path.join(output_dir, "ca-key.pem")
    cert_path = os.path.join(output_dir, "ca-cert.pem")
    
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
    
    print(f"\n[+] Root CA generated successfully!")
    print(f"    Certificate: {cert_path}")
    print(f"    Private Key: {key_path}")
    print(f"    Valid for: {validity_days} days")
    print(f"\n[!] WARNING: Keep ca-key.pem secure and do NOT commit to git!")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA certificate")
    parser.add_argument(
        "--name",
        default="SecureChat Root CA",
        help="Common Name for the CA (default: SecureChat Root CA)"
    )
    parser.add_argument(
        "--out",
        default="certs",
        help="Output directory (default: certs)"
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
        default=3650,
        help="Validity period in days (default: 3650)"
    )
    
    args = parser.parse_args()
    generate_ca(args.name, args.out, args.keysize, args.days)


if __name__ == "__main__":
    main()
