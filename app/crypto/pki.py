"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID


class CertValidationError(Exception):
    """Certificate validation failed."""
    pass


def validate_cert(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    expected_cn: str = None
) -> tuple[bool, str]:
    """
    Validate X.509 certificate against CA certificate.
    
    Checks:
    - Certificate is signed by CA
    - Certificate is within validity period
    - CN/SAN matches expected hostname (if provided)
    
    Args:
        cert_pem: Certificate to validate (PEM format)
        ca_cert_pem: CA certificate (PEM format)
        expected_cn: Expected CN or SAN hostname (optional)
        
    Returns:
        (is_valid, error_message) tuple
        If valid: (True, "")
        If invalid: (False, "error description")
    """
    try:
        # Load certificates
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
        
        # Check 1: Verify signature (cert signed by CA)
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters,
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return (False, f"BAD_CERT: Signature verification failed - {str(e)}")
        
        # Check 2: Verify validity period
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            return (False, f"BAD_CERT: Certificate not yet valid (starts {cert.not_valid_before_utc})")
        if now > cert.not_valid_after_utc:
            return (False, f"BAD_CERT: Certificate expired (ended {cert.not_valid_after_utc})")
        
        # Check 3: Verify CN/SAN if expected_cn provided
        if expected_cn:
            cn_match = False
            
            # Check CN
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    cn = cn_attrs[0].value
                    if cn == expected_cn:
                        cn_match = True
            except Exception:
                pass
            
            # Check SAN
            if not cn_match:
                try:
                    san_ext = cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    )
                    san_names = san_ext.value.get_values_for_type(x509.DNSName)
                    if expected_cn in san_names:
                        cn_match = True
                except Exception:
                    pass
            
            if not cn_match:
                return (False, f"BAD_CERT: CN/SAN mismatch (expected '{expected_cn}')")
        
        return (True, "")
        
    except Exception as e:
        return (False, f"BAD_CERT: Validation error - {str(e)}")


def get_cert_fingerprint(cert_pem: bytes) -> str:
    """
    Get SHA-256 fingerprint of certificate.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Hex fingerprint string
    """
    from cryptography.hazmat.primitives import hashes
    
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def get_cert_cn(cert_pem: bytes) -> str:
    """
    Extract Common Name from certificate.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        CN string
    """
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    return ""
