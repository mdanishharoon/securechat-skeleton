"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


def sign_digest(private_key_pem: bytes, digest: bytes) -> bytes:
    """
    Sign a digest using RSA private key with PKCS#1 v1.5 padding.
    
    Args:
        private_key_pem: Private key in PEM format
        digest: Pre-computed hash digest (e.g., SHA-256 output)
        
    Returns:
        Signature bytes
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Sign the digest using PKCS#1 v1.5 with SHA-256
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(cert_pem: bytes, digest: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature using public key from certificate.
    
    Args:
        cert_pem: X.509 certificate in PEM format
        digest: Pre-computed hash digest
        signature: Signature to verify
        
    Returns:
        True if signature is valid, False otherwise
    """
    from cryptography import x509
    
    # Load certificate and extract public key
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    public_key = cert.public_key()
    
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def load_private_key(key_path: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        RSA private key object
    """
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_certificate(cert_path: str) -> bytes:
    """
    Load X.509 certificate from PEM file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Certificate PEM bytes
    """
    with open(cert_path, 'rb') as f:
        return f.read()
