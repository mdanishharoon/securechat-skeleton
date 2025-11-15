"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


# RFC 3526 2048-bit MODP Group (Group 14) - safe prime
RFC3526_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
RFC3526_GENERATOR = 2


def generate_dh_params() -> tuple[int, int]:
    """
    Generate DH parameters (p, g).
    Uses RFC 3526 2048-bit safe prime for security.
    
    Returns:
        (p, g) tuple
    """
    return (RFC3526_PRIME_2048, RFC3526_GENERATOR)


def generate_private_key(p: int, g: int) -> int:
    """
    Generate a random DH private key.
    
    Args:
        p: Prime modulus
        g: Generator
        
    Returns:
        Random private key a (where 1 < a < p-1)
    """
    return secrets.randbelow(p - 2) + 1


def compute_public_key(g: int, private_key: int, p: int) -> int:
    """
    Compute DH public key: g^a mod p.
    
    Args:
        g: Generator
        private_key: Private key a
        p: Prime modulus
        
    Returns:
        Public key A = g^a mod p
    """
    return pow(g, private_key, p)


def compute_shared_secret(peer_public_key: int, private_key: int, p: int) -> int:
    """
    Compute DH shared secret: B^a mod p (or A^b mod p).
    
    Args:
        peer_public_key: Other party's public key (A or B)
        private_key: Our private key (b or a)
        p: Prime modulus
        
    Returns:
        Shared secret Ks
    """
    return pow(peer_public_key, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    Uses Trunc16(SHA256(big-endian(Ks))) as specified.
    
    Args:
        shared_secret: DH shared secret (integer)
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash and truncate to 16 bytes
    hash_digest = hashlib.sha256(ks_bytes).digest()
    return hash_digest[:16]


def full_dh_exchange_client(p: int, g: int) -> tuple[int, int]:
    """
    Client-side: Generate private key and public key.
    
    Args:
        p: Prime modulus
        g: Generator
        
    Returns:
        (private_key, public_key_A)
    """
    private_key = generate_private_key(p, g)
    public_key = compute_public_key(g, private_key, p)
    return (private_key, public_key)


def full_dh_exchange_server(p: int, g: int, client_public_key: int) -> tuple[int, bytes]:
    """
    Server-side: Generate keys, compute shared secret, derive AES key.
    
    Args:
        p: Prime modulus
        g: Generator
        client_public_key: Client's public key A
        
    Returns:
        (server_public_key_B, aes_key)
    """
    private_key = generate_private_key(p, g)
    public_key = compute_public_key(g, private_key, p)
    shared_secret = compute_shared_secret(client_public_key, private_key, p)
    aes_key = derive_aes_key(shared_secret)
    return (public_key, aes_key)
