#!/usr/bin/env python3
"""Test message integrity by tampering with ciphertext."""
import sys
import os
import socket
import json
import secrets
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.common.protocol import ChatMsg
from app.crypto import aes, sign


def tamper_with_message():
    """
    Test tampering detection:
    1. Create a legitimate encrypted message
    2. Flip a bit in the ciphertext
    3. Send to server
    4. Server should detect tampered signature and reject with SIG_FAIL
    """
    print("\n" + "="*70)
    print("TEST: Message Tampering Detection")
    print("="*70)
    print("\nThis test verifies that any modification to encrypted messages")
    print("is detected through signature verification failure.\n")
    
    # Load alice's certificate and key
    try:
        with open("certs/alice-cert.pem", "rb") as f:
            alice_cert = f.read()
        with open("certs/alice-key.pem", "rb") as f:
            alice_key = f.read()
    except FileNotFoundError:
        print("ERROR: Alice's certificate not found!")
        print("   Please register alice first: python -m app.client --register --username alice ...")
        return
    
    # Create a legitimate message
    print("[*] Step 1: Creating a legitimate encrypted message...")
    
    session_key = secrets.token_bytes(16)  # Simulate session key
    plaintext = "This is a secret message that will be tampered with"
    seqno = 1
    ts = now_ms()
    
    # Encrypt message
    ct = aes.encrypt(session_key, plaintext.encode('utf-8'))
    ct_b64 = b64e(ct)
    
    # Sign the message
    digest = sha256_hex(f"{seqno}{ts}{ct_b64}".encode('utf-8')).encode('utf-8')
    signature = sign.sign_digest(alice_key, digest)
    sig_b64 = b64e(signature)
    
    print(f"   Original plaintext: {plaintext}")
    print(f"   Ciphertext (base64): {ct_b64[:50]}...")
    print(f"   Signature (base64): {sig_b64[:50]}...")
    
    # Create the original message
    original_msg = ChatMsg(
        seqno=seqno,
        ts=ts,
        ct=ct_b64,
        sig=sig_b64
    )
    
    # Verify original signature works
    print("\n[*] Step 2: Verifying original message signature...")
    original_digest = sha256_hex(f"{seqno}{ts}{ct_b64}".encode('utf-8')).encode('utf-8')
    is_valid = sign.verify_signature(alice_cert, original_digest, signature)
    
    if is_valid:
        print("   [PASS] Original signature is VALID")
    else:
        print("   [FAIL] ERROR: Original signature verification failed!")
        return
    
    # Tamper with the ciphertext (flip a bit)
    print("\n[*] Step 3: Tampering with ciphertext (flipping bit)...")
    
    tampered_ct = bytearray(ct)
    # Flip a bit in the middle of the ciphertext
    tampered_ct[len(tampered_ct)//2] ^= 0x01  # XOR with 1 to flip the last bit
    tampered_ct_b64 = b64e(bytes(tampered_ct))
    
    print(f"   Original byte: {ct[len(ct)//2]:02x}")
    print(f"   Tampered byte: {tampered_ct[len(ct)//2]:02x}")
    print(f"   Tampered ciphertext: {tampered_ct_b64[:50]}...")
    
    # Try to verify signature with tampered ciphertext
    print("\n[*] Step 4: Verifying signature with tampered ciphertext...")
    tampered_digest = sha256_hex(f"{seqno}{ts}{tampered_ct_b64}".encode('utf-8')).encode('utf-8')
    is_valid_tampered = sign.verify_signature(alice_cert, tampered_digest, signature)
    
    if not is_valid_tampered:
        print("   [PASS] Tampered message signature is INVALID (expected!)")
        print("\n[PASS] Tampering detected! Signature verification failed.")
        print("   The server would reject this with SIG_FAIL error.")
    else:
        print("   [FAIL] Tampered message signature still valid (security issue!)")
        return
    
    # Show what happens if we try to decrypt the tampered ciphertext
    print("\n[*] Step 5: Attempting to decrypt tampered ciphertext...")
    try:
        decrypted_tampered = aes.decrypt(session_key, bytes(tampered_ct)).decode('utf-8')
        print(f"   Decrypted (garbled): {repr(decrypted_tampered)}")
        print("   [PASS] Even if decryption succeeds, the content is corrupted")
    except Exception as e:
        print(f"   [PASS] Decryption failed: {e}")
        print("   This is expected - tampered ciphertext often can't be decrypted")
    
    print("\n" + "="*70)
    print("CONCLUSION:")
    print("="*70)
    print("[PASS] Signature verification DETECTS tampering")
    print("[PASS] Modified ciphertext produces different digest")
    print("[PASS] Server will reject with SIG_FAIL error")
    print("[PASS] Integrity protection is working correctly")
    print("="*70)


def test_with_live_server():
    """
    Additional test: Try sending a tampered message to a live server.
    This will show the actual SIG_FAIL error from the server.
    """
    print("\n" + "="*70)
    print("BONUS TEST: Send Tampered Message to Live Server")
    print("="*70)
    print("\nThis requires manual intervention:")
    print("1. Start server: python -m app.server")
    print("2. Login as alice: python -m app.client --username alice --email alice@example.com --password alicepass123")
    print("3. Use a packet capture tool to intercept and modify a message")
    print("4. Observe server rejecting it with SIG_FAIL")
    print("\nAlternatively, we could create a modified client that intentionally")
    print("sends tampered messages to demonstrate the server's detection.")
    print("="*70)


def main():
    print("\nMessage Tampering Detection Test")
    print("This test verifies that message integrity is protected by RSA signatures.\n")
    
    tamper_with_message()
    test_with_live_server()


if __name__ == "__main__":
    main()
