#!/usr/bin/env python3
"""
Offline verification of transcript and receipt for non-repudiation.

This script demonstrates:
1. Loading a transcript and receipt from disk
2. Verifying each message's RSA signature
3. Verifying the receipt's RSA signature over the transcript hash
4. Proving non-repudiation: the transcript is cryptographically bound to both parties
"""
import sys
import os
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.storage.transcript import load_transcript
from app.crypto import sign, pki
from app.common.utils import b64d, sha256_hex


def load_certificate(cert_path: str) -> bytes:
    """Load a certificate from file."""
    with open(cert_path, 'rb') as f:
        return f.read()


def verify_message_signature(msg: dict, sender_cert: bytes) -> bool:
    """
    Verify a single message's RSA signature.
    
    The digest is: SHA256(seqno || ts || ct_base64)
    """
    # Recompute the digest
    digest_input = f"{msg['seqno']}{msg['ts']}{msg['ct']}"
    digest = sha256_hex(digest_input.encode('utf-8')).encode('utf-8')
    
    # Decode the signature
    sig_bytes = b64d(msg['sig'])
    
    # Verify signature
    return sign.verify_signature(sender_cert, digest, sig_bytes)


def verify_receipt_signature(receipt_data: dict, server_cert: bytes) -> bool:
    """
    Verify the receipt's RSA signature over the transcript hash.
    
    The receipt is signed over: transcript_sha256 (as UTF-8 bytes)
    """
    digest = receipt_data['transcript_sha256'].encode('utf-8')
    sig_bytes = b64d(receipt_data['sig'])
    
    return sign.verify_signature(server_cert, digest, sig_bytes)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Verify transcript and receipt for non-repudiation")
    parser.add_argument("--transcript", required=True, help="Path to transcript file")
    parser.add_argument("--receipt", required=True, help="Path to receipt JSON file")
    parser.add_argument("--sender-cert", required=True, help="Path to sender's certificate (e.g., alice-cert.pem)")
    parser.add_argument("--server-cert", default="certs/server-cert.pem", help="Path to server certificate")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("NON-REPUDIATION: Offline Transcript & Receipt Verification")
    print("="*70)
    print("\nThis test verifies:")
    print("1. Each message signature (RSA over SHA-256 digest)")
    print("2. Receipt signature (RSA over transcript hash)")
    print("3. Transcript hash matches receipt")
    print()
    
    # Load transcript
    print(f"[*] Loading transcript: {args.transcript}")
    if not os.path.exists(args.transcript):
        print(f"[FAIL] Transcript file not found: {args.transcript}")
        return
    
    transcript = load_transcript(args.transcript)
    print(f"    Session ID: {transcript.session_id}")
    print(f"    Peer role: {transcript.peer_role}")
    print(f"    Messages: {len(transcript.messages)}")
    
    # Load receipt
    print(f"\n[*] Loading receipt: {args.receipt}")
    if not os.path.exists(args.receipt):
        print(f"[FAIL] Receipt file not found: {args.receipt}")
        return
    
    with open(args.receipt, 'r') as f:
        receipt_data = json.load(f)
    
    print(f"    First seq: {receipt_data['first_seq']}")
    print(f"    Last seq: {receipt_data['last_seq']}")
    print(f"    Transcript hash: {receipt_data['transcript_sha256']}")
    
    # Load certificates
    print(f"\n[*] Loading certificates...")
    sender_cert = load_certificate(args.sender_cert)
    server_cert = load_certificate(args.server_cert)
    print(f"    Sender cert: {args.sender_cert}")
    print(f"    Server cert: {args.server_cert}")
    
    # Step 1: Verify each message signature
    print(f"\n[*] Step 1: Verifying message signatures...")
    print("-" * 70)
    
    all_valid = True
    for i, msg in enumerate(transcript.messages):
        is_valid = verify_message_signature(msg, sender_cert)
        status = "[PASS]" if is_valid else "[FAIL]"
        print(f"{status} Message {msg['seqno']} (ts={msg['ts']}): signature {'VALID' if is_valid else 'INVALID'}")
        
        if not is_valid:
            all_valid = False
            print(f"    CT: {msg['ct'][:50]}...")
            print(f"    Sig: {msg['sig'][:50]}...")
    
    if all_valid:
        print(f"\n[PASS] All {len(transcript.messages)} message signatures are VALID")
    else:
        print(f"\n[FAIL] Some message signatures are INVALID")
        return
    
    # Step 2: Verify transcript hash
    print(f"\n[*] Step 2: Verifying transcript hash...")
    print("-" * 70)
    
    computed_hash = transcript.compute_transcript_hash()
    expected_hash = receipt_data['transcript_sha256']
    
    print(f"Computed hash: {computed_hash}")
    print(f"Receipt hash:  {expected_hash}")
    
    if computed_hash == expected_hash:
        print(f"[PASS] Transcript hash MATCHES receipt")
    else:
        print(f"[FAIL] Transcript hash MISMATCH")
        return
    
    # Step 3: Verify receipt signature
    print(f"\n[*] Step 3: Verifying receipt signature...")
    print("-" * 70)
    
    receipt_valid = verify_receipt_signature(receipt_data, server_cert)
    
    if receipt_valid:
        print(f"[PASS] Receipt signature is VALID")
        print(f"    Server signed the transcript hash: {expected_hash[:32]}...")
    else:
        print(f"[FAIL] Receipt signature is INVALID")
        return
    
    # Summary
    print("\n" + "="*70)
    print("NON-REPUDIATION VERIFICATION: PASSED")
    print("="*70)
    print("\nWhat we proved:")
    print(f"1. All {len(transcript.messages)} messages were signed by the sender")
    print(f"   - Sender cannot deny sending these messages")
    print(f"2. The transcript hash matches the receipt")
    print(f"   - Transcript has not been modified")
    print(f"3. The receipt was signed by the server")
    print(f"   - Server cannot deny receiving these messages")
    print(f"\nConclusion:")
    print(f"  This transcript provides cryptographic proof that:")
    print(f"  - The sender sent these specific messages")
    print(f"  - The server received these messages")
    print(f"  - Neither party can repudiate their participation")
    print("="*70)


if __name__ == "__main__":
    main()
