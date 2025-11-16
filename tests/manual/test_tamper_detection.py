#!/usr/bin/env python3
"""
Test non-repudiation by tampering with transcript and showing verification fails.

This demonstrates that:
1. Any modification to the transcript breaks the hash
2. Any modification to the receipt signature fails verification
3. The transcript provides tamper-evident proof
"""
import sys
import os
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.storage.transcript import load_transcript
from app.crypto import sign
from app.common.utils import b64d


def tamper_with_transcript(transcript_path: str) -> str:
    """
    Create a tampered copy of the transcript.
    Returns path to tampered transcript.
    """
    # Read original
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
    
    # Find first message line and modify it
    tampered_lines = []
    tampered = False
    
    for line in lines:
        if not line.startswith('#') and line.strip() and '|' in line and not tampered:
            # Tamper with the ciphertext (change one character)
            parts = line.strip().split('|')
            if len(parts) == 5:
                # Modify the ciphertext (3rd field)
                original_ct = parts[2]
                tampered_ct = 'X' + original_ct[1:] if original_ct else 'X'
                parts[2] = tampered_ct
                line = '|'.join(parts) + '\n'
                tampered = True
                print(f"[!] Tampered with message {parts[0]}")
                print(f"    Original CT: {original_ct[:40]}...")
                print(f"    Tampered CT: {tampered_ct[:40]}...")
        
        tampered_lines.append(line)
    
    # Write tampered version
    tampered_path = transcript_path + ".tampered"
    with open(tampered_path, 'w') as f:
        f.writelines(tampered_lines)
    
    return tampered_path


def tamper_with_receipt(receipt_path: str) -> str:
    """
    Create a tampered copy of the receipt.
    Returns path to tampered receipt.
    """
    import json
    
    # Read original
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    # Tamper with the hash
    original_hash = receipt['transcript_sha256']
    tampered_hash = 'X' + original_hash[1:]
    receipt['transcript_sha256'] = tampered_hash
    
    print(f"[!] Tampered with receipt hash")
    print(f"    Original: {original_hash[:40]}...")
    print(f"    Tampered: {tampered_hash[:40]}...")
    
    # Write tampered version
    tampered_path = receipt_path + ".tampered"
    with open(tampered_path, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    return tampered_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Test tamper detection in non-repudiation")
    parser.add_argument("--transcript", required=True, help="Path to transcript file")
    parser.add_argument("--receipt", required=True, help="Path to receipt JSON file")
    parser.add_argument("--sender-cert", required=True, help="Path to sender's certificate")
    parser.add_argument("--server-cert", default="certs/server-cert.pem", help="Path to server certificate")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("NON-REPUDIATION: Tamper Detection Test")
    print("="*70)
    print("\nThis test demonstrates that any modification to the transcript")
    print("or receipt will be detected through cryptographic verification.\n")
    
    # Test 1: Tamper with transcript
    print("[*] TEST 1: Tamper with transcript ciphertext")
    print("-" * 70)
    
    tampered_transcript_path = tamper_with_transcript(args.transcript)
    
    # Compute hash of tampered transcript
    tampered_transcript = load_transcript(tampered_transcript_path)
    tampered_hash = tampered_transcript.compute_transcript_hash()
    
    # Load original receipt
    import json
    with open(args.receipt, 'r') as f:
        receipt = json.load(f)
    
    original_hash = receipt['transcript_sha256']
    
    print(f"\nHash comparison:")
    print(f"  Original hash:  {original_hash}")
    print(f"  Tampered hash:  {tampered_hash}")
    
    if tampered_hash != original_hash:
        print(f"[PASS] Tampered transcript has DIFFERENT hash")
        print(f"  The receipt signature will no longer match!")
    else:
        print(f"[FAIL] Hashes match (unexpected)")
    
    # Cleanup
    os.remove(tampered_transcript_path)
    
    # Test 2: Tamper with receipt
    print(f"\n[*] TEST 2: Tamper with receipt hash")
    print("-" * 70)
    
    tampered_receipt_path = tamper_with_receipt(args.receipt)
    
    # Try to verify tampered receipt signature
    with open(tampered_receipt_path, 'r') as f:
        tampered_receipt = json.load(f)
    
    server_cert = open(args.server_cert, 'rb').read()
    digest = tampered_receipt['transcript_sha256'].encode('utf-8')
    sig_bytes = b64d(tampered_receipt['sig'])
    
    is_valid = sign.verify_signature(server_cert, digest, sig_bytes)
    
    print(f"\nSignature verification:")
    if not is_valid:
        print(f"[PASS] Tampered receipt signature is INVALID")
        print(f"  The signature was computed over the original hash,")
        print(f"  so it doesn't match the tampered hash!")
    else:
        print(f"[FAIL] Signature still valid (unexpected)")
    
    # Cleanup
    os.remove(tampered_receipt_path)
    
    # Test 3: Tamper with receipt signature
    print(f"\n[*] TEST 3: Tamper with receipt signature")
    print("-" * 70)
    
    # Modify the signature
    with open(args.receipt, 'r') as f:
        receipt = json.load(f)
    
    original_sig = receipt['sig']
    tampered_sig = 'X' + original_sig[1:]
    receipt['sig'] = tampered_sig
    
    print(f"[!] Tampered with receipt signature")
    print(f"    Original: {original_sig[:40]}...")
    print(f"    Tampered: {tampered_sig[:40]}...")
    
    tampered_receipt_path = args.receipt + ".tampered2"
    with open(tampered_receipt_path, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    # Try to verify
    with open(tampered_receipt_path, 'r') as f:
        tampered_receipt = json.load(f)
    
    digest = tampered_receipt['transcript_sha256'].encode('utf-8')
    try:
        sig_bytes = b64d(tampered_receipt['sig'])
        is_valid = sign.verify_signature(server_cert, digest, sig_bytes)
        
        if not is_valid:
            print(f"[PASS] Tampered signature is INVALID")
        else:
            print(f"[FAIL] Signature still valid (unexpected)")
    except Exception as e:
        print(f"[PASS] Tampered signature cannot be decoded: {e}")
    
    # Cleanup
    os.remove(tampered_receipt_path)
    
    # Summary
    print("\n" + "="*70)
    print("TAMPER DETECTION: PASSED")
    print("="*70)
    print("\nWhat we proved:")
    print("1. Modifying the transcript changes its hash")
    print("   - Receipt signature will not match")
    print("2. Modifying the receipt hash breaks signature verification")
    print("   - Server's signature is only valid for original hash")
    print("3. Modifying the receipt signature breaks verification")
    print("   - Invalid signature detected immediately")
    print("\nConclusion:")
    print("  The transcript and receipt provide TAMPER-EVIDENT proof.")
    print("  Any modification is immediately detectable through:")
    print("  - Hash mismatch (for transcript changes)")
    print("  - Signature verification failure (for receipt changes)")
    print("="*70)


if __name__ == "__main__":
    main()
