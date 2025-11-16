#!/usr/bin/env python3
"""
Send a tampered message to the server to demonstrate SIG_FAIL detection.
This creates a modified client that deliberately tampers with a message.
"""
import sys
import os
import socket
import json
import secrets

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.client import SecureChatClient
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.common.protocol import ChatMsg
from app.crypto import aes, sign


class TamperingClient(SecureChatClient):
    """Modified client that sends a tampered message to test SIG_FAIL."""
    
    def send_tampered_message(self, plaintext: str):
        """Send a message with tampered ciphertext but original signature."""
        if not self.session_key or not self.transcript:
            print(f"[!] No active session. Call start_chat_session() first.")
            return False
        
        print("\n[*] Creating LEGITIMATE message...")
        # Encrypt message
        ct = aes.encrypt(self.session_key, plaintext.encode('utf-8'))
        ct_b64 = b64e(ct)
        
        # Create digest and sign
        ts = now_ms()
        digest = sha256_hex(f"{self.seqno}{ts}{ct_b64}".encode('utf-8')).encode('utf-8')
        signature = sign.sign_digest(self.client_key, digest)
        
        print(f"   Original ciphertext: {ct_b64[:40]}...")
        print(f"   Signature: {b64e(signature)[:40]}...")
        
        # TAMPER WITH THE CIPHERTEXT
        print("\n[!] TAMPERING: Flipping a bit in the ciphertext...")
        tampered_ct = bytearray(ct)
        tampered_ct[len(tampered_ct)//2] ^= 0xFF  # Flip multiple bits
        tampered_ct_b64 = b64e(bytes(tampered_ct))
        
        print(f"   Tampered ciphertext: {tampered_ct_b64[:40]}...")
        print(f"   (Kept the SAME signature - this will fail!)")
        
        # Create message with TAMPERED ciphertext but ORIGINAL signature
        msg = ChatMsg(
            seqno=self.seqno,
            ts=ts,
            ct=tampered_ct_b64,  # TAMPERED!
            sig=b64e(signature)  # Original signature, won't match!
        )
        
        print(f"\n[*] Sending tampered message to server...")
        self.sock.sendall(msg.model_dump_json().encode('utf-8'))
        
        # Wait for server response
        data = self.sock.recv(4096).decode('utf-8')
        response = json.loads(data)
        
        if response.get('type') == 'error' and response.get('code') == 'SIG_FAIL':
            print(f"\n[PASS] SUCCESS: Server detected tampering!")
            print(f"   Error code: {response['code']}")
            print(f"   Message: {response['message']}")
            return True
        else:
            print(f"\n[FAIL] UNEXPECTED: Server did not detect tampering")
            print(f"   Response: {response}")
            return False


def main():
    print("\n" + "="*70)
    print("TEST: Send Tampered Message to Live Server")
    print("="*70)
    print("\nThis test connects to the server and deliberately sends")
    print("a message with tampered ciphertext to trigger SIG_FAIL.\n")
    
    # Check if server is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("localhost", 5000))
        sock.close()
    except:
        print("ERROR: Server not running!")
        print("   Please start the server first: python -m app.server")
        return
    
    try:
        # Create client
        print("[*] Connecting as alice...")
        client = TamperingClient("localhost", 5000, username="alice")
        client.connect()
        
        if not client._certificate_exchange():
            print("[!] Certificate exchange failed")
            return
        
        # Login
        print("[*] Logging in...")
        if not client.login("alice@example.com", "alicepass123"):
            print("[!] Login failed - make sure alice is registered!")
            return
        
        # Start session
        print("[*] Starting chat session...")
        client.start_chat_session(secrets.token_hex(8))
        
        # Send tampered message
        success = client.send_tampered_message("This message will be tampered with")
        
        if success:
            print("\n" + "="*70)
            print("TAMPERING TEST PASSED")
            print("="*70)
            print("The server correctly detected the tampered message")
            print("and rejected it with SIG_FAIL error.")
            print("="*70)
        
    except Exception as e:
        print(f"\nTest error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
