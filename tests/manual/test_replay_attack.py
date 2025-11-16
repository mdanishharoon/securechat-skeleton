#!/usr/bin/env python3
"""
Test replay attack detection by resending a message with an old sequence number.
The server should detect and reject it with a REPLAY error.
"""
import sys
import os
import socket
import json
import secrets
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.client import SecureChatClient
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.common.protocol import ChatMsg
from app.crypto import aes, sign


class ReplayClient(SecureChatClient):
    """Modified client that attempts replay attacks."""
    
    def send_legitimate_message(self, plaintext: str):
        """Send a legitimate message and capture it for replay."""
        if not self.session_key or not self.transcript:
            print(f"[!] No active session. Call start_chat_session() first.")
            return None
        
        print(f"\n[*] Sending legitimate message (seqno={self.seqno})...")
        
        # Encrypt message
        ct = aes.encrypt(self.session_key, plaintext.encode('utf-8'))
        ct_b64 = b64e(ct)
        
        # Create digest and sign
        ts = now_ms()
        digest = sha256_hex(f"{self.seqno}{ts}{ct_b64}".encode('utf-8')).encode('utf-8')
        signature = sign.sign_digest(self.client_key, digest)
        
        # Create message
        msg = ChatMsg(
            seqno=self.seqno,
            ts=ts,
            ct=ct_b64,
            sig=b64e(signature)
        )
        
        print(f"   Seqno: {msg.seqno}")
        print(f"   Timestamp: {msg.ts}")
        print(f"   Ciphertext: {msg.ct[:40]}...")
        print(f"   Signature: {msg.sig[:40]}...")
        
        # Send message
        self.sock.sendall(msg.model_dump_json().encode('utf-8'))
        self.seqno += 1
        
        # Wait for acknowledgment
        data = self.sock.recv(4096).decode('utf-8')
        response = json.loads(data)
        
        if response.get('type') == 'ok':
            print(f"   [PASS] Message accepted by server")
            return msg
        else:
            print(f"   [FAIL] Unexpected response: {response}")
            return None
    
    def replay_message(self, old_msg: ChatMsg):
        """Attempt to replay an old message."""
        print(f"\n[!] REPLAY ATTACK: Resending old message with seqno={old_msg.seqno}...")
        print(f"   Current seqno should be: {self.seqno}")
        print(f"   Replaying message with old seqno: {old_msg.seqno}")
        
        # Send the old message again
        self.sock.sendall(old_msg.model_dump_json().encode('utf-8'))
        
        # Wait for server response
        data = self.sock.recv(4096).decode('utf-8')
        response = json.loads(data)
        
        if response.get('type') == 'error' and response.get('code') == 'REPLAY':
            print(f"\n[PASS] SUCCESS: Server detected replay attack!")
            print(f"   Error code: {response['code']}")
            print(f"   Message: {response['message']}")
            return True
        else:
            print(f"\n[FAIL] UNEXPECTED: Server did not detect replay")
            print(f"   Response: {response}")
            return False


def main():
    print("\n" + "="*70)
    print("TEST: Replay Attack Detection")
    print("="*70)
    print("\nThis test verifies that the server detects and rejects messages")
    print("with sequence numbers that have already been used (replay attacks).\n")
    
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
        client = ReplayClient("localhost", 5000, username="alice")
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
        
        # Send first legitimate message
        msg1 = client.send_legitimate_message("First message - will be replayed")
        if not msg1:
            print("[!] Failed to send first message")
            return
        
        # Send second legitimate message to advance sequence number
        time.sleep(0.1)  # Small delay
        msg2 = client.send_legitimate_message("Second message - advances seqno")
        if not msg2:
            print("[!] Failed to send second message")
            return
        
        # Send third legitimate message
        time.sleep(0.1)
        msg3 = client.send_legitimate_message("Third message - seqno continues")
        if not msg3:
            print("[!] Failed to send third message")
            return
        
        print("\n" + "-"*70)
        print("Sequence number progression:")
        print(f"  Message 1: seqno={msg1.seqno}")
        print(f"  Message 2: seqno={msg2.seqno}")
        print(f"  Message 3: seqno={msg3.seqno}")
        print(f"  Current seqno: {client.seqno}")
        print("-"*70)
        
        # Now attempt replay attack - resend message 1
        success = client.replay_message(msg1)
        
        if success:
            print("\n" + "="*70)
            print("REPLAY ATTACK TEST PASSED")
            print("="*70)
            print("The server correctly detected the replayed message")
            print("and rejected it with REPLAY error.")
            print("\nSecurity property verified:")
            print("- Server tracks sequence numbers per session")
            print("- Old messages cannot be replayed")
            print("- Protection against replay attacks is working")
            print("="*70)
        
    except Exception as e:
        print(f"\nTest error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
