#!/usr/bin/env python3
"""
Helper script to conduct a chat session and save the receipt for offline verification.

Usage:
1. Run this script to connect and send a few messages
2. Type 'quit' to end the session
3. The receipt will be saved to a JSON file
4. Use verify_nonrepudiation.py to verify the transcript and receipt
"""
import sys
import os
import json
import secrets

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.client import SecureChatClient


def save_receipt_to_file(receipt_msg, session_id: str):
    """Save receipt to JSON file."""
    receipt_dir = "receipts"
    os.makedirs(receipt_dir, exist_ok=True)
    
    receipt_path = os.path.join(receipt_dir, f"receipt_{session_id}.json")
    
    receipt_data = {
        'type': receipt_msg.type,
        'peer': receipt_msg.peer,
        'first_seq': receipt_msg.first_seq,
        'last_seq': receipt_msg.last_seq,
        'transcript_sha256': receipt_msg.transcript_sha256,
        'sig': receipt_msg.sig
    }
    
    with open(receipt_path, 'w') as f:
        json.dump(receipt_data, f, indent=2)
    
    print(f"[+] Receipt saved to: {receipt_path}")
    return receipt_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Chat session with receipt export")
    parser.add_argument("--username", required=True, help="Your username (e.g., alice)")
    parser.add_argument("--email", required=True, help="Your email")
    parser.add_argument("--password", required=True, help="Your password")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("Chat Session with Receipt Export")
    print("="*70)
    print(f"\nConnecting as {args.username}...")
    print("Send a few messages, then type 'quit' to end the session.")
    print("The receipt will be saved for offline verification.\n")
    
    # Create client
    client = SecureChatClient(args.host, args.port, username=args.username)
    
    try:
        # Connect
        client.connect()
        
        if not client._certificate_exchange():
            print("[!] Certificate exchange failed")
            return
        
        # Login
        if not client.login(args.email, args.password):
            print("[!] Login failed")
            return
        
        # Start session
        session_id = secrets.token_hex(8)
        client.start_chat_session(session_id)
        
        print(f"[+] Session ID: {session_id}")
        print(f"[+] Transcript will be saved to: {client.transcript.filepath}")
        print()
        
        # Chat loop
        while True:
            try:
                message = input("> ")
                
                if message.lower() == 'quit':
                    print("\n[*] Ending session...")
                    break
                
                if message.strip():
                    client.send_message(message)
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted. Ending session...")
                break
        
        # Receive receipt
        print("\n[*] Requesting receipt from server...")
        client.sock.sendall(b"QUIT")
        
        # Receive receipt
        from app.common.protocol import ReceiptMsg
        data = client.sock.recv(8192).decode('utf-8')
        receipt = ReceiptMsg.model_validate_json(data)
        
        print(f"\n[+] Session receipt received:")
        print(f"    Peer: {receipt.peer}")
        print(f"    Messages: {receipt.first_seq} - {receipt.last_seq}")
        print(f"    Transcript hash: {receipt.transcript_sha256}")
        
        # Save receipt to file
        receipt_path = save_receipt_to_file(receipt, session_id)
        transcript_path = str(client.transcript.filepath)
        
        print("\n" + "="*70)
        print("Session complete! Files saved:")
        print("="*70)
        print(f"Transcript: {transcript_path}")
        print(f"Receipt:    {receipt_path}")
        print("\nTo verify offline:")
        print(f"  python tests/manual/verify_nonrepudiation.py \\")
        print(f"    --transcript {transcript_path} \\")
        print(f"    --receipt {receipt_path} \\")
        print(f"    --sender-cert certs/{args.username}-cert.pem \\")
        print(f"    --server-cert certs/server-cert.pem")
        print("\nTo test tamper detection:")
        print(f"  python tests/manual/test_tamper_detection.py \\")
        print(f"    --transcript {transcript_path} \\")
        print(f"    --receipt {receipt_path} \\")
        print(f"    --sender-cert certs/{args.username}-cert.pem \\")
        print(f"    --server-cert certs/server-cert.pem")
        print("="*70)
        
        client.close()
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
