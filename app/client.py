"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import os
import socket
import json
import secrets
import hashlib
import sys
from dotenv import load_dotenv
from app.common.protocol import (
    HelloMsg, ServerHelloMsg, RegisterMsg, LoginMsg, RegisterResponseMsg,
    SaltRequestMsg, SaltResponseMsg,
    DHClientMsg, DHServerMsg, ChatMsg, ReceiptMsg, ErrorMsg, OkMsg
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import aes, dh, pki, sign
from app.storage.transcript import Transcript

load_dotenv()


def _ensure_client_cert():
    """Auto-generate client certificate if it doesn't exist."""
    cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client-cert.pem")
    key_path = os.getenv("CLIENT_KEY_PATH", "certs/client-key.pem")
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("[*] Client certificate not found, generating one...")
        
        # Import and call directly instead of subprocess
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        
        from scripts.gen_cert import generate_cert
        
        try:
            generate_cert(
                cn="client",
                output_prefix="certs/client",
                ca_cert_path="certs/ca-cert.pem",
                ca_key_path="certs/ca-key.pem"
            )
            print(f"[+] Client certificate generated successfully")
        except Exception as e:
            print(f"[!] Failed to generate certificate: {e}")
            print(f"[*] Please run manually: python scripts/gen_cert.py --cn client --out certs/client")
            raise


class SecureChatClient:
    """Secure chat client with PKI, DH, and encrypted messaging."""
    
    def __init__(self, host: str, port: int, username: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.ca_cert = self._load_file(os.getenv("CA_CERT_PATH", "certs/ca-cert.pem"))
        
        # Load user-specific certificate if username provided (for login)
        if username:
            cert_path = f"certs/{username}-cert.pem"
            key_path = f"certs/{username}-key.pem"
            
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                raise FileNotFoundError(
                    f"Certificate not found for user '{username}'. "
                    f"Please register first with: python -m app.client --register --username {username}"
                )
            
            self.client_cert = self._load_file(cert_path)
            self.client_key = self._load_file(key_path)
            print(f"[*] Loaded certificate for user: {username}")
        else:
            # For registration, use temporary bootstrap cert
            # Generate temporary cert if doesn't exist
            _ensure_client_cert()
            self.client_cert = self._load_file("certs/client-cert.pem")
            self.client_key = self._load_file("certs/client-key.pem")
            print(f"[*] Using bootstrap certificate for registration")
        
        self.sock = None
        self.session_key = None
        self.server_cert = None
        self.transcript = None
        self.seqno = 1
        
    def _load_file(self, path: str) -> bytes:
        """Load file contents."""
        with open(path, 'rb') as f:
            return f.read()
    
    def connect(self):
        """Connect to server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[+] Connected to {self.host}:{self.port}")
    
    def _certificate_exchange(self):
        """Exchange and validate certificates."""
        # Send client hello
        client_nonce = b64e(secrets.token_bytes(16))
        hello = HelloMsg(
            client_cert=self.client_cert.decode('utf-8'),
            nonce=client_nonce
        )
        self.sock.sendall(hello.model_dump_json().encode('utf-8'))
        
        # Receive server hello
        data = self.sock.recv(8192).decode('utf-8')
        
        # Check if it's an error
        try:
            error = ErrorMsg.model_validate_json(data)
            print(f"[!] Server error: {error.message}")
            return False
        except:
            pass
        
        server_hello = ServerHelloMsg.model_validate_json(data)
        self.server_cert = server_hello.server_cert.encode('utf-8')
        
        # Validate server certificate
        is_valid, error_msg = pki.validate_cert(self.server_cert, self.ca_cert)
        if not is_valid:
            print(f"[!] Server certificate validation failed: {error_msg}")
            return False
        
        print(f"[+] Server certificate validated")
        return True
    
    def _temp_dh_exchange(self) -> bytes:
        """
        Perform temporary DH exchange for registration/login encryption.
        Returns: 16-byte AES key
        """
        # Generate DH parameters
        p, g = dh.generate_dh_params()
        client_private, client_public = dh.full_dh_exchange_client(p, g)
        
        # Send DH params and public key
        dh_client = DHClientMsg(g=g, p=p, A=client_public)
        self.sock.sendall(dh_client.model_dump_json().encode('utf-8'))
        
        # Receive server DH public key
        data = self.sock.recv(4096).decode('utf-8')
        dh_server = DHServerMsg.model_validate_json(data)
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(dh_server.B, client_private, p)
        aes_key = dh.derive_aes_key(shared_secret)
        
        print(f"[+] Temporary DH key exchange complete")
        return aes_key
    
    def register(self, email: str, username: str, password: str):
        """Register a new user and receive user-specific certificate."""
        print(f"[*] Starting registration for {username}...")
        temp_key = self._temp_dh_exchange()
        print(f"[*] DH exchange complete, encrypting registration data...")
        
        # Generate salt and hash password
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
        
        # Create registration message
        reg = RegisterMsg(
            email=email,
            username=username,
            pwd=b64e(pwd_hash),
            salt=b64e(salt)
        )
        
        # Encrypt with temp key
        plaintext = reg.model_dump_json().encode('utf-8')
        ct = aes.encrypt(temp_key, plaintext)
        
        # Send encrypted payload
        payload = {"encrypted_payload": b64e(ct)}
        self.sock.sendall(json.dumps(payload).encode('utf-8'))
        print(f"[*] Registration data sent, waiting for response...")
        
        # Receive encrypted response
        data = self.sock.recv(8192).decode('utf-8')
        msg_json = json.loads(data)
        
        # Check if it's an error
        if msg_json.get('type') == 'error':
            error = ErrorMsg.model_validate(msg_json)
            print(f"[!] Registration failed: {error.message}")
            return False
        
        # Decrypt response
        ct = b64d(msg_json['encrypted_payload'])
        plaintext = aes.decrypt(temp_key, ct).decode('utf-8')
        response = RegisterResponseMsg.model_validate_json(plaintext)
        
        # Save user certificate and key
        import os
        os.makedirs("certs", exist_ok=True)
        
        cert_path = f"certs/{username}-cert.pem"
        key_path = f"certs/{username}-key.pem"
        
        with open(cert_path, "w") as f:
            f.write(response.user_cert)
        with open(key_path, "w") as f:
            f.write(response.user_key)
        
        print(f"[+] {response.message}")
        print(f"[+] Certificate saved to {cert_path}")
        print(f"[+] Private key saved to {key_path}")
        print(f"[!] Keep your private key secure!")
        
        return True
    
    def login(self, email: str, password: str):
        """Login with existing credentials."""
        # First, request the user's salt
        salt_request = SaltRequestMsg(email=email)
        self.sock.sendall(salt_request.model_dump_json().encode('utf-8'))
        
        # Receive salt response
        data = self.sock.recv(4096).decode('utf-8')
        
        try:
            error = ErrorMsg.model_validate_json(data)
            print(f"[!] Failed to get salt: {error.message}")
            return False
        except:
            pass
        
        salt_response = SaltResponseMsg.model_validate_json(data)
        salt = b64d(salt_response.salt)
        
        print(f"[DEBUG] Received salt: {salt.hex()}")
        
        # Now do temp DH exchange for encrypted login
        temp_key = self._temp_dh_exchange()
        
        # Hash password with salt
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).digest()
        
        print(f"[DEBUG] Computed hash: {pwd_hash.hex()}")
        
        # Create login message
        login_msg = LoginMsg(
            email=email,
            pwd=b64e(pwd_hash),
            nonce=b64e(secrets.token_bytes(16))
        )
        
        # Encrypt with temp key
        plaintext = login_msg.model_dump_json().encode('utf-8')
        ct = aes.encrypt(temp_key, plaintext)
        
        # Send encrypted payload
        payload = {"encrypted_payload": b64e(ct)}
        self.sock.sendall(json.dumps(payload).encode('utf-8'))
        
        # Receive response
        data = self.sock.recv(4096).decode('utf-8')
        
        try:
            error = ErrorMsg.model_validate_json(data)
            print(f"[!] Login failed: {error.message}")
            return False
        except:
            pass
        
        ok = OkMsg.model_validate_json(data)
        print(f"[+] {ok.message}")
        return True
    
    def _session_dh_exchange(self) -> bytes:
        """
        Perform session DH exchange for encrypted chat.
        Returns: 16-byte AES key
        """
        return self._temp_dh_exchange()
    
    def start_chat_session(self, session_id: str):
        """Initialize chat session with session key and transcript."""
        self.session_key = self._session_dh_exchange()
        self.transcript = Transcript(session_id, "client")
        print(f"[+] Chat session ready (session: {session_id})")
        print(f"[*] Type your messages (or 'quit' to exit)\n")
    
    def send_message(self, plaintext: str):
        """Send encrypted and signed message."""
        if not self.session_key or not self.transcript:
            print(f"[!] No active session. Call start_chat_session() first.")
            return False
        
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
        
        # Send message
        self.sock.sendall(msg.model_dump_json().encode('utf-8'))
        
        # Append to transcript
        server_fingerprint = pki.get_cert_fingerprint(self.server_cert)
        self.transcript.append(self.seqno, ts, ct_b64, msg.sig, server_fingerprint)
        
        # Receive ACK
        data = self.sock.recv(4096).decode('utf-8')
        
        try:
            error = ErrorMsg.model_validate_json(data)
            print(f"[!] Server error: {error.message}")
            return False
        except:
            pass
        
        ok = OkMsg.model_validate_json(data)
        print(f"[>] Sent (seqno {self.seqno}): {plaintext}")
        
        self.seqno += 1
        return True
    
    def receive_receipt(self):
        """Receive and verify session receipt from server."""
        # Send quit signal
        self.sock.sendall(b"QUIT")
        
        # Receive receipt
        data = self.sock.recv(8192).decode('utf-8')
        receipt = ReceiptMsg.model_validate_json(data)
        
        print(f"\n[+] Session receipt received:")
        print(f"    Peer: {receipt.peer}")
        print(f"    Messages: {receipt.first_seq} - {receipt.last_seq}")
        print(f"    Transcript hash: {receipt.transcript_sha256}")
        
        # Verify signature
        digest = receipt.transcript_sha256.encode('utf-8')
        sig_bytes = b64d(receipt.sig)
        
        if sign.verify_signature(self.server_cert, digest, sig_bytes):
            print(f"[+] Receipt signature verified")
        else:
            print(f"[!] Receipt signature verification FAILED")
        
        # Verify our transcript hash matches
        our_hash = self.transcript.compute_transcript_hash()
        if our_hash == receipt.transcript_sha256:
            print(f"[+] Transcript hash matches")
        else:
            print(f"[!] Transcript hash MISMATCH")
            print(f"    Ours:   {our_hash}")
            print(f"    Theirs: {receipt.transcript_sha256}")
    
    def close(self):
        """Close connection."""
        if self.sock:
            self.sock.close()
            print(f"[+] Connection closed")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Client")
    parser.add_argument("--host", default=os.getenv("SERVER_HOST", "localhost"), help="Server host")
    parser.add_argument("--port", type=int, default=int(os.getenv("SERVER_PORT", 5000)), help="Server port")
    parser.add_argument("--register", action="store_true", help="Register new user")
    parser.add_argument("--email", help="User email")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password")
    
    args = parser.parse_args()
    
    # For login, username is required to load the correct certificate
    if not args.register and not args.username:
        print(f"[!] Login requires --username to load your certificate")
        print(f"[*] Example: python -m app.client --username alice --email alice@example.com --password pass123")
        return
    
    # Create client with username (None for registration, specific user for login)
    username_for_cert = args.username if not args.register else None
    client = SecureChatClient(args.host, args.port, username=username_for_cert)
    
    try:
        # Connect and exchange certificates
        client.connect()
        
        if not client._certificate_exchange():
            print(f"[!] Certificate exchange failed")
            return
        
        # Register or Login
        if args.register:
            if not args.email or not args.username or not args.password:
                print(f"[!] Registration requires --email, --username, and --password")
                return
            
            if not client.register(args.email, args.username, args.password):
                return
            
            print(f"\n[+] Registration complete! You can now login with:")
            print(f"    python -m app.client --username {args.username} --email {args.email} --password YOUR_PASSWORD")
            return
        else:
            if not args.email or not args.password:
                print(f"[!] Login requires --email and --password")
                return
            
            if not client.login(args.email, args.password):
                return
        
        # Start chat session
        session_id = secrets.token_hex(8)
        client.start_chat_session(session_id)
        
        # Interactive chat loop
        while True:
            try:
                message = input("You: ").strip()
                
                if message.lower() in ['quit', 'exit', 'q']:
                    break
                
                if message:
                    client.send_message(message)
                    
            except KeyboardInterrupt:
                print()
                break
        
        # Receive session receipt
        client.receive_receipt()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    main()
