"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import os
import socket
import json
import secrets
from dotenv import load_dotenv
from app.common.protocol import (
    HelloMsg, ServerHelloMsg, RegisterMsg, LoginMsg,
    DHClientMsg, DHServerMsg, ChatMsg, ReceiptMsg, ErrorMsg, OkMsg
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import aes, dh, pki, sign
from app.storage.db import register_user, authenticate_user, init_db
from app.storage.transcript import Transcript

load_dotenv()


class SecureChatServer:
    """Secure chat server with PKI, DH, and encrypted messaging."""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.ca_cert = self._load_file(os.getenv("CA_CERT_PATH", "certs/ca-cert.pem"))
        self.server_cert = self._load_file(os.getenv("SERVER_CERT_PATH", "certs/server-cert.pem"))
        self.server_key = self._load_file(os.getenv("SERVER_KEY_PATH", "certs/server-key.pem"))
        
    def _load_file(self, path: str) -> bytes:
        """Load file contents."""
        with open(path, 'rb') as f:
            return f.read()
    
    def handle_client(self, conn: socket.socket, addr: tuple):
        """Handle a single client connection."""
        session_id = secrets.token_hex(8)
        print(f"\n[+] New connection from {addr} (session: {session_id})")
        
        try:
            # Phase 1: Certificate Exchange & Validation
            client_cert, client_nonce = self._certificate_exchange(conn)
            if not client_cert:
                return
            
            # Phase 2: Temporary DH for Registration/Login
            temp_key = self._temp_dh_exchange(conn)
            if not temp_key:
                return
            
            # Phase 3: Registration or Login
            username = self._handle_auth(conn, temp_key)
            if not username:
                return
            
            print(f"[+] User '{username}' authenticated")
            
            # Phase 4: Session DH for Encrypted Chat
            session_key = self._session_dh_exchange(conn)
            if not session_key:
                return
            
            # Phase 5: Encrypted Messaging
            client_fingerprint = pki.get_cert_fingerprint(client_cert)
            transcript = Transcript(session_id, "server")
            
            self._handle_messages(conn, session_key, client_cert, client_fingerprint, transcript)
            
            # Phase 6: Session Teardown & Receipt
            self._send_receipt(conn, transcript)
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            conn.close()
            print(f"[+] Connection closed (session: {session_id})")
    
    def _certificate_exchange(self, conn: socket.socket) -> tuple:
        """
        Exchange and validate certificates.
        Returns: (client_cert_pem, client_nonce) or (None, None) on failure
        """
        # Receive client hello
        data = conn.recv(8192).decode('utf-8')
        hello = HelloMsg.model_validate_json(data)
        
        client_cert = hello.client_cert.encode('utf-8')
        client_nonce = hello.nonce
        
        # Validate client certificate
        is_valid, error_msg = pki.validate_cert(client_cert, self.ca_cert)
        if not is_valid:
            error = ErrorMsg(code="BAD_CERT", message=error_msg)
            conn.sendall(error.model_dump_json().encode('utf-8'))
            return None, None
        
        print(f"[+] Client certificate validated")
        
        # Send server hello
        server_nonce = b64e(secrets.token_bytes(16))
        server_hello = ServerHelloMsg(
            server_cert=self.server_cert.decode('utf-8'),
            nonce=server_nonce
        )
        conn.sendall(server_hello.model_dump_json().encode('utf-8'))
        
        return client_cert, client_nonce
    
    def _temp_dh_exchange(self, conn: socket.socket) -> bytes:
        """
        Perform temporary DH exchange for registration/login encryption.
        Returns: 16-byte AES key or None on failure
        """
        # Receive client DH params
        data = conn.recv(4096).decode('utf-8')
        dh_client = DHClientMsg.model_validate_json(data)
        
        # Server generates DH keypair
        server_private, server_public = dh.full_dh_exchange_client(dh_client.p, dh_client.g)
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(dh_client.A, server_private, dh_client.p)
        aes_key = dh.derive_aes_key(shared_secret)
        
        # Send server DH public key
        dh_server = DHServerMsg(B=server_public)
        conn.sendall(dh_server.model_dump_json().encode('utf-8'))
        
        print(f"[+] Temporary DH key exchange complete")
        return aes_key
    
    def _handle_auth(self, conn: socket.socket, temp_key: bytes) -> str:
        """
        Handle registration or login (encrypted with temp DH key).
        Returns: username on success, None on failure
        """
        # Receive encrypted auth message
        data = conn.recv(4096).decode('utf-8')
        msg_json = json.loads(data)
        
        # Decrypt payload
        ct = b64d(msg_json['encrypted_payload'])
        plaintext = aes.decrypt(temp_key, ct).decode('utf-8')
        auth_data = json.loads(plaintext)
        
        msg_type = auth_data.get('type')
        
        if msg_type == 'register':
            reg = RegisterMsg.model_validate(auth_data)
            success, message = register_user(reg.email, reg.username, reg.pwd)
            
            if success:
                response = OkMsg(message=f"Registration successful: {reg.username}")
                print(f"[+] Registered user: {reg.username}")
            else:
                response = ErrorMsg(code="REG_FAIL", message=message)
                print(f"[!] Registration failed: {message}")
                conn.sendall(response.model_dump_json().encode('utf-8'))
                return None
            
            conn.sendall(response.model_dump_json().encode('utf-8'))
            return reg.username
        
        elif msg_type == 'login':
            login = LoginMsg.model_validate(auth_data)
            success, message, username = authenticate_user(login.email, login.pwd)
            
            if success:
                response = OkMsg(message=f"Login successful: {username}")
                print(f"[+] User logged in: {username}")
            else:
                response = ErrorMsg(code="AUTH_FAIL", message=message)
                print(f"[!] Login failed: {message}")
                conn.sendall(response.model_dump_json().encode('utf-8'))
                return None
            
            conn.sendall(response.model_dump_json().encode('utf-8'))
            return username
        
        else:
            error = ErrorMsg(code="INVALID_MSG", message="Expected register or login")
            conn.sendall(error.model_dump_json().encode('utf-8'))
            return None
    
    def _session_dh_exchange(self, conn: socket.socket) -> bytes:
        """
        Perform session DH exchange for encrypted chat.
        Returns: 16-byte AES key or None on failure
        """
        # Same as temp DH but for session
        return self._temp_dh_exchange(conn)
    
    def _handle_messages(self, conn: socket.socket, session_key: bytes, 
                        client_cert: bytes, client_fingerprint: str, 
                        transcript: Transcript):
        """Handle encrypted chat messages with replay protection."""
        expected_seqno = 1
        
        print(f"[+] Ready for encrypted messages")
        
        while True:
            try:
                data = conn.recv(8192).decode('utf-8')
                if not data:
                    break
                
                # Check for quit command
                if data.strip() == "QUIT":
                    print(f"[+] Client requested session end")
                    break
                
                msg = ChatMsg.model_validate_json(data)
                
                # Replay protection: check sequence number
                if msg.seqno != expected_seqno:
                    error = ErrorMsg(code="REPLAY", message=f"Expected seqno {expected_seqno}, got {msg.seqno}")
                    conn.sendall(error.model_dump_json().encode('utf-8'))
                    continue
                
                # Verify signature
                digest = sha256_hex(f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')).encode('utf-8')
                sig_bytes = b64d(msg.sig)
                
                if not sign.verify_signature(client_cert, digest, sig_bytes):
                    error = ErrorMsg(code="SIG_FAIL", message="Signature verification failed")
                    conn.sendall(error.model_dump_json().encode('utf-8'))
                    continue
                
                # Decrypt message
                ct_bytes = b64d(msg.ct)
                plaintext = aes.decrypt(session_key, ct_bytes).decode('utf-8')
                
                print(f"[<] Message {msg.seqno}: {plaintext}")
                
                # Append to transcript
                transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, client_fingerprint)
                
                # Send ACK
                ack = OkMsg(message=f"ACK {msg.seqno}")
                conn.sendall(ack.model_dump_json().encode('utf-8'))
                
                expected_seqno += 1
                
            except Exception as e:
                print(f"[!] Error processing message: {e}")
                break
    
    def _send_receipt(self, conn: socket.socket, transcript: Transcript):
        """Generate and send signed session receipt."""
        receipt_data = transcript.export_receipt_data()
        transcript_hash = receipt_data['transcript_sha256']
        
        # Sign transcript hash
        digest = transcript_hash.encode('utf-8')
        signature = sign.sign_digest(self.server_key, digest)
        
        receipt = ReceiptMsg(
            peer="server",
            first_seq=receipt_data['first_seq'],
            last_seq=receipt_data['last_seq'],
            transcript_sha256=transcript_hash,
            sig=b64e(signature)
        )
        
        conn.sendall(receipt.model_dump_json().encode('utf-8'))
        print(f"[+] Session receipt sent (hash: {transcript_hash[:16]}...)")
    
    def start(self):
        """Start the server."""
        # Initialize database
        try:
            init_db()
        except Exception as e:
            print(f"[!] Warning: Database init failed: {e}")
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[*] SecureChat Server")
        print(f"[*] Listening on {self.host}:{self.port}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                self.handle_client(conn, addr)
        except KeyboardInterrupt:
            print(f"\n[*] Server shutting down...")
        finally:
            server_socket.close()


def main():
    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", 5000))
    
    server = SecureChatServer(host, port)
    server.start()


if __name__ == "__main__":
    main()
