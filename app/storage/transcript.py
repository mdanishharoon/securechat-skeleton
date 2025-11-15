"""Append-only transcript + TranscriptHash helpers."""
import os
import hashlib
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Transcript:
    """
    Append-only transcript for non-repudiation.
    Format: seqno | ts | ct | sig | peer-cert-fingerprint
    """
    
    def __init__(self, session_id: str, peer_role: str = "unknown"):
        """
        Initialize transcript.
        
        Args:
            session_id: Unique session identifier
            peer_role: "client" or "server"
        """
        self.session_id = session_id
        self.peer_role = peer_role
        self.messages = []
        
        # Get transcript directory from env
        transcript_dir = os.getenv("TRANSCRIPT_DIR", "transcripts")
        Path(transcript_dir).mkdir(parents=True, exist_ok=True)
        
        # Create unique transcript filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filepath = Path(transcript_dir) / f"{peer_role}_{session_id}_{timestamp}.txt"
        
        # Create file with header
        with open(self.filepath, 'w') as f:
            f.write(f"# SecureChat Transcript\n")
            f.write(f"# Session ID: {session_id}\n")
            f.write(f"# Peer Role: {peer_role}\n")
            f.write(f"# Created: {datetime.now().isoformat()}\n")
            f.write(f"# Format: seqno | ts | ct_base64 | sig_base64 | peer_cert_fingerprint\n")
            f.write("#" + "-" * 78 + "\n")
    
    def append(self, seqno: int, ts: int, ct: str, sig: str, peer_fingerprint: str):
        """
        Append a message to the transcript.
        
        Args:
            seqno: Sequence number
            ts: Timestamp (Unix milliseconds)
            ct: Ciphertext (base64)
            sig: Signature (base64)
            peer_fingerprint: SHA-256 fingerprint of peer certificate (hex)
        """
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}\n"
        
        # Append to file
        with open(self.filepath, 'a') as f:
            f.write(line)
        
        # Keep in memory for hash computation
        self.messages.append({
            'seqno': seqno,
            'ts': ts,
            'ct': ct,
            'sig': sig,
            'fingerprint': peer_fingerprint
        })
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of all transcript messages.
        
        Returns:
            Hex string of transcript hash
        """
        if not self.messages:
            return hashlib.sha256(b"").hexdigest()
        
        # Concatenate all message lines (without header)
        transcript_data = ""
        for msg in self.messages:
            line = f"{msg['seqno']}|{msg['ts']}|{msg['ct']}|{msg['sig']}|{msg['fingerprint']}\n"
            transcript_data += line
        
        return hashlib.sha256(transcript_data.encode('utf-8')).hexdigest()
    
    def get_message_count(self) -> int:
        """Get total number of messages in transcript."""
        return len(self.messages)
    
    def get_first_seqno(self) -> int:
        """Get first sequence number in transcript."""
        return self.messages[0]['seqno'] if self.messages else 0
    
    def get_last_seqno(self) -> int:
        """Get last sequence number in transcript."""
        return self.messages[-1]['seqno'] if self.messages else 0
    
    def export_receipt_data(self) -> dict:
        """
        Export data for creating a session receipt.
        
        Returns:
            Dictionary with receipt data
        """
        return {
            'session_id': self.session_id,
            'peer_role': self.peer_role,
            'first_seq': self.get_first_seqno(),
            'last_seq': self.get_last_seqno(),
            'message_count': self.get_message_count(),
            'transcript_sha256': self.compute_transcript_hash(),
            'filepath': str(self.filepath)
        }


def load_transcript(filepath: str) -> Transcript:
    """
    Load a transcript from file.
    
    Args:
        filepath: Path to transcript file
        
    Returns:
        Transcript object with messages loaded
    """
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Parse header for session_id and peer_role
    session_id = "unknown"
    peer_role = "unknown"
    
    for line in lines:
        if line.startswith("# Session ID:"):
            session_id = line.split(":", 1)[1].strip()
        elif line.startswith("# Peer Role:"):
            peer_role = line.split(":", 1)[1].strip()
    
    # Create transcript object (will create a new file, but we'll overwrite the filepath)
    transcript = Transcript(session_id, peer_role)
    transcript.filepath = Path(filepath)
    transcript.messages = []
    
    # Parse message lines
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        
        parts = line.strip().split("|")
        if len(parts) == 5:
            transcript.messages.append({
                'seqno': int(parts[0]),
                'ts': int(parts[1]),
                'ct': parts[2],
                'sig': parts[3],
                'fingerprint': parts[4]
            })
    
    return transcript


def verify_transcript_hash(filepath: str, expected_hash: str) -> bool:
    """
    Verify that a transcript's hash matches the expected value.
    
    Args:
        filepath: Path to transcript file
        expected_hash: Expected SHA-256 hash (hex)
        
    Returns:
        True if hash matches, False otherwise
    """
    transcript = load_transcript(filepath)
    computed_hash = transcript.compute_transcript_hash()
    return computed_hash == expected_hash


if __name__ == "__main__":
    # Test transcript functionality
    print("[*] Testing transcript functionality...")
    
    # Create a test transcript
    transcript = Transcript("test-session-123", "server")
    print(f"[+] Created transcript: {transcript.filepath}")
    
    # Add some test messages
    transcript.append(1, 1700000001000, "dGVzdF9jdA==", "dGVzdF9zaWc=", "abc123fingerprint")
    transcript.append(2, 1700000002000, "dGVzdF9jdDI=", "dGVzdF9zaWcy", "abc123fingerprint")
    transcript.append(3, 1700000003000, "dGVzdF9jdDM=", "dGVzdF9zaWcz", "abc123fingerprint")
    print(f"[+] Added 3 messages")
    
    # Compute transcript hash
    hash_value = transcript.compute_transcript_hash()
    print(f"[+] Transcript hash: {hash_value}")
    
    # Export receipt data
    receipt_data = transcript.export_receipt_data()
    print(f"[+] Receipt data:")
    for key, value in receipt_data.items():
        print(f"    {key}: {value}")
    
    # Test loading and verification
    print(f"\n[*] Testing transcript loading and verification...")
    loaded = load_transcript(str(transcript.filepath))
    loaded_hash = loaded.compute_transcript_hash()
    print(f"[+] Loaded transcript hash: {loaded_hash}")
    print(f"[+] Hash match: {loaded_hash == hash_value}")
    
    print(f"\n[+] Transcript test complete!")
