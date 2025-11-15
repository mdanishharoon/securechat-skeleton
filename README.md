
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

A console-based secure chat system with PKI, demonstrating confidentiality, integrity, authenticity, and non-repudiation (CIANR).

## What This Does

This is a simple client-server chat application that uses real cryptography at the application layer. Everything is encrypted, signed, and verified - no plaintext passwords, no TLS shortcuts. The assignment focuses on understanding how crypto primitives work together to build secure systems.

## Project Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow
│  ├─ server.py              # Server workflow  
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128 encryption (ECB + PKCS#7)
│  │  ├─ dh.py               # Diffie-Hellman key exchange
│  │  ├─ pki.py              # Certificate validation
│  │  └─ sign.py             # RSA signatures
│  ├─ common/
│  │  ├─ protocol.py         # Message models
│  │  └─ utils.py            # Helper functions
│  └─ storage/
│     ├─ db.py               # MySQL with salted passwords
│     └─ transcript.py       # Session transcripts
├─ scripts/
│  ├─ gen_ca.py              # Create root CA
│  └─ gen_cert.py            # Issue certificates
├─ certs/                    # Generated certificates (gitignored)
├─ transcripts/              # Chat logs (gitignored)
└─ .env                      # Config (gitignored)
```

## Setup

### 1. Clone and Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

Copy the example config and fill in your MySQL details:

```bash
cp .env.example .env
```

Edit `.env` with your database credentials. If you're using a remote MySQL host, make sure remote connections are enabled.

### 3. Initialize Database

```bash
python -m app.storage.db --init
```

Test it works:
```bash
python -m app.storage.db --test
```

### 4. Generate Certificates

First create the root CA:
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

Then generate server and client certificates:
```bash
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

You should now have these files in `certs/`:
- `ca-cert.pem` / `ca-key.pem`
- `server-cert.pem` / `server-key.pem`
- `client-cert.pem` / `client-key.pem`

## Running the Chat

### Start the Server

```bash
python -m app.server
```

Server will listen on port 5000 (configurable in `.env`).

### Connect a Client

In another terminal, register a new user:
```bash
python -m app.client --register --email alice@example.com --username alice --password pass123
```

Or login with existing credentials:
```bash
python -m app.client --email alice@example.com --password pass123
```

Once connected, type messages and press enter. Type `quit` to exit.

## How It Works

### Phase 1: Certificate Exchange
Both sides exchange X.509 certificates and validate them against the root CA. Checks include signature verification, expiry dates, and CN/SAN matching.

### Phase 2: Temporary DH Key Exchange
A Diffie-Hellman exchange creates a temporary shared secret, which gets hashed and truncated to a 16-byte AES key. This key is used to encrypt the registration or login payload.

### Phase 3: Registration/Login
Client sends encrypted credentials. Server decrypts, generates a random 16-byte salt per user, computes `SHA256(salt || password)`, and stores it in MySQL. No plaintext passwords anywhere.

### Phase 4: Session DH Key Exchange
Another DH exchange creates a fresh session key for the actual chat messages.

### Phase 5: Encrypted Chat
Messages are encrypted with AES-128, then signed with RSA. Each message has a sequence number to prevent replay attacks. Everything gets logged to an append-only transcript.

### Phase 6: Session Receipt
When the chat ends, the server computes a SHA-256 hash of the entire transcript, signs it with its private key, and sends it to the client. This proves the conversation happened and can't be tampered with later.

## Security Properties

- **Confidentiality**: AES-128 encryption for all messages
- **Integrity**: SHA-256 digests detect tampering
- **Authenticity**: RSA signatures prove who sent what
- **Non-repudiation**: Signed transcripts provide cryptographic proof
- **Replay protection**: Sequence numbers prevent message replay

## Testing

You can check various security properties:

**Test certificate validation:**
Try using a self-signed cert or an expired one - the server should reject it with `BAD_CERT`.

**Test message tampering:**
Modify a ciphertext byte in transit (you'd need to intercept it) - signature verification will fail with `SIG_FAIL`.

**Test replay attacks:**
Try resending an old message with the same sequence number - server rejects it with `REPLAY`.

**Wireshark capture:**
Run `wireshark` or `tcpdump` while chatting. You should only see encrypted payloads on the wire, no plaintext.

## Project Notes

This was built for the Information Security course at FAST-NUCES. The goal was to implement application-layer crypto without using TLS, so we could see how all the pieces fit together.

The implementation uses the `cryptography` library for the heavy lifting (AES, RSA, X.509), but all the protocol logic and key exchange is custom. MySQL stores user credentials with proper salted hashing.

Transcripts are saved locally in the `transcripts/` directory with a format like:
```
seqno | timestamp | ciphertext_b64 | signature_b64 | peer_fingerprint
```

At the end of each session, both sides can verify their transcript hashes match and check the signature on the receipt.

## Common Issues

**Database connection fails:** Make sure your MySQL server allows remote connections if you're using a remote host. Check your `.env` credentials.

**Certificate errors:** Verify all certificates are in the `certs/` directory and properly generated. The CN in the certificate should match what's being validated.

**Import errors:** Activate your virtual environment: `source venv/bin/activate`

## Assignment Requirements

This implementation covers all the assignment requirements:
- PKI with CA-signed certificates
- Salted password hashing in MySQL
- DH key exchange with proper key derivation
- AES-128 encryption with PKCS#7 padding
- RSA signatures for authenticity
- Replay protection with sequence numbers
- Non-repudiation with signed transcripts
- No TLS or SSL (everything is application-layer)

Check `tests/manual/NOTES.md` for testing evidence and Wireshark captures.
