
# SecureChat

A console-based secure chat application demonstrating application-layer cryptography: PKI, Diffie-Hellman key exchange, AES encryption, RSA signatures, and non-repudiation through signed transcripts.

## Architecture

```
app/
├── client.py           # Client implementation
├── server.py           # Server implementation
├── crypto/             # Cryptographic primitives (AES, RSA, DH, PKI)
├── common/             # Protocol definitions and utilities
└── storage/            # Database and transcript management

scripts/
├── gen_ca.py           # Root CA generation
└── gen_cert.py         # Certificate issuance

tests/manual/           # Security testing scripts
```

## Setup

### 1. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Database

Create `.env` file with your MySQL credentials:

```bash
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=securechat
SERVER_HOST=localhost
SERVER_PORT=5000
```

Initialize the database:

```bash
python -m app.storage.db --init
```

### 3. Generate Certificates

Create root CA:
```bash
python scripts/gen_ca.py --name "SecureChat CA"
```

Generate server certificate:
```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

Generate bootstrap client certificate (used during registration):
```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

Required files in `certs/`:
- `ca-cert.pem`, `ca-key.pem`
- `server-cert.pem`, `server-key.pem`
- `client-cert.pem`, `client-key.pem` (bootstrap only)

## Usage

### Start Server

```bash
python -m app.server
```

The server listens on `localhost:5000` by default.

### Register New User

```bash
python -m app.client --register --username alice --email alice@example.com --password alicepass123
```

During registration:
- Server generates a per-user certificate with `CN=username`
- Client saves certificate to `certs/alice-cert.pem` and `certs/alice-key.pem`
- Password is salted and hashed (SHA-256) before storage

### Login

```bash
python -m app.client --username alice --email alice@example.com --password alicepass123
```

During login:
- Client loads user-specific certificate from `certs/alice-cert.pem`
- Server validates certificate CN matches username
- Diffie-Hellman key exchange establishes session key

### Chat Session

After successful login:
- Type messages and press Enter
- Messages are AES-encrypted and RSA-signed
- Type `quit` to end session and receive signed receipt

### Transcript and Receipt

After ending a session:
- Transcript saved to `transcripts/client_SESSION_ID_TIMESTAMP.txt`
- Receipt saved to `receipts/receipt_SESSION_ID.json`
- Both can be verified offline using `tests/manual/verify_nonrepudiation.py`

## Protocol Overview

### 1. Certificate Exchange
- Client and server exchange X.509 certificates
- Both validate against root CA (signature, expiry, CN/SAN)
- Per-user certificates: each user has `CN=username`

### 2. Authentication
- Registration: Client provides salt, server generates per-user certificate
- Login: Client requests salt, hashes password, server validates
- Passwords stored as `SHA256(salt || password)` in MySQL

### 3. Key Exchange
- Diffie-Hellman establishes session key
- Temporary key for auth, separate session key for chat
- Keys derived: `AES-128-key = SHA256(shared_secret)[:16]`

### 4. Encrypted Chat
- Messages encrypted with AES-128
- Each message signed with RSA (SHA-256 digest)
- Sequence numbers prevent replay attacks
- All messages logged to append-only transcript

### 5. Session Receipt
- Server computes SHA-256 hash of transcript
- Server signs hash with private key
- Receipt proves both parties participated in conversation

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-128 encryption |
| Integrity | RSA-SHA256 signatures |
| Authenticity | PKI certificates + signatures |
| Non-repudiation | Signed transcripts + receipts |
| Replay protection | Sequence numbers |
