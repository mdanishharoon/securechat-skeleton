from pydantic import BaseModel
from typing import Literal


class HelloMsg(BaseModel):
    """Client hello with certificate and nonce."""
    type: Literal["hello"] = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64


class ServerHelloMsg(BaseModel):
    """Server hello with certificate and nonce."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64


class RegisterMsg(BaseModel):
    """Registration message (encrypted with temporary DH key)."""
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||password))
    salt: str  # base64


class LoginMsg(BaseModel):
    """Login message (encrypted with temporary DH key)."""
    type: Literal["login"] = "login"
    email: str
    pwd: str  # base64(sha256(salt||password))
    nonce: str  # base64


class DHClientMsg(BaseModel):
    """Client DH parameters and public key."""
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p


class DHServerMsg(BaseModel):
    """Server DH public key."""
    type: Literal["dh_server"] = "dh_server"
    B: int  # g^b mod p


class ChatMsg(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int  # Unix milliseconds
    ct: str  # base64(ciphertext)
    sig: str  # base64(RSA signature)


class ReceiptMsg(BaseModel):
    """Session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64(RSA signature of transcript hash)


class ErrorMsg(BaseModel):
    """Error response."""
    type: Literal["error"] = "error"
    code: str  # BAD_CERT, SIG_FAIL, REPLAY, AUTH_FAIL, etc.
    message: str


class OkMsg(BaseModel):
    """Success response."""
    type: Literal["ok"] = "ok"
    message: str = ""
