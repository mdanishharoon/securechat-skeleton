"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
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


class RegisterResponseMsg(BaseModel):
    """Registration response with user certificate and private key."""
    type: Literal["register_response"] = "register_response"
    user_cert: str  # PEM format
    user_key: str  # PEM format (encrypted with temp DH key for transport)
    message: str = "Registration successful"


class LoginMsg(BaseModel):
    """Login message (encrypted with temporary DH key)."""
    type: Literal["login"] = "login"
    email: str
    pwd: str  # base64(sha256(salt||password))
    nonce: str  # base64


class SaltRequestMsg(BaseModel):
    """Request user's salt for login."""
    type: Literal["salt_request"] = "salt_request"
    email: str


class SaltResponseMsg(BaseModel):
    """Response with user's salt."""
    type: Literal["salt_response"] = "salt_response"
    salt: str  # base64


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
