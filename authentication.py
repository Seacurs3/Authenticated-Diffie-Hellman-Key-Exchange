# This file contains the authentication-related functions for the authenticated Diffie-Hellman key exchange protocol.
import json

from cryptography.exceptions import InvalidSignature

# Setting max message size.
MAX_MESSAGE_BYTES = 4096
HEX_DIGITS = "0123456789abcdef"


class ProtocolError(Exception):
     # Raised on any failure; the caller aborts the exchange.
    pass



# Step 6: trusted setup
def trusted_setup(alice, bob):
    # Alice's trusted keys: "Bob"   -> Bob's authentic signing public key
    # Bob's trusted keys:   "Alice" -> Alice's authentic signing public key
    # Eve controls network messages but cannot modify this configuration.
    alice.trusted_keys = {bob.name: bob.verification_key}
    bob.trusted_keys = {alice.name: alice.verification_key}



# Step 7: deterministic JSON encoding

def encode(message):
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject_duplicate_keys(pairs):
    # Reject duplicate JSON keys.
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ProtocolError("duplicate JSON key")
        obj[key] = value
    return obj


def decode(data):
    if not isinstance(data, bytes):
        raise ProtocolError("message must be bytes")
    # Enforce the size limit before parsing.
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message too large")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("malformed JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("message must be a JSON object")
    return obj


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in HEX_DIGITS for c in value)



# Signing and verification (Ed25519 from the cryptography library)

def sign_message(signing_key, payload):
    # signature = signing_key.sign(message_bytes)
    signature = signing_key.sign(encode(payload))
    # send the payload and its signature; the signature is outside the signed payload.
    return encode({"payload": payload, "signature": signature.hex()})


def open_envelope(data):
    envelope = decode(data)
    # Reject unexpected fields and wrong types.
    if set(envelope) != {"payload", "signature"}:
        raise ProtocolError("unexpected envelope fields")
    if not isinstance(envelope["payload"], dict):
        raise ProtocolError("payload must be an object")
    # Ed25519 signatures are 64 bytes = 128 hex characters.
    if not is_hex(envelope["signature"], 128):
        raise ProtocolError("malformed signature")
    return envelope["payload"], bytes.fromhex(envelope["signature"])


def verify_signature(trusted_keys, signer, payload, signature):
    # Always verify against the already configured trusted key for that label,
    # never a key supplied inside a message.
    verification_key = trusted_keys.get(signer)
    if verification_key is None:
        raise ProtocolError(f"no trusted key for {signer!r}")
    try:
        # A successful verify call returns normally.
        verification_key.verify(signature, encode(payload))
    except InvalidSignature as exc:
        # A bad signature raises InvalidSignature: abort the exchange.
        raise ProtocolError(f"{signer} signature: INVALID") from exc
