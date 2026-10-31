# this file implements authenticated Diffie-Hellman key exchange using Ed25519 signatures to prevent MITM attacks and tampering

import secrets

from authentication import ProtocolError, is_hex, open_envelope, sign_message, verify_signature
from modular_math import modular_exponentiation
from parameters import find_generator, is_generator, prime_factors, validate_received_modulus

# Step 7: protocol label and fixed schemas.
PROTOCOL = "DH-CLASSROOM-AUTH-v1"
INIT_FIELDS = {"protocol", "message_type", "initiator", "responder", "p", "g", "A", "nonce_A"}
TRANSCRIPT_FIELDS = {"protocol", "initiator", "responder", "p", "g", "A", "B", "nonce_A", "nonce_B"}
SIGNED_TRANSCRIPT_FIELDS = {"message_type", "transcript"}  # used by "response" and "finish"


# Step 7: field validation helpers (no coercion of strings to integers)
def _require_fields(obj, expected):
    if not isinstance(obj, dict) or set(obj) != expected:
        raise ProtocolError("missing or unexpected fields")


def _require_int(value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProtocolError("numeric field must be an integer")


def _require_nonce(value):
    # 32-byte nonce encoded as a 64-character hexadecimal string.
    if not is_hex(value, 64):
        raise ProtocolError("malformed nonce")


def _require_identities(obj, initiator, responder):
    # Fixed ASCII identity labels.
    if obj["initiator"] != initiator or obj["responder"] != responder:
        raise ProtocolError("unexpected identities")


def _require_public_value(value, p):
    # Received public values must satisfy 2 <= public_value <= p - 2.
    if not 2 <= value <= p - 2:
        raise ProtocolError("public value out of range")


def _validate_init(payload, initiator, responder):
    _require_fields(payload, INIT_FIELDS)
    if payload["protocol"] != PROTOCOL or payload["message_type"] != "init":
        raise ProtocolError("wrong protocol or message type")
    _require_identities(payload, initiator, responder)
    for field in ("p", "g", "A"):
        _require_int(payload[field])
    _require_nonce(payload["nonce_A"])


def _validate_signed_transcript(payload, message_type, initiator, responder):
    _require_fields(payload, SIGNED_TRANSCRIPT_FIELDS)
    if payload["message_type"] != message_type:
        raise ProtocolError("wrong message type")
    transcript = payload["transcript"]
    _require_fields(transcript, TRANSCRIPT_FIELDS)
    if transcript["protocol"] != PROTOCOL:
        raise ProtocolError("wrong protocol")
    _require_identities(transcript, initiator, responder)
    for field in ("p", "g", "A", "B"):
        _require_int(transcript[field])
    _require_nonce(transcript["nonce_A"])
    _require_nonce(transcript["nonce_B"])
    return transcript


def new_nonce():
    # One fresh 32-byte nonce per participant, as 64 hex characters.
    return secrets.token_bytes(32).hex()


def generate_parameters(p):
    #Factor p - 1 and find a generator for an accepted prime p 
    return find_generator(p, prime_factors(p - 1))



# Message 1: Alice's signed initiation
def alice_start(alice, p, g, private_key=None):
    # Alice generates a, A, and nonce_A (p and g are passed in).
    a, A = alice.new_dh_keypair(p, g, private_key)
    nonce_A = new_nonce()

    # She signs an initiation payload containing:
    #   protocol, message_type="init", initiator="Alice", responder="Bob", p, g, A, nonce_A
    payload = {
        "protocol": PROTOCOL,
        "message_type": "init",
        "initiator": alice.name,
        "responder": alice.peer,
        "p": p,
        "g": g,
        "A": A,
        "nonce_A": nonce_A,
    }

    # Pending-session record so the response must match this exchange.
    # (The private exponent a stays here and never goes into a message.)
    alice.sessions[nonce_A] = {"p": p, "g": g, "a": a, "A": A}

    # Send the payload and its signature.
    return sign_message(alice.signing_key, payload)


def bob_handle_init(bob, message, private_key=None):
    payload, signature = open_envelope(message)

    # 1. Check format, size limits, protocol, message type, and expected identities.
    _validate_init(payload, initiator=bob.peer, responder=bob.name)

    # 2. Verify the signature using Alice's trusted signing public key.
    verify_signature(bob.trusted_keys, bob.peer, payload, signature)

    # 3. Independently validate p with the library primality check,
    #    factor p - 1, and verify g.
    p, g, A = payload["p"], payload["g"], payload["A"]
    try:
        validate_received_modulus(p, allow_fixture=bob.allow_fixture)
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"received modulus rejected: {exc}") from exc
    if not is_generator(g, p, prime_factors(p - 1)):
        raise ProtocolError("g is not a generator")

    # 4. Check A is in the permitted range.
    _require_public_value(A, p)
    # 5. Abort on any failure. (Every failure above raises ProtocolError.)

    # After accepting the initiation, Bob generates b, B, and nonce_B.
    b, B = bob.new_dh_keypair(p, g, private_key)
    nonce_B = new_nonce()

    # Construct the complete transcript:
    #   protocol, initiator, responder, p, g, A, B, nonce_A, nonce_B
    transcript = {
        "protocol": PROTOCOL,
        "initiator": bob.peer,
        "responder": bob.name,
        "p": p,
        "g": g,
        "A": A,
        "B": B,
        "nonce_A": payload["nonce_A"],
        "nonce_B": nonce_B,
    }
    bob.sessions[nonce_B] = {"transcript": transcript, "b": b}

    # Bob signs a response payload containing:
    #   message_type="response", transcript=<complete transcript>
    return sign_message(bob.signing_key, {"message_type": "response", "transcript": transcript})



# Message 2: Bob's signed response  (Alice processes it, then sends Message 3)
def alice_handle_response(alice, message):
    payload, signature = open_envelope(message)

    # 1. Validate the response schema and expected identities.
    transcript = _validate_signed_transcript(payload, "response", alice.name, alice.peer)

    # The response must belong to an active pending session.
    nonce_A = transcript["nonce_A"]
    session = alice.sessions.get(nonce_A)
    if session is None:
        raise ProtocolError("no pending session matches this response")

    try:
        # 2. Confirm p, g, A, and nonce_A match her pending session exactly.
        if (transcript["p"], transcript["g"], transcript["A"]) != (session["p"], session["g"], session["A"]):
            raise ProtocolError("response does not match pending session")

        # 3. Check B is in the permitted range.
        _require_public_value(transcript["B"], session["p"])

        # 4. Verify Bob's signature using Bob's trusted signing key.
        verify_signature(alice.trusted_keys, alice.peer, payload, signature)
    except ProtocolError:
        # 5. Abort on any failure: clear the session's usable state.
        del alice.sessions[nonce_A]
        raise

    # Step 9: after verifying the peer's signature, calculate S_A = B^a mod p
    shared_secret = modular_exponentiation(transcript["B"], session["a"], session["p"])
    del alice.sessions[nonce_A]
    alice.completed[nonce_A] = shared_secret

    # Message 3: Alice signs message_type="finish", transcript=<the same complete transcript>
    return sign_message(alice.signing_key, {"message_type": "finish", "transcript": transcript})



# Message 3: Alice's signed finish  (Bob processes it)

def bob_handle_finish(bob, message):
    payload, signature = open_envelope(message)
    transcript = _validate_signed_transcript(payload, "finish", bob.peer, bob.name)

    nonce_B = transcript["nonce_B"]
    # Reject already completed sessions.
    if nonce_B in bob.completed:
        raise ProtocolError("session already completed")
    # Reject unexpected sessions.
    session = bob.sessions.get(nonce_B)
    if session is None:
        raise ProtocolError("no pending session matches this finish")

    try:
        # Require exact agreement with his pending transcript (reject mismatched).
        if transcript != session["transcript"]:
            raise ProtocolError("finish does not match pending transcript")
        # Verify Alice's signature.
        verify_signature(bob.trusted_keys, bob.peer, payload, signature)
    except ProtocolError:
        del bob.sessions[nonce_B]
        raise

    # Step 9: Bob only completes after accepting Alice's finish: S_B = A^b mod p
    shared_secret = modular_exponentiation(transcript["A"], session["b"], transcript["p"])
    del bob.sessions[nonce_B]
    bob.completed[nonce_B] = shared_secret
    # Bob marks the transcript authenticated.
    return nonce_B


def run_exchange(alice, bob, p, g, a=None, b=None):
    """Run all three messages. Returns (S_A, S_B) for the local test coordinator only;
    the raw secrets are never sent across the simulated network."""
    init = alice_start(alice, p, g, private_key=a)
    response = bob_handle_init(bob, init, private_key=b)
    finish = alice_handle_response(alice, response)
    nonce_B = bob_handle_finish(bob, finish)
    nonce_A = open_envelope(init)[0]["nonce_A"]
    return alice.completed[nonce_A], bob.completed[nonce_B]
