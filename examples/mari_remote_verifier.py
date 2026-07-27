"""
Related-work Remote Verifier.

Generates fresh nonces on request and verifies attestation evidence from the
edge via MQTT. Counterpart to examples/mari_edge.py (EDHOC Responder, node =
Initiator design).

Protocol:
  - /maura/nonce_request : edge -> verifier, CBOR {node_id} -- request a fresh nonce
  - /maura/nonce_response: verifier -> edge, CBOR {node_id, nonce} -- the generated nonce
  - /maura/evidence      : edge -> verifier, CBOR {node_id, evidence, binder} -- verify token
  - /maura/attest_result : verifier -> edge, CBOR {node_id, result} -- send back result

The verifier -- not the edge -- generates the nonce and keeps the node_id -> nonce
mapping itself, so freshness is anchored to the verifier's own RNG rather than
trusting a value the edge picked.

Verification:
  1. Look up stored nonce for node_id.
  2. Decode COSE_Sign1 token from evidence bytes.
  3. Verify nonce in EAT payload matches stored nonce.
  4. Reconstruct Sig_Structure with attestation_binder as external_aad.
  5. Verify Ed25519 signature.
"""

import os
import threading
import time
from typing import Optional

import cbor2
import click
import paho.mqtt.client as mqtt_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# MQTT topics (must match examples/mari_edge.py)
TOPIC_NONCE_REQUEST  = "/maura/nonce_request"
TOPIC_NONCE_RESPONSE = "/maura/nonce_response"
TOPIC_EVIDENCE       = "/maura/evidence"
TOPIC_RESULT         = "/maura/attest_result"

# Ed25519 public key — matches _public_key[] in mari/app/03app_node/attestation.c
ATTESTATION_PUBLIC_KEY = bytes([
    0xb2, 0x4f, 0x6d, 0x4e, 0x5f, 0x81, 0x47, 0xaf, 0x1d, 0x1c, 0xd8, 0xc2, 0x6e, 0x1a, 0x51, 0x0b,
    0x7a, 0x0f, 0x7f, 0x0a, 0x7b, 0xcc, 0x60, 0x68, 0x89, 0x55, 0xd3, 0x27, 0xb9, 0x9c, 0x64, 0x75,
])

# Fixed expected firmware hash (matches _test_hash[] in mari/app/03app_node/attestation.c)
EXPECTED_HASH = bytes([
    0xDE, 0x6C, 0xD0, 0x5D, 0x50, 0x77, 0x86, 0x48,
    0xBD, 0xB0, 0x7B, 0x4D, 0x1C, 0x6D, 0xB8, 0x1E,
    0x0C, 0x2D, 0xF4, 0x53, 0x3A, 0x32, 0xE5, 0x15,
    0xE5, 0x33, 0xA2, 0x6E, 0x21, 0x72, 0x87, 0x3B,
])

# ========================= COSE_Sign1 decoder ================================

def _decode_cose_sign1(token: bytes):
    """
    Decode a COSE_Sign1 token (tag 18 / 0xd2 0x84 header).
    Returns (protected_header_bytes, unprotected, payload_bytes, signature_bytes).
    """
    decoded = cbor2.loads(token)
    # cbor2 may decode as CBORTag(18, [...]) or directly as a list
    if hasattr(decoded, "value"):
        parts = decoded.value
    else:
        parts = decoded
    if not isinstance(parts, (list, tuple)) or len(parts) != 4:
        raise ValueError(f"Expected COSE_Sign1 array(4), got {type(parts)}")
    protected_bstr, unprotected, payload_bstr, sig_bstr = parts
    return bytes(protected_bstr), unprotected, bytes(payload_bstr), bytes(sig_bstr)


def _build_sig_structure(protected: bytes, external_aad: bytes, payload: bytes) -> bytes:
    """Build the Sig_Structure for Ed25519 verification."""
    return cbor2.dumps(["Signature1", protected, external_aad, payload])


def verify_cose_sign1(token: bytes, binder: bytes) -> tuple[bool, Optional[bytes]]:
    """
    Verify a COSE_Sign1 token.

    Returns (ok, nonce_from_payload) where nonce_from_payload is the nonce
    extracted from the EAT claim map (used for freshness check).
    """
    try:
        protected, _unprotected, payload_bstr, signature = _decode_cose_sign1(token)
    except Exception as e:
        print(f"[VERIFIER] COSE decode failed: {e}")
        return False, None

    # Build Sig_Structure with binder as external_aad
    sig_structure = _build_sig_structure(protected, binder, payload_bstr)

    # Verify Ed25519 signature
    pub_key = Ed25519PublicKey.from_public_bytes(ATTESTATION_PUBLIC_KEY)
    try:
        pub_key.verify(signature, sig_structure)
    except InvalidSignature:
        print("[VERIFIER] Signature INVALID")
        return False, None
    except Exception as e:
        print(f"[VERIFIER] Signature verification error: {e}")
        return False, None

    # Decode EAT payload and extract nonce (claim 10)
    try:
        eat = cbor2.loads(payload_bstr)
        nonce_in_token = bytes(eat.get(10, b""))  # claim 10 = nonce
    except Exception as e:
        print(f"[VERIFIER] EAT decode failed: {e}")
        return True, None  # signature valid but can't extract nonce

    return True, nonce_in_token


# ========================= Verifier state ====================================

class MauraVerifier:
    def __init__(self):
        self._nonce_store: dict[int, bytes] = {}
        self._lock = threading.Lock()
        self.stats = {"received": 0, "succeeded": 0, "failed": 0}

    def register_nonce(self, node_id: int, nonce: bytes) -> None:
        with self._lock:
            self._nonce_store[node_id] = nonce

    def generate_nonce(self, node_id: int) -> bytes:
        """Generate a fresh nonce for node_id, store it, and return it for
        publishing back to the edge."""
        nonce = os.urandom(8)
        self.register_nonce(node_id, nonce)
        return nonce

    def verify_evidence(self, node_id: int, evidence: bytes, binder: bytes) -> bool:
        with self._lock:
            expected_nonce = self._nonce_store.get(node_id)

        if expected_nonce is None:
            print(f"[VERIFIER] No nonce for 0x{node_id:016X} — rejecting")
            self.stats["failed"] += 1
            return False

        self.stats["received"] += 1

        ok, nonce_from_token = verify_cose_sign1(evidence, binder)
        if not ok:
            print(f"[VERIFIER] Signature verification FAILED for 0x{node_id:016X}")
            self.stats["failed"] += 1
            return False

        # Freshness: nonce in token must match the one we announced
        if nonce_from_token is not None and nonce_from_token != expected_nonce:
            print(f"[VERIFIER] Nonce mismatch for 0x{node_id:016X}: "
                  f"expected={expected_nonce.hex()} got={nonce_from_token.hex()}")
            self.stats["failed"] += 1
            return False

        print(f"[VERIFIER] Attestation PASSED for 0x{node_id:016X}")
        self.stats["succeeded"] += 1

        # Consume nonce (one-time use)
        with self._lock:
            self._nonce_store.pop(node_id, None)

        return True


# ========================= MQTT glue =========================================

def _parse_mqtt_url(url: str) -> tuple[str, int, bool]:
    """Parse mqtt://host:port or mqtts://host:port -> (host, port, tls)."""
    if url.startswith("mqtts://"):
        rest, tls = url[len("mqtts://"):], True
    else:
        rest, tls = url[len("mqtt://"):], False
    host, _, port_str = rest.partition(":")
    port = int(port_str) if port_str else (8883 if tls else 1883)
    return host, port, tls


@click.command()
@click.option("--mqtt-url", "-m", type=str, default="mqtt://localhost:1883",
              show_default=True, help="MQTT broker URL")
def main(mqtt_url: str):
    """Related-work Remote Verifier: nonce store + COSE_Sign1 verification."""

    verifier   = MauraVerifier()
    host, port, tls = _parse_mqtt_url(mqtt_url)

    client = mqtt_client.Client()

    def on_connect(c, userdata, flags, rc):
        if rc == 0:
            print(f"[VERIFIER] Connected to MQTT broker {host}:{port}")
            c.subscribe(TOPIC_NONCE_REQUEST)
            c.subscribe(TOPIC_EVIDENCE)
            print(f"[VERIFIER] Subscribed to {TOPIC_NONCE_REQUEST} and {TOPIC_EVIDENCE}")
        else:
            print(f"[VERIFIER] MQTT connect failed: rc={rc}")

    def on_message(c, userdata, msg):
        try:
            payload = cbor2.loads(msg.payload)
        except Exception as e:
            print(f"[VERIFIER] CBOR decode failed on {msg.topic}: {e}")
            return

        if msg.topic == TOPIC_NONCE_REQUEST:
            node_id = payload.get("node_id")
            if node_id is None:
                print("[VERIFIER] Incomplete nonce_request payload")
                return
            node_id = int(node_id)
            nonce = verifier.generate_nonce(node_id)
            c.publish(TOPIC_NONCE_RESPONSE, cbor2.dumps({"node_id": node_id, "nonce": nonce}))

        elif msg.topic == TOPIC_EVIDENCE:
            node_id  = payload.get("node_id")
            evidence = payload.get("evidence")
            binder   = payload.get("binder")
            if node_id is None or evidence is None or binder is None:
                print("[VERIFIER] Incomplete evidence payload")
                return
            node_id = int(node_id)
            evidence = bytes(evidence)
            binder   = bytes(binder)
            result  = verifier.verify_evidence(node_id, evidence, binder)

            # Publish result back to edge
            result_msg = cbor2.dumps({"node_id": node_id, "result": result})
            c.publish(TOPIC_RESULT, result_msg)

            s = verifier.stats
            print(f"[VERIFIER] Stats: rcv={s['received']} ok={s['succeeded']} fail={s['failed']}")

    client.on_connect = on_connect
    client.on_message = on_message

    if tls:
        client.tls_set()

    client.connect(host, port, keepalive=60)
    client.loop_start()

    print("[VERIFIER] Started. Waiting for attestations ...")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        s = verifier.stats
        print(f"\n[VERIFIER] Shutdown. received={s['received']} ok={s['succeeded']} fail={s['failed']}")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
