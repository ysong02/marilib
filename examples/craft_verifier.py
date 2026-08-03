"""CRAFT+SEDA Remote Verifier: generates SEDA challenges and verifies attest HMAC tags from the edge via MQTT (counterpart to mari_edge.py).

Protocol:
  - /craft/challenge_request : edge -> verifier, CBOR {node_id}
  - /craft/challenge_response: verifier -> edge, CBOR {node_id, challenge}
  - /craft/attest            : edge -> verifier, CBOR {node_id, tag}
  - /craft/attest_result     : verifier -> edge, CBOR {node_id, result}
"""

import hmac
import hashlib
import os
import threading
import time

import cbor2
import click
import paho.mqtt.client as mqtt_client

# MQTT topics (must match examples/mari_edge.py)
TOPIC_CHALLENGE_REQUEST  = "/craft/challenge_request"
TOPIC_CHALLENGE_RESPONSE = "/craft/challenge_response"
TOPIC_ATTEST             = "/craft/attest"
TOPIC_RESULT             = "/craft/attest_result"

CHALLENGE_SIZE = 8
ATTEST_TAG_SIZE = 32

# One static key for the whole testbed. Must match SEDA_SHARED_KEY in
# generate_craft_keys.py / CRAFT_SEDA_SHARED_KEY in attestation.c.
SEDA_SHARED_KEY = bytes.fromhex("3d0cf16e45fb5835f2ec73f339c26df919c5fadedee09aecd0f07b27612178e3")

# Matches test_hash[] in app/03app_node/attestation.c
EXPECTED_HASH = bytes([
    0xDE, 0x6C, 0xD0, 0x5D, 0x50, 0x77, 0x86, 0x48,
    0xBD, 0xB0, 0x7B, 0x4D, 0x1C, 0x6D, 0xB8, 0x1E,
    0x0C, 0x2D, 0xF4, 0x53, 0x3A, 0x32, 0xE5, 0x15,
    0xE5, 0x33, 0xA2, 0x6E, 0x21, 0x72, 0x87, 0x3B,
])


def _expected_tag(challenge: bytes, node_id: int) -> bytes:
    """HMAC-SHA256(K, challenge || hash || node_id), node_id big-endian."""
    data = challenge + EXPECTED_HASH + node_id.to_bytes(8, "big")
    return hmac.new(SEDA_SHARED_KEY, data, hashlib.sha256).digest()


# ========================= Verifier state ====================================

class CraftVerifier:
    def __init__(self):
        self._challenge_store: dict[int, bytes] = {}
        self._lock = threading.Lock()
        self.stats = {"received": 0, "succeeded": 0, "failed": 0}

    def register_challenge(self, node_id: int, challenge: bytes) -> None:
        with self._lock:
            self._challenge_store[node_id] = challenge

    def generate_challenge(self, node_id: int) -> bytes:
        """Generate a fresh challenge for node_id, store it, and return it for
        publishing back to the edge."""
        challenge = os.urandom(CHALLENGE_SIZE)
        self.register_challenge(node_id, challenge)
        print(f"[VERIFIER] generated challenge for 0x{node_id:016X}: {challenge.hex()}")
        return challenge

    def verify_attest(self, node_id: int, tag: bytes) -> bool:
        with self._lock:
            challenge = self._challenge_store.get(node_id)

        if challenge is None:
            print(f"[VERIFIER] No challenge for 0x{node_id:016X} — rejecting")
            self.stats["failed"] += 1
            return False

        self.stats["received"] += 1

        if len(tag) != ATTEST_TAG_SIZE:
            print(f"[VERIFIER] Attest tag wrong length for 0x{node_id:016X}: {len(tag)}")
            self.stats["failed"] += 1
            return False

        expected = _expected_tag(challenge, node_id)
        if not hmac.compare_digest(tag, expected):
            print(f"[VERIFIER] Attestation FAILED (tag mismatch) for 0x{node_id:016X}")
            print(f"[VERIFIER]   challenge: {challenge.hex()}")
            print(f"[VERIFIER]   expected:  {expected.hex()}")
            print(f"[VERIFIER]   got:       {tag.hex()}")
            self.stats["failed"] += 1
            return False

        print(f"[VERIFIER] Attestation PASSED for 0x{node_id:016X}")
        self.stats["succeeded"] += 1

        # One-time use: the tag match plus consuming it here is the freshness proof.
        with self._lock:
            self._challenge_store.pop(node_id, None)

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
    """CRAFT+SEDA Remote Verifier: challenge store + HMAC tag verification."""

    verifier = CraftVerifier()
    host, port, tls = _parse_mqtt_url(mqtt_url)

    client = mqtt_client.Client()

    def on_connect(c, userdata, flags, rc):
        if rc == 0:
            print(f"[VERIFIER] Connected to MQTT broker {host}:{port}")
            c.subscribe(TOPIC_CHALLENGE_REQUEST)
            c.subscribe(TOPIC_ATTEST)
            print(f"[VERIFIER] Subscribed to {TOPIC_CHALLENGE_REQUEST} and {TOPIC_ATTEST}")
        else:
            print(f"[VERIFIER] MQTT connect failed: rc={rc}")

    def on_message(c, userdata, msg):
        try:
            payload = cbor2.loads(msg.payload)
        except Exception as e:
            print(f"[VERIFIER] CBOR decode failed on {msg.topic}: {e}")
            return

        if msg.topic == TOPIC_CHALLENGE_REQUEST:
            node_id = payload.get("node_id")
            if node_id is None:
                print("[VERIFIER] Incomplete challenge_request payload")
                return
            node_id   = int(node_id)
            challenge = verifier.generate_challenge(node_id)
            c.publish(TOPIC_CHALLENGE_RESPONSE, cbor2.dumps({"node_id": node_id, "challenge": challenge}))

        elif msg.topic == TOPIC_ATTEST:
            node_id = payload.get("node_id")
            tag     = payload.get("tag")
            if node_id is None or tag is None:
                print("[VERIFIER] Incomplete attest payload")
                return
            node_id = int(node_id)
            tag     = bytes(tag)
            result  = verifier.verify_attest(node_id, tag)

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
