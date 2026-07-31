"""
CRAFT+SEDA Edge — connect (join) relying party + attest relay.

Verifies the node's connect request against PK_O, fetches a SEDA challenge
from the verifier over MQTT, and replies with the connect reply + challenge
as the join response. Relays the node's attest tag to the verifier and acts
on the pass/fail result.
"""

import struct
import time

import cbor2
import click
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from craft_edge_keys import (
    OPERATOR_PUBLIC_KEY, EDGE_H, EDGE_TA, EDGE_TB,
    EDGE_X25519_PRIVATE_KEY, EDGE_X25519_PUBLIC_KEY, EDGE_SIGMA,
)

from marilib.logger import MetricsLogger
from marilib.model import EdgeEvent
from marilib.communication_adapter import SerialAdapter, MQTTAdapter
from marilib.serial_uart import get_default_port
from marilib.marilib_edge import MarilibEdge

# Transport subtypes (mirror of mr_edhoc_subtype_t in models.h)
EDHOC_MSG1 = 1  # connect request (node -> edge)
EDHOC_MSG2 = 2  # connect reply + piggybacked challenge (edge -> node)
EDHOC_MSG3 = 3  # attest tag (node -> edge)

# connect wire layout: h_i(1) | Ta_i(4) | Tb_i(4) | PK_i(32) | SigExp(4) | sigma(64)
# Must match CRAFT_*_SIZE in app/03app_node/attestation.h.
H_SIZE, TA_SIZE, TB_SIZE, PK_SIZE, SIGEXP_SIZE, SIGMA_SIZE = 1, 4, 4, 32, 4, 64
SIGNED_SIZE   = H_SIZE + TA_SIZE + TB_SIZE + PK_SIZE  # 41, what sigma covers
CONNECT_SIZE  = SIGNED_SIZE + SIGEXP_SIZE + SIGMA_SIZE  # 109
CHALLENGE_SIZE = 8

ATTEST_TAG_SIZE = 32

SIG_EXPIRATION = 0xFFFFFFFF  # far-future constant, see attestation.c

# Must stay below the node's CONNECT_REPLY_TIMEOUT_SLOTS (app/03app_node/main.c).
CONNECT_REPLY_RETRY_INTERVAL = 2.0
CONNECT_REPLY_MAX_RETRIES    = 30

ATTEST_ACK_TAG = 0xAC  # must match CRAFT_ATTEST_ACK_TAG in app/03app_node/main.c

MQTT_TOPIC_CHALLENGE_REQUEST  = "/craft/challenge_request"
MQTT_TOPIC_CHALLENGE_RESPONSE = "/craft/challenge_response"
MQTT_TOPIC_ATTEST             = "/craft/attest"
MQTT_TOPIC_ATTEST_RESULT      = "/craft/attest_result"

CHALLENGE_REQUEST_TIMEOUT = 3.0

_operator_public_key = ed25519.Ed25519PublicKey.from_public_bytes(OPERATOR_PUBLIC_KEY)
_edge_x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(EDGE_X25519_PRIVATE_KEY)


# ========================= connect wire helpers ================================

def _verify_connect_request(connect_bytes: bytes) -> bytes | None:
    """Verify sigma_i against PK_O. Returns PK_i on success, None on failure."""
    if len(connect_bytes) != CONNECT_SIZE:
        return None
    # bytearray -> bytes: the cryptography library rejects bytearray slices.
    connect_bytes  = bytes(connect_bytes)
    signed_portion = connect_bytes[:SIGNED_SIZE]
    pk_i           = connect_bytes[H_SIZE + TA_SIZE + TB_SIZE: SIGNED_SIZE]
    sigma_i        = connect_bytes[SIGNED_SIZE + SIGEXP_SIZE:]
    try:
        _operator_public_key.verify(sigma_i, signed_portion)
    except InvalidSignature:
        return None
    return pk_i


def _build_connect_reply(challenge: bytes) -> bytes:
    """h_edge | Ta_edge | Tb_edge | PK_edge | SigExp | sigma_edge | challenge."""
    return (
        struct.pack(">BII", EDGE_H, EDGE_TA, EDGE_TB)
        + EDGE_X25519_PUBLIC_KEY
        + struct.pack(">I", SIG_EXPIRATION)
        + EDGE_SIGMA
        + challenge
    )


def _derive_k_ij(pk_i: bytes) -> bytes:
    """ECDH(EDGE_X25519_PRIVATE_KEY, PK_i). Unused downstream, kept for protocol fidelity."""
    peer = x25519.X25519PublicKey.from_public_bytes(pk_i)
    return _edge_x25519_private_key.exchange(peer)


# ========================= Event handler =====================================

def on_event(event: EdgeEvent, event_data, mari: MarilibEdge, connect_state: dict):
    if event == EdgeEvent.NODE_JOINED:
        print(f"[CRAFT] NODE_JOINED 0x{event_data.address:016X}")

    elif event == EdgeEvent.NODE_LEFT:
        reason = getattr(event_data, "left_reason", None)
        print(f"[CRAFT] NODE_LEFT 0x{event_data.address:016X} reason={reason}")
        connect_state["sessions"].pop(event_data.address, None)
        connect_state["pending_reply"].pop(event_data.address, None)
        connect_state["pending_challenge"].pop(event_data.address, None)
        connect_state["completed"].discard(event_data.address)

    elif event == EdgeEvent.EDHOC:
        subtype, node_id, msg_bytes, _asn_dl, _asn_ul = event_data

        if subtype == EDHOC_MSG1:
            # No cached-reply fast path: connect requests are byte-identical
            # across reboots, so resending a cached reply could recycle a
            # stale/consumed challenge. Always re-verify and fetch fresh.
            pending = connect_state["pending_challenge"].get(node_id)
            if pending is not None and pending["request"] == msg_bytes:
                if time.time() - pending["ts"] < CHALLENGE_REQUEST_TIMEOUT:
                    return  # request already in flight

            pk_i = _verify_connect_request(msg_bytes)
            if pk_i is None:
                return

            connect_state["completed"].discard(node_id)  # fresh cycle for this node

            _derive_k_ij(pk_i)  # unused downstream, kept for protocol fidelity

            # Non-blocking: publish and return so the serial reader thread
            # isn't blocked; the reply is sent later from the MQTT callback.
            if not _request_challenge_from_verifier(mari, node_id):
                return
            connect_state["pending_challenge"][node_id] = {"request": msg_bytes, "ts": time.time()}

        elif subtype == EDHOC_MSG3:
            print(f"[CRAFT] attest tag from 0x{node_id:016X} ({len(msg_bytes)} B): {msg_bytes.hex()}")
            connect_state["pending_reply"].pop(node_id, None)

            if node_id in connect_state["completed"]:
                # Already forwarded -- this is a retransmit of a lost ack, not
                # a new tag. Re-ack only; don't resubmit (challenge is consumed).
                mari.send_frame(node_id, bytes([ATTEST_ACK_TAG]))
                return

            session = connect_state["sessions"].pop(node_id, None)
            if session is None:
                print(f"[CRAFT] DROP attest tag from 0x{node_id:016X}: no live session")
                return

            if len(msg_bytes) != ATTEST_TAG_SIZE:
                print(f"[CRAFT] DROP attest tag from 0x{node_id:016X}: wrong length {len(msg_bytes)}")
                return

            connect_state["completed"].add(node_id)
            mari.send_frame(node_id, bytes([ATTEST_ACK_TAG]))
            _send_attest_to_verifier(mari, node_id, msg_bytes)

    elif event == EdgeEvent.ATTEST_RESULT:
        node_id, result = event_data
        if not result:
            mari._send_kick_to_gateway(node_id)
        print(f"[CRAFT] Attest result for 0x{node_id:016X}: {'PASS' if result else 'FAIL'}")


def _request_challenge_from_verifier(mari: MarilibEdge, node_id: int) -> bool:
    """Publish a challenge request to the verifier. Non-blocking -- the reply
    is handled asynchronously by _on_challenge_response when it arrives."""
    if not mari.uses_mqtt:
        return False
    payload = cbor2.dumps({"node_id": node_id})
    try:
        mari.mqtt_interface.client.publish(MQTT_TOPIC_CHALLENGE_REQUEST, payload)
    except Exception as e:
        print(f"[CRAFT] MQTT challenge request failed: {e}")
        return False
    return True


def _wire_challenge_response_subscription(mari: MarilibEdge, connect_state: dict) -> None:
    """Subscribe to /craft/challenge_response, self-healing across MQTT reconnects.

    Runs on the MQTT client's own background thread, not the serial reader
    thread -- builds and sends the connect reply here so the reader thread
    is never blocked waiting for the verifier.
    """
    client = mari.mqtt_interface.client

    def _on_challenge_response(_client, _userdata, message):
        try:
            payload   = cbor2.loads(message.payload)
            node_id   = int(payload["node_id"])
            challenge = bytes(payload["challenge"])
        except Exception as e:
            print(f"[CRAFT] Malformed challenge_response payload: {e}")
            return

        pending = connect_state["pending_challenge"].pop(node_id, None)
        if pending is None:
            return  # stale/duplicate response, or node already gave up

        reply = _build_connect_reply(challenge)
        connect_state["sessions"][node_id] = {
            "request":   pending["request"],
            "reply":     reply,
            "challenge": challenge,
        }
        connect_state["pending_reply"][node_id] = (reply, time.time(), 0)
        mari.send_edhoc(EDHOC_MSG2, node_id, reply)

    def _subscribe():
        client.message_callback_add(MQTT_TOPIC_CHALLENGE_RESPONSE, _on_challenge_response)
        client.subscribe(MQTT_TOPIC_CHALLENGE_RESPONSE, qos=0)

    _prior_on_connect = client.on_connect

    def _on_connect_chained(c, userdata, flags, reason_code, properties):
        if _prior_on_connect:
            _prior_on_connect(c, userdata, flags, reason_code, properties)
        _subscribe()

    client.on_connect = _on_connect_chained
    _subscribe()


def _send_attest_to_verifier(mari: MarilibEdge, node_id: int, tag: bytes) -> None:
    """Send the attest HMAC tag to the verifier via MQTT."""
    if not mari.uses_mqtt:
        return
    payload = cbor2.dumps({"node_id": node_id, "tag": tag})
    try:
        mari.mqtt_interface.client.publish(MQTT_TOPIC_ATTEST, payload)
    except Exception as e:
        print(f"[CRAFT] MQTT attest send failed: {e}")


def _wire_attest_result_subscription(mari: MarilibEdge, on_event_wrapper) -> None:
    """Subscribe to /craft/attest_result, self-healing across MQTT reconnects."""
    client = mari.mqtt_interface.client

    def _on_attest_result(_client, _userdata, message):
        try:
            payload = cbor2.loads(message.payload)
            node_id = int(payload["node_id"])
            result  = bool(payload["result"])
        except Exception as e:
            print(f"[CRAFT] Malformed attest_result payload: {e}")
            return
        on_event_wrapper(EdgeEvent.ATTEST_RESULT, (node_id, result))

    def _subscribe():
        client.message_callback_add(MQTT_TOPIC_ATTEST_RESULT, _on_attest_result)
        client.subscribe(MQTT_TOPIC_ATTEST_RESULT, qos=0)

    _prior_on_connect = client.on_connect

    def _on_connect_chained(c, userdata, flags, reason_code, properties):
        if _prior_on_connect:
            _prior_on_connect(c, userdata, flags, reason_code, properties)
        _subscribe()

    client.on_connect = _on_connect_chained
    _subscribe()


@click.command()
@click.option("--port", "-p", type=str, default=get_default_port(), show_default=True)
@click.option("--mqtt-url", "-m", type=str, default=None)
def main(port, mqtt_url):
    """CRAFT+SEDA Edge: connect relying party + attest relay (node = initiator)."""

    connect_state: dict = {
        "sessions":          {},
        "pending_reply":     {},
        "pending_challenge": {},
        "completed":         set(),
    }

    def on_event_wrapper(event, event_data):
        on_event(event, event_data, mari, connect_state)

    mari = MarilibEdge(
        on_event_wrapper,
        serial_interface=SerialAdapter(port),
        mqtt_interface=MQTTAdapter.from_url(mqtt_url, is_edge=True) if mqtt_url else None,
        logger=MetricsLogger(log_dir_base="logs", rotation_interval_minutes=1440,
                             log_interval_seconds=1.0),
        tui=None,
        main_file=__file__,
        metrics_probe_period=0,
    )

    # Wire subscriptions before the main loop -- MQTT doesn't back-deliver
    # messages published before a subscription existed.
    if mari.uses_mqtt:
        while not mari.mqtt_connected:
            mari.update()
            time.sleep(0.01)
        _wire_challenge_response_subscription(mari, connect_state)
        _wire_attest_result_subscription(mari, on_event_wrapper)

    print("[CRAFT] Edge ready — waiting for node connect requests.")
    try:
        while True:
            mari.update()
            now = time.time()

            # Retry the connect reply for nodes that haven't sent an attest tag yet
            for node_id, (reply, last_sent, retry_count) in list(connect_state["pending_reply"].items()):
                if retry_count >= CONNECT_REPLY_MAX_RETRIES:
                    connect_state["pending_reply"].pop(node_id, None)
                    continue
                if now - last_sent >= CONNECT_REPLY_RETRY_INTERVAL:
                    mari.send_edhoc(EDHOC_MSG2, node_id, reply)
                    connect_state["pending_reply"][node_id] = (reply, now, retry_count + 1)

            time.sleep(0.001)
    except KeyboardInterrupt:
        pass
    finally:
        mari.close_tui()
        mari.logger.close()


if __name__ == "__main__":
    main()
