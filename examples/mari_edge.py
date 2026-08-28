"""CRAFT+SEDA Edge: connect (join) relying party + attest relay between node and verifier."""

import csv
import os
import struct
import threading
import time
from datetime import datetime
from pathlib import Path

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

MQTT_TOPIC_CHALLENGE_REQUEST  = "/craft/challenge_request"
MQTT_TOPIC_CHALLENGE_RESPONSE = "/craft/challenge_response"
MQTT_TOPIC_ATTEST             = "/craft/attest"
MQTT_TOPIC_ATTEST_RESULT      = "/craft/attest_result"

CHALLENGE_REQUEST_TIMEOUT = 3.0

# Only kick a node off the mesh after this many attestation failures in a row
# (across rounds) -- a lone fail is more likely transient congestion than a
# compromised node, and kicking mid-round just makes it re-contend for the
# join slot for nothing (it's already marked attested for this round).
KICK_AFTER_N_FAILURES = 3

# Mirrors mr_event_tag_t in mari/models.h -- only used to label NODE_LEFT reasons.
LEFT_REASON_NAMES = {
    0: "none",
    1: "handover",
    2: "out_of_sync",
    3: "peer_lost",  # deprecated
    4: "gateway_full",
    5: "peer_lost_timeout",
    6: "peer_lost_bloom",
    7: "handover_failed",
    8: "attestation_failed",
}

_operator_public_key = ed25519.Ed25519PublicKey.from_public_bytes(OPERATOR_PUBLIC_KEY)
_edge_x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(EDGE_X25519_PRIVATE_KEY)


# ========================= per-run CSV logging ================================

def _csv_path_for_run(eval_log: str, run: int) -> str:
    """--eval-log dir/prefix.csv -> dir/prefix_{run:03d}.csv."""
    stem, ext = os.path.splitext(eval_log)
    return f"{stem}_{run:03d}{ext or '.csv'}"


def _start_round_csv(eval_log: str | None, round_num: int, t0: float):
    """Open a fresh per-round CSV with a t0 row; returns (None, None) if eval_log is unset."""
    if eval_log is None:
        return None, None
    path = _csv_path_for_run(eval_log, round_num)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "w", newline="")
    writer = csv.writer(f)
    writer.writerow(["type", "timestamp", "node_id", "elapsed_s", "latency_s"])
    writer.writerow(["t0", f"{t0:.6f}", "", "", ""])
    f.flush()
    return f, writer


# ========================= connect wire helpers ================================

def _verify_connect_request(connect_bytes: bytes) -> bytes | None:
    """Verify sigma_i against PK_O, returning PK_i on success or None on failure."""
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
    """Derives the ECDH shared secret from EDGE_X25519_PRIVATE_KEY and PK_i, unused downstream but kept for protocol fidelity."""
    peer = x25519.X25519PublicKey.from_public_bytes(pk_i)
    return _edge_x25519_private_key.exchange(peer)


# ========================= Event handler =====================================

def on_event(event: EdgeEvent, event_data, mari: MarilibEdge, connect_state: dict, target_nodes: int, reboot_wait: float):
    if event == EdgeEvent.NODE_JOINED:
        # csv_file/csv_writer are also swapped from the main thread on round rollover
        # (see main()); this runs on the serial reader thread, so it needs the same lock.
        with connect_state["csv_lock"]:
            if connect_state["csv_writer"] is not None and connect_state["t0"] is not None:
                now = time.time()
                elapsed = now - connect_state["t0"]
                connect_state["csv_writer"].writerow(
                    ["node_joined", f"{now:.6f}", f"0x{event_data.address:016X}", f"{elapsed:.3f}", ""])
                connect_state["csv_file"].flush()

    elif event == EdgeEvent.NODE_LEFT:
        connect_state["sessions"].pop(event_data.address, None)
        connect_state["pending_reply"].pop(event_data.address, None)
        connect_state["pending_challenge"].pop(event_data.address, None)
        connect_state["completed"].discard(event_data.address)

        reason = LEFT_REASON_NAMES.get(event_data.left_reason, f"unknown({event_data.left_reason})")
        connect_state["left_reasons"][reason] = connect_state["left_reasons"].get(reason, 0) + 1

    elif event == EdgeEvent.EDHOC:
        subtype, node_id, msg_bytes, _asn_dl, _asn_ul = event_data

        if subtype == EDHOC_MSG1:
            if node_id in connect_state["attested"]:
                return  # already attested this round; stray retransmission needs no action

            # No cached-reply fast path: a stale reply could recycle a consumed challenge, so always re-verify.
            pending = connect_state["pending_challenge"].get(node_id)
            if pending is not None and pending["request"] == msg_bytes:
                if time.time() - pending["ts"] < CHALLENGE_REQUEST_TIMEOUT:
                    return  # request already in flight

            # Duplicate of a request already answered this cycle: resend the existing
            # reply instead of fetching a fresh challenge, which would invalidate the
            # challenge the node may already have in flight for its attest tag.
            session = connect_state["sessions"].get(node_id)
            if session is not None and session["request"] == msg_bytes:
                mari.send_edhoc(EDHOC_MSG2, node_id, session["reply"])
                connect_state["pending_reply"][node_id] = (session["reply"], time.time(), 0)
                return

            pk_i = _verify_connect_request(msg_bytes)
            if pk_i is None:
                return

            connect_state["completed"].discard(node_id)  # fresh cycle for this node

            _derive_k_ij(pk_i)  # unused downstream, kept for protocol fidelity

            # Non-blocking: publish and return so the serial reader thread isn't blocked.
            if not _request_challenge_from_verifier(mari, node_id):
                return
            connect_state["pending_challenge"][node_id] = {"request": msg_bytes, "ts": time.time()}

        elif subtype == EDHOC_MSG3:
            connect_state["pending_reply"].pop(node_id, None)

            if node_id in connect_state["completed"]:
                # Node resends its tag a few times regardless of outcome; already forwarded, ignore the repeat.
                return

            session = connect_state["sessions"].pop(node_id, None)
            if session is None:
                return

            if len(msg_bytes) != ATTEST_TAG_SIZE:
                return

            connect_state["completed"].add(node_id)
            _send_attest_to_verifier(mari, node_id, msg_bytes, connect_state["round"])

    elif event == EdgeEvent.ATTEST_RESULT:
        node_id, result, result_round = event_data
        if result_round != connect_state["round"]:
            return  # late result from an already-rebooted round; drop instead of miscrediting

        if result:
            connect_state["fail_counts"].pop(node_id, None)
        else:
            fails = connect_state["fail_counts"].get(node_id, 0) + 1
            connect_state["fail_counts"][node_id] = fails
            if fails >= KICK_AFTER_N_FAILURES:
                mari._send_kick_to_gateway(node_id)

        if node_id in connect_state["attested"]:
            return  # duplicate result
        connect_state["attested"].add(node_id)
        count = len(connect_state["attested"])
        ts = datetime.now().strftime("%H:%M:%S")
        round_label = "warmup" if connect_state["round"] == 1 else f"run {connect_state['round'] - 1}"
        print(f"[CRAFT] 0x{node_id:016X} {'PASS' if result else 'FAIL'} at {ts} ({count}/{target_nodes}, {round_label})")

        if count >= target_nodes and connect_state["reboot_at"] is None:
            connect_state["reboot_at"] = time.time() + reboot_wait
            if connect_state["t0"] is not None:
                reasons = ", ".join(f"{k}={v}" for k, v in sorted(dict(connect_state["left_reasons"]).items())) or "none"
                print(f"[CRAFT] {round_label} finished in {time.time() - connect_state['t0']:.1f}s (left reasons: {reasons})")


def _request_challenge_from_verifier(mari: MarilibEdge, node_id: int) -> bool:
    """Publish a challenge request to the verifier; reply is handled asynchronously."""
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
    """Subscribe to /craft/challenge_response and send the connect reply from the MQTT thread, so the serial reader never blocks."""
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

        now = time.time()
        reply = _build_connect_reply(challenge)
        connect_state["sessions"][node_id] = {
            "request":   pending["request"],
            "reply":     reply,
            "challenge": challenge,
        }
        connect_state["pending_reply"][node_id] = (reply, now, 0)
        mari.send_edhoc(EDHOC_MSG2, node_id, reply)

        # Time from EDHOC_MSG1 receipt to EDHOC_MSG2 sent -- the window the node's
        # own CONNECT_REPLY_TIMEOUT_SLOTS (~10.7s) races against before it self-resets.
        latency = now - pending["ts"]
        with connect_state["csv_lock"]:
            if connect_state["csv_writer"] is not None and connect_state["t0"] is not None:
                elapsed = now - connect_state["t0"]
                connect_state["csv_writer"].writerow(
                    ["connect_reply", f"{now:.6f}", f"0x{node_id:016X}", f"{elapsed:.3f}", f"{latency:.3f}"])
                connect_state["csv_file"].flush()

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


def _send_attest_to_verifier(mari: MarilibEdge, node_id: int, tag: bytes, round_num: int) -> None:
    """Send the attest HMAC tag to the verifier via MQTT, tagged with the requesting round."""
    if not mari.uses_mqtt:
        return
    payload = cbor2.dumps({"node_id": node_id, "tag": tag, "round": round_num})
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
            round_num = int(payload["round"])
        except Exception as e:
            print(f"[CRAFT] Malformed attest_result payload: {e}")
            return
        on_event_wrapper(EdgeEvent.ATTEST_RESULT, (node_id, result, round_num))

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
@click.option("--target-nodes", "-N", type=int, default=1, show_default=True,
              help="Number of nodes expected to attest before reboot_all is sent")
@click.option("--runs", "-r", type=int, default=0, show_default=True,
              help="Number of reboot cycles to run (0 = run forever, Ctrl+C to stop)")
@click.option("--reboot-wait", type=float, default=1.0, show_default=True,
              help="Seconds to wait after the target node count attests before sending reboot_all")
@click.option("--eval-log", type=click.Path(), default=None,
              help="CSV prefix for per-run joining-time logs, e.g. craft_nodes_010/craft_run.csv "
                   "-> craft_nodes_010/craft_run_001.csv, _002.csv, ... (one file per run)")
@click.option("--round-timeout", type=float, default=45.0, show_default=True,
              help="Force reboot_all if a round hasn't finished within this many seconds (0 = disabled)")
def main(port, mqtt_url, target_nodes, runs, reboot_wait, eval_log, round_timeout):
    """CRAFT+SEDA Edge: connect relying party + attest relay (node = initiator)."""

    connect_state: dict = {
        "sessions":          {},
        "pending_reply":     {},
        "pending_challenge": {},
        "completed":         set(),
        "attested":          set(),
        "left_reasons":      {},  # reset every round, see main loop
        "fail_counts":       {},  # persists across rounds -- see KICK_AFTER_N_FAILURES
        "reboot_at":         None,
        "round":             1,
        "stop":              False,
        "csv_file":          None,
        "csv_writer":        None,
        "csv_lock":          threading.Lock(),
        "t0":                None,
    }

    def on_event_wrapper(event, event_data):
        on_event(event, event_data, mari, connect_state, target_nodes, reboot_wait)

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

    # Wire subscriptions before the main loop -- MQTT won't back-deliver messages published earlier.
    if mari.uses_mqtt:
        while not mari.mqtt_connected:
            mari.update()
            time.sleep(0.01)
        _wire_challenge_response_subscription(mari, connect_state)
        _wire_attest_result_subscription(mari, on_event_wrapper)

    run_label = f"{runs} + 1 warmup" if runs > 0 else "unlimited"
    print(f"[CRAFT] Edge ready — waiting for node connect requests. (target_nodes={target_nodes}, runs={run_label})")

    # Round 1 is always a warmup: not counted towards --runs, not logged to CSV.
    connect_state["t0"] = time.time()

    try:
        while not connect_state["stop"]:
            mari.update()
            now = time.time()

            # Retry the connect reply indefinitely for nodes that haven't sent an attest tag yet,
            # with no per-node give-up cap, since round-timeout below is the only thing that ever
            # force-reboots a round.
            for node_id, (reply, last_sent, retry_count) in list(connect_state["pending_reply"].items()):
                if now - last_sent >= CONNECT_REPLY_RETRY_INTERVAL:
                    mari.send_edhoc(EDHOC_MSG2, node_id, reply)
                    connect_state["pending_reply"][node_id] = (reply, now, retry_count + 1)

            # A round can get stuck without ever entering the retry loop above
            # (e.g. a node that never sends a connect request this round at all),
            # so this is the sole backstop: force a reboot if the round has simply
            # run too long, regardless of what's stuck.
            if (round_timeout > 0 and connect_state["reboot_at"] is None
                    and connect_state["t0"] is not None
                    and now - connect_state["t0"] > round_timeout):
                reasons = ", ".join(f"{k}={v}" for k, v in sorted(dict(connect_state["left_reasons"]).items())) or "none"
                print(f"[CRAFT] round timed out after {round_timeout:.0f}s "
                      f"({len(connect_state['attested'])}/{target_nodes} attested) -- rebooting "
                      f"(left reasons: {reasons})")
                connect_state["reboot_at"] = now

            # Fire the reboot once the target node count has attested (see on_event),
            # from the main loop rather than the MQTT callback thread.
            if connect_state["reboot_at"] is not None and now >= connect_state["reboot_at"]:
                mari.send_reboot_all()
                connect_state["attested"] = set()
                connect_state["completed"] = set()
                connect_state["left_reasons"] = {}
                connect_state["reboot_at"] = None
                connect_state["round"] += 1
                if runs > 0 and connect_state["round"] > runs + 1:
                    print(f"[CRAFT] Completed {runs} run(s) — exiting.")
                    connect_state["stop"] = True
                else:
                    connect_state["t0"] = time.time()
                    # round is always >= 2 here (round 1 is the warmup, handled
                    # before the loop) -- recorded run numbers start at 1.
                    new_file, new_writer = _start_round_csv(
                        eval_log, connect_state["round"] - 1, connect_state["t0"])
                    with connect_state["csv_lock"]:
                        old_file = connect_state["csv_file"]
                        connect_state["csv_file"], connect_state["csv_writer"] = new_file, new_writer
                    if old_file is not None:
                        old_file.close()

            time.sleep(0.001)
    except KeyboardInterrupt:
        pass
    finally:
        if connect_state["csv_file"] is not None:
            connect_state["csv_file"].close()
        mari.close_tui()
        mari.logger.close()


if __name__ == "__main__":
    main()
