"""
Related-work Edge — EDHOC Responder + Attestation relay.

Design difference from the swarm mari_edge.py (this file on the
measurement-edhoc-attestation branch):
  - Node = EDHOC Initiator (sends msg1 in join request, msg3 with EAD_3 in uplink)
  - Edge = EDHOC Responder (receives msg1, sends msg2 with EAD_2 in join response)

EDHOC + Attestation flow:
  1. MSG1 received (from join request):
     - Request a fresh nonce from the verifier via MQTT (verifier generates it
       and keeps the node_id -> nonce mapping itself).
     - Build EAD_2 = CBOR [258, h'nonce'].
     - process_message_1() -> prepare_message_2(ead_2) -> send MSG2 to node.
  2. MSG3 received (from uplink):
     - parse_message_3() -> verify_message_3().
     - Extract EAD_3 (COSE_Sign1 token).
     - Compute attestation_binder from msg1 + msg2.
     - Send evidence + binder to verifier via MQTT.
  3. attest_result received (from verifier, via MQTT):
     - Log the result; kick the node from the gateway schedule if it failed
       (mirrors the swarm implementation's "kick node if result is false").
"""

import csv
import hashlib
import hmac
import os
import time
from datetime import datetime

import cbor2
import click
import lakers
from lakers import EdhocResponder, CredentialTransfer

from marilib.logger import MetricsLogger
from marilib.model import EdgeEvent, MariNode
from marilib.communication_adapter import SerialAdapter, MQTTAdapter
from marilib.serial_uart import get_default_port
from marilib.marilib_edge import MarilibEdge

# EDHOC subtype constants (mirror of mr_edhoc_subtype_t in models.h)
EDHOC_MSG1 = 1
EDHOC_MSG2 = 2
EDHOC_MSG3 = 3

# Must stay below the node's MSG2_TIMEOUT_SLOTS (~6s, see app/03app_node/main.c)
# or every node reset lands the next retry on a stale session (same failure mode
# already found and fixed on the swarm branch).
MSG3_RETRY_INTERVAL = 2.0
MSG3_MAX_RETRIES    = 30

# Downlink tag for the msg3 ack, sent the instant msg3 verifies so the node can stop retransmitting instead of guessing; must match MAURA_MSG3_ACK_TAG in app/03app_node/main.c.
MSG3_ACK_TAG = 0xAC

# MQTT topics for nonce request/response, evidence forwarding, and result retrieval
MQTT_TOPIC_NONCE_REQUEST  = "/maura/nonce_request"
MQTT_TOPIC_NONCE_RESPONSE = "/maura/nonce_response"
MQTT_TOPIC_EVIDENCE       = "/maura/evidence"
MQTT_TOPIC_ATTEST_RESULT  = "/maura/attest_result"

# How long to wait for the verifier's nonce_response before giving up on this
# msg1 (verifier is on the same localhost broker, so this should resolve in
# low milliseconds under normal operation).
NONCE_REQUEST_TIMEOUT = 3.0

# Edge is the EDHOC Responder here, using the credentials previously held by the mari node since the roles are reversed.
R = bytes([
    0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d,
    0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac,
])

CRED_R = bytes([
    0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1,
    0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60,
    0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
    0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45,
    0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca,
    0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
])

# CRED_I = expected node/initiator credential
CRED_I = bytes([
    0xa2, 0x02, 0x78, 0x20, 0x38, 0x35, 0x43, 0x31, 0x45, 0x43, 0x32, 0x31, 0x46, 0x32, 0x36, 0x46,
    0x34, 0x31, 0x45, 0x37, 0x41, 0x33, 0x30, 0x41, 0x38, 0x41, 0x38, 0x37, 0x42, 0x44, 0x42, 0x45,
    0x46, 0x32, 0x33, 0x43, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x01, 0x20, 0x01, 0x21,
    0x58, 0x20, 0x52, 0x7c, 0x4d, 0x4c, 0x08, 0x9f, 0x9f, 0xe3, 0x33, 0x56, 0xaa, 0x97, 0xa1, 0xd6,
    0x72, 0xda, 0x32, 0xc1, 0x60, 0x08, 0x24, 0x4f, 0xef, 0x37, 0xf0, 0x71, 0x54, 0xe0, 0x70, 0xe6,
    0x6d, 0x1f, 0x22, 0x58, 0x20, 0x32, 0xe4, 0x6c, 0x45, 0xc4, 0xdd, 0xcb, 0x6d, 0x6c, 0x52, 0x4f,
    0x37, 0x9d, 0x57, 0x15, 0x9d, 0x64, 0x2d, 0xd7, 0xf0, 0x27, 0x9c, 0x45, 0x50, 0xe3, 0x44, 0x48,
    0xda, 0xc4, 0x19, 0x53, 0x2c,
])

# ID_CRED_I = {4: h'\x01'} as CBOR bytes — matches _id_cred_i_cbor in app/03app_node/attestation.c
ID_CRED_I_BYTES = bytes([0xa1, 0x04, 0x41, 0x01])


# ========================= Attestation binder =================================

def _compute_h12(msg1: bytes, msg2: bytes) -> bytes:
    """H_12 = SHA256(SHA256(msg1) || msg2)."""
    h_msg1 = hashlib.sha256(msg1).digest()
    return hashlib.sha256(h_msg1 + msg2).digest()


def _hkdf_expand_sha256(prk: bytes, info: bytes) -> bytes:
    """HKDF-Expand(prk, info, 32): T(1) = HMAC-SHA256(prk, info || 0x01)."""
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def compute_attestation_binder(msg1: bytes, msg2: bytes) -> bytes:
    """
    attestation_binder = HKDF-Expand(zero_32, CBOR[H_12, "attestation", {4: h'\x01'}], 32)
    Mirrors _compute_attestation_binder() in app/03app_node/attestation.c.
    """
    h12         = _compute_h12(msg1, msg2)
    attest_info = cbor2.dumps([h12, "attestation", {4: bytes([0x01])}])
    zero_key    = bytes(32)
    return _hkdf_expand_sha256(zero_key, attest_info)


# ========================= Event handler =====================================

def on_event(
    event: EdgeEvent,
    event_data,
    mari: MarilibEdge,
    edhoc_state: dict,
    node_state: dict,
    eval_state: dict,
    target_nodes: int,
    nonce_responses: dict,
):
    writer = eval_state["writer"]

    if event == EdgeEvent.NODE_JOINED:
        node_state["joined"].add(event_data.address)
        node_state["edhoc_done"].discard(event_data.address)

    elif event == EdgeEvent.NODE_LEFT:
        node_state["joined"].discard(event_data.address)
        edhoc_state["sessions"].pop(event_data.address, None)
        edhoc_state["pending_msg2"].pop(event_data.address, None)
        edhoc_state["completed"].discard(event_data.address)

    elif event == EdgeEvent.EDHOC:
        subtype, node_id, edhoc_bytes, _asn_dl, _asn_ul = event_data

        if subtype == EDHOC_MSG1:
            # Node sent msg1 in join request -> create responder session

            # Only treat a repeat msg1 as a stale retry to resend the cached msg2 when its bytes
            # exactly match the cached one, since a rebooted node sends a genuinely new msg1 with
            # a fresh key that an old msg2 could never verify.
            existing = edhoc_state["sessions"].get(node_id)
            if existing is not None and existing["msg1"] == edhoc_bytes:
                mari.send_edhoc(EDHOC_MSG2, node_id, existing["msg2"])
                _, _, retry_count = edhoc_state["pending_msg2"].get(node_id, (None, None, 0))
                edhoc_state["pending_msg2"][node_id] = (existing["msg2"], time.time(), retry_count)
                return

            if not (5 <= len(edhoc_bytes) <= 200):
                return

            try:
                responder = EdhocResponder(R, CRED_R)
                _c_i, ead_1 = responder.process_message_1(edhoc_bytes)
            except Exception as e:
                print(f"[MAURA] process_message_1 failed for 0x{node_id:016X}: {e}")
                return

            # Request a fresh nonce from the verifier -- it generates the value
            # and keeps the node_id -> nonce mapping itself, rather than us
            # picking the value and just informing it.
            nonce = _request_nonce_from_verifier(mari, node_id, nonce_responses)
            if nonce is None:
                print(f"[MAURA] nonce request timed out for 0x{node_id:016X}")
                return

            # Build EAD_2 = CBOR [258, h'nonce']
            ead_2_value = cbor2.dumps([258, nonce])
            ead_2       = lakers.EADItem(2, False, ead_2_value)

            # Deterministic connection ID from node_id, restricted to 0..23: the node's
            # C API (lakers-c) strips the CBOR type header off the parsed c_r and later
            # rebuilds it via ConnId::from_int_raw(), which only accepts raw bytes that
            # are already a valid compact CBOR positive int (0..23) -- anything outside
            # that range reconstructs into an invalid ConnId and panics the node the
            # first time something classifies it (shared/src/lib.rs's
            # "Type invariant requires valid classification" unreachable!()).
            c_r = node_id % 24
            try:
                msg2 = responder.prepare_message_2(CredentialTransfer.ByReference, [c_r], ead_2)
            except Exception as e:
                print(f"[MAURA] prepare_message_2 failed for 0x{node_id:016X}: {e}")
                return

            edhoc_state["sessions"][node_id] = {
                "responder": responder,
                "msg1":      edhoc_bytes,
                "msg2":      bytes(msg2),
                "nonce":     nonce,
            }
            edhoc_state["pending_msg2"][node_id] = (bytes(msg2), time.time(), 0)
            mari.send_edhoc(EDHOC_MSG2, node_id, msg2)

        elif subtype == EDHOC_MSG3:
            # Node sent msg3 with EAD_3 in uplink
            edhoc_state["pending_msg2"].pop(node_id, None)

            if node_id in edhoc_state["completed"]:
                # We already verified msg3 for this node and popped its session --
                # this arrival is the node retransmitting because our ack got lost,
                # not a new msg3. Just re-send the ack; do NOT re-verify or re-submit
                # evidence to the verifier (the nonce is already consumed there, so a
                # second submission would fail nonce-reuse and could wrongly get the
                # node kicked for what was actually a successful attestation).
                mari.send_frame(node_id, bytes([MSG3_ACK_TAG]))
                return

            session = edhoc_state["sessions"].pop(node_id, None)
            if session is None:
                return

            responder = session["responder"]
            msg1      = session["msg1"]
            msg2      = session["msg2"]

            try:
                id_cred_i, ead_3 = responder.parse_message_3(edhoc_bytes)
                valid_cred_i      = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
                _prk_out          = responder.verify_message_3(valid_cred_i)
            except Exception as e:
                print(f"[MAURA] parse/verify_message_3 failed for 0x{node_id:016X}: {e}")
                return

            node_state["edhoc_done"].add(node_id)
            edhoc_state["completed"].add(node_id)
            mari.send_frame(node_id, bytes([MSG3_ACK_TAG]))
            print(f"[MAURA] EDHOC complete for 0x{node_id:016X}")

            if ead_3 is not None:
                evidence = ead_3.value()
                if evidence:
                    binder = compute_attestation_binder(msg1, msg2)
                    _send_evidence_to_verifier(mari, node_id, evidence, binder)

    elif event == EdgeEvent.ATTEST_RESULT:
        # Synthesized locally by _wire_attest_result_subscription() below — the swarm
        # branch's ATTEST_RESULT travels over the uniform /mari/{network_id}/to_edge
        # channel; this design uses its own /maura/attest_result topic instead, but
        # reuses the same EdgeEvent value and (node_id, result) tuple shape.
        if not eval_state["accepting_results"]:
            return  # round not active -- discard late results from verifier backlog
        node_id, result = event_data
        if node_id in node_state["attest_done_nodes"]:
            return  # duplicate result, ignore
        node_state["attest_done_nodes"].add(node_id)

        if not result:
            mari._send_kick_to_gateway(node_id)
            print(f"[MAURA] Attestation FAILED for 0x{node_id:016X} -> kicked from gateway")

        ts      = time.time()
        elapsed = ts - eval_state["t0"] if eval_state["t0"] else 0.0
        writer.writerow(["attest_result", f"{ts:.6f}", f"0x{node_id:016X}", str(result)])
        count = len(node_state["attest_done_nodes"])
        print(f"[EVAL] Attest node=0x{node_id:016X} result={result} at +{elapsed:.1f}s ({count}/{target_nodes})")
        if count == target_nodes:
            print(f"[EVAL] *** ALL {target_nodes} ATTESTATIONS DONE in {elapsed:.1f}s ***")
            eval_state["accepting_results"] = False
            eval_state["done"]              = True


def _request_nonce_from_verifier(mari: MarilibEdge, node_id: int, nonce_responses: dict) -> bytes | None:
    """Ask the verifier for a fresh nonce and block until it replies (or times out).

    The verifier generates the nonce and keeps its own node_id -> nonce mapping;
    nonce_responses is populated by the subscription wired in
    _wire_nonce_response_subscription() below, running on the MQTT client's
    background thread, so this busy-wait just polls that dict.
    """
    if not mari.uses_mqtt:
        return None
    payload = cbor2.dumps({"node_id": node_id})
    try:
        mari.mqtt_interface.client.publish(MQTT_TOPIC_NONCE_REQUEST, payload)
    except Exception as e:
        print(f"[MAURA] MQTT nonce request failed: {e}")
        return None

    deadline = time.time() + NONCE_REQUEST_TIMEOUT
    while time.time() < deadline:
        nonce = nonce_responses.pop(node_id, None)
        if nonce is not None:
            return nonce
        time.sleep(0.001)
    return None


def _wire_nonce_response_subscription(mari: MarilibEdge, nonce_responses: dict) -> None:
    """
    Subscribe to /maura/nonce_response on the edge's existing MQTT client.

    Same self-healing-across-reconnects pattern as _wire_attest_result_subscription
    below: chained onto on_connect so a broker reconnect doesn't silently drop it.
    """
    client = mari.mqtt_interface.client

    def _on_nonce_response(_client, _userdata, message):
        try:
            payload = cbor2.loads(message.payload)
            node_id = int(payload["node_id"])
            nonce   = bytes(payload["nonce"])
        except Exception as e:
            print(f"[MAURA] Malformed nonce_response payload: {e}")
            return
        nonce_responses[node_id] = nonce

    def _subscribe():
        client.message_callback_add(MQTT_TOPIC_NONCE_RESPONSE, _on_nonce_response)
        client.subscribe(MQTT_TOPIC_NONCE_RESPONSE, qos=0)

    _prior_on_connect = client.on_connect

    def _on_connect_chained(c, userdata, flags, reason_code, properties):
        if _prior_on_connect:
            _prior_on_connect(c, userdata, flags, reason_code, properties)
        _subscribe()

    client.on_connect = _on_connect_chained
    _subscribe()


def _send_evidence_to_verifier(mari: MarilibEdge, node_id: int, evidence: bytes, binder: bytes) -> None:
    """Send COSE_Sign1 evidence and attestation_binder to verifier via MQTT."""
    if not mari.uses_mqtt:
        return
    payload = cbor2.dumps({"node_id": node_id, "evidence": evidence, "binder": binder})
    try:
        mari.mqtt_interface.client.publish(MQTT_TOPIC_EVIDENCE, payload)
    except Exception as e:
        print(f"[MAURA] MQTT evidence send failed: {e}")


def _wire_attest_result_subscription(mari: MarilibEdge, on_event_wrapper) -> None:
    """
    Subscribe to /maura/attest_result on the edge's existing MQTT client.

    MQTTAdapter binds client.on_message to its own handler for the uniform
    /mari/{network_id}/to_edge channel; message_callback_add() attaches a
    topic-specific callback that paho dispatches instead of on_message for
    this one topic, without disturbing the rest of the edge<->cloud traffic.

    The subscribe call itself only registers with the *current* broker session.
    MQTTAdapter's own on_connect (_on_connect_edge) re-subscribes its uniform
    /mari/.../to_edge topic on every reconnect, but had no idea about this
    extra topic -- so a single MQTT reconnect (broker blip, keepalive timeout
    under load, etc.) silently unsubscribed us from /maura/attest_result
    forever, since this function only ever ran once. Chaining onto on_connect
    makes the subscription self-healing across reconnects, same as the
    library's own topic.
    """
    client = mari.mqtt_interface.client

    def _on_attest_result(_client, _userdata, message):
        try:
            payload = cbor2.loads(message.payload)
            node_id = int(payload["node_id"])
            result  = bool(payload["result"])
        except Exception as e:
            print(f"[MAURA] Malformed attest_result payload: {e}")
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


def _csv_path_for_run(eval_log: str, run: int, runs: int) -> str:
    if runs == 1:
        return eval_log
    stem, ext = os.path.splitext(eval_log)
    return f"{stem}_{run:03d}{ext or '.csv'}"


@click.command()
@click.option("--port", "-p", type=str, default=get_default_port(), show_default=True)
@click.option("--mqtt-url", "-m", type=str, default=None)
@click.option("--metrics-probe-interval", "-i", type=float, default=0)
@click.option("--log-dir", default="logs", show_default=True, type=click.Path())
@click.option("--eval-log", default="eval_maura.csv", show_default=True, type=click.Path())
@click.option("--target-nodes", "-N", type=int, default=100, show_default=True)
@click.option("--runs", "-r", type=int, default=1, show_default=True)
@click.option("--reboot-wait", type=float, default=5.0, show_default=True)
@click.option("--auto-exit", is_flag=True, default=False)
@click.option("--round-timeout", type=float, default=300.0, show_default=True)
@click.option("--warmup-runs", type=int, default=1, show_default=True)
def main(port, mqtt_url, metrics_probe_interval, log_dir, eval_log,
         target_nodes, runs, reboot_wait, auto_exit, round_timeout, warmup_runs):
    """Related-work Edge: EDHOC Responder + attestation relay (node = Initiator)."""

    edhoc_state: dict = {
        "sessions":    {},
        "pending_msg2": {},
        "completed":   set(),
    }
    node_state: dict = {
        "joined": set(), "edhoc_done": set(), "attest_done_nodes": set(),
    }
    eval_state: dict = {
        "t0": None, "done": False, "writer": None,
        "run": 0, "total_runs": runs,
        "accepting_results": False,
    }
    nonce_responses: dict = {}

    def on_event_wrapper(event, event_data):
        on_event(event, event_data, mari, edhoc_state, node_state, eval_state, target_nodes, nonce_responses)

    mari = MarilibEdge(
        on_event_wrapper,
        serial_interface=SerialAdapter(port),
        mqtt_interface=MQTTAdapter.from_url(mqtt_url, is_edge=True) if mqtt_url else None,
        logger=MetricsLogger(log_dir_base=log_dir, rotation_interval_minutes=1440,
                             log_interval_seconds=1.0),
        tui=None,
        main_file=__file__,
        metrics_probe_period=metrics_probe_interval,
    )

    exit_on_done = auto_exit or (runs > 1)
    result_subscription_wired = False

    # Wire the attest_result and nonce_response subscriptions before the reboot_wait sleep
    # below, since a node that finishes during that window would publish before mari_edge
    # is subscribed and MQTT does not back-deliver missed messages.
    if mari.uses_mqtt:
        while not mari.mqtt_connected:
            mari.update()
            time.sleep(0.01)
        _wire_nonce_response_subscription(mari, nonce_responses)
        _wire_attest_result_subscription(mari, on_event_wrapper)
        result_subscription_wired = True

    try:
        for run in range(1 - warmup_runs, runs + 1):
            is_warmup = run <= 0
            warmup_label = f"WARMUP {warmup_runs + run}/{warmup_runs}" if is_warmup else f"{run}/{runs}"

            if is_warmup:
                import io as _io
                eval_file = _io.StringIO()
            else:
                csv_path = _csv_path_for_run(eval_log, run, runs)
                csv_dir  = os.path.dirname(csv_path)
                if csv_dir:
                    os.makedirs(csv_dir, exist_ok=True)
                eval_file = open(csv_path, "w", newline="")

            writer = csv.writer(eval_file)
            writer.writerow(["type", "timestamp", "node_id", "result"])

            edhoc_state.update({"sessions": {}, "pending_msg2": {}, "completed": set()})
            node_state.update({"joined": set(), "edhoc_done": set(), "attest_done_nodes": set()})
            eval_state.update({"t0": None, "done": False, "writer": writer, "run": run,
                                "accepting_results": False})
            nonce_responses.clear()

            print(f"\n{'#'*62}")
            if is_warmup:
                print(f"# [EVAL] {warmup_label}  (warm-up)")
            else:
                print(f"# [EVAL] Run {warmup_label}  ->  {csv_path}")
            print(f"{'#'*62}\n")

            t0 = time.time()
            eval_state["t0"]               = t0
            eval_state["accepting_results"] = True
            writer.writerow(["t0", f"{t0:.6f}", "", ""])
            eval_file.flush()
            t0_wall = datetime.fromtimestamp(t0).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[EVAL] T0 = {t0_wall}")

            # Reboot nodes so they rejoin and trigger fresh EDHOC
            mari.send_reboot_all()
            if reboot_wait > 0:
                print(f"[EVAL] Reboot sent — waiting {reboot_wait:.0f}s ...")
                time.sleep(reboot_wait)
            print(f"[EVAL] Reboot wait done — round {run} active (target={target_nodes})")

            last_flush = 0.0
            while not eval_state["done"]:
                mari.update()
                now = time.time()

                if not result_subscription_wired and mari.mqtt_connected:
                    _wire_attest_result_subscription(mari, on_event_wrapper)
                    result_subscription_wired = True

                if round_timeout > 0 and now - t0 >= round_timeout:
                    attested = len(node_state["attest_done_nodes"])
                    print(f"[EVAL] Round {run} TIMEOUT — {attested}/{target_nodes} attested")
                    writer.writerow(["timeout", f"{now:.6f}", "", f"{attested}/{target_nodes}"])
                    eval_state["accepting_results"] = False
                    eval_state["done"]              = True
                    break

                if now - last_flush >= 2.0:
                    eval_file.flush()
                    last_flush = now

                # Retry msg2 for nodes that haven't responded with msg3 yet
                for node_id, (msg2, last_sent, retry_count) in list(edhoc_state["pending_msg2"].items()):
                    if node_id not in node_state["joined"]:
                        edhoc_state["pending_msg2"].pop(node_id, None)
                        continue
                    if retry_count >= MSG3_MAX_RETRIES:
                        edhoc_state["pending_msg2"].pop(node_id, None)
                        continue
                    if now - last_sent >= MSG3_RETRY_INTERVAL:
                        mari.send_edhoc(EDHOC_MSG2, node_id, msg2)
                        edhoc_state["pending_msg2"][node_id] = (msg2, now, retry_count + 1)

                if not exit_on_done and eval_state["done"]:
                    break

                time.sleep(0.001)

            eval_file.flush()
            eval_file.close()

            if run < runs:
                label = "Warm-up" if is_warmup else f"Round {run}"
                print(f"[EVAL] {label} complete — starting next round.")

    except KeyboardInterrupt:
        pass
    finally:
        mari.close_tui()
        mari.logger.close()


if __name__ == "__main__":
    main()
