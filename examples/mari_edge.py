import csv
import os
import time
from datetime import datetime

import cbor2
import click
import lakers
from lakers import EdhocInitiator, CredentialTransfer

from marilib.logger import MetricsLogger
from marilib.mari_protocol import Frame, MARI_BROADCAST_ADDRESS, DefaultPayload
from marilib.model import EdgeEvent, MariNode
from marilib.communication_adapter import SerialAdapter, MQTTAdapter
from marilib.serial_uart import get_default_port
from marilib.tui_edge import MarilibTUIEdge
from marilib.marilib_edge import MarilibEdge

# EDHOC subtype constants (mirror of mr_edhoc_subtype_t in models.h)
EDHOC_MSG1 = 1
EDHOC_MSG2 = 2
EDHOC_MSG3 = 3
EDHOC_MSG4 = 4

MSG3_RETRY_INTERVAL = 2.0   # seconds between msg3 retries (must be < node's MSG3_TIMEOUT_SLOTS ≈ 6s)
MSG3_MAX_RETRIES    = 30    # max msg3 retry attempts per node

# Initiator (edge) static private DH key (matches I[0] in 03app_dotbot.c)
I = bytes([
    0x1f, 0x7e, 0x4a, 0xe4, 0x29, 0x3a, 0x34, 0x8b, 0xf2, 0xb1, 0x36, 0x5c, 0xe0, 0x98, 0xaa, 0x49,
    0xc2, 0x07, 0xbd, 0x1b, 0xa7, 0xdd, 0xde, 0xcd, 0xfa, 0xd6, 0x0c, 0xad, 0xe8, 0x2e, 0x9e, 0xf5,
])

# Initiator credential (matches CRED_I_BYTES in node main.c and CRED_I[0] in 03app_dotbot.c)
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

# Responder credential (matches CRED_R_BYTES in node main.c and CRED_R in 03app_dotbot.c)
CRED_R = bytes([
    0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65, 0x64, 0x75, 0x08, 0xa1,
    0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60,
    0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
    0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0, 0x22, 0x58, 0x20, 0x45,
    0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca,
    0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
])

# How often to rotate msg1 (new ephemeral key for forward secrecy).
EDHOC_MSG1_RESEND_INTERVAL = 300.0


def _init_edhoc(mari: MarilibEdge) -> tuple[EdhocInitiator, bytes]:
    """Create a fresh EdhocInitiator and generate message 1 (no EAD_1)."""
    initiator = EdhocInitiator()
    msg1 = initiator.prepare_message_1(c_i=None, ead_1=None)
    return initiator, msg1


def _csv_path_for_run(eval_log: str, run: int, runs: int) -> str:
    """Return the CSV path for a given run number (numbered only when runs > 1)."""
    if runs == 1:
        return eval_log
    stem, ext = os.path.splitext(eval_log)
    return f"{stem}_{run:03d}{ext or '.csv'}"


def on_event(
    event: EdgeEvent,
    event_data,
    mari: MarilibEdge,
    edhoc_state: dict,
    node_state: dict,
    eval_state: dict,
    target_nodes: int,
):
    """Application event handler — eval_state['writer'] holds the current CSV writer."""
    writer = eval_state["writer"]

    if event == EdgeEvent.NODE_JOINED:
        node_state["joined"].add(event_data.address)
        node_state["edhoc_done"].discard(event_data.address)

    elif event == EdgeEvent.NODE_LEFT:
        node_state["joined"].discard(event_data.address)
        edhoc_state["pending_msg3"].pop(event_data.address, None)

    elif event == EdgeEvent.ATTEST_RESULT:
        if not eval_state["accepting_results"]:
            return  # round not active — discard late results from verifier backlog
        node_id, result = event_data
        if node_id in node_state["attest_done_nodes"]:
            return  # duplicate result for this node, ignore
        node_state["attest_done_nodes"].add(node_id)
        ts = time.time()
        elapsed = ts - eval_state["t0"] if eval_state["t0"] else 0.0
        writer.writerow(["attest_result", f"{ts:.6f}", f"0x{node_id:016X}", str(result)])
        count = len(node_state["attest_done_nodes"])
        run_label = f"run {eval_state['run']}/{eval_state['total_runs']}  " if eval_state["total_runs"] > 1 else ""
        print(f"[EVAL] {run_label}Attest node=0x{node_id:016X} result={result} at +{elapsed:.1f}s  ({count}/{target_nodes})")
        if count == target_nodes:
            print(f"[EVAL] *** ALL {target_nodes} ATTESTATIONS DONE in {elapsed:.1f}s ***")
            eval_state["accepting_results"] = False
            eval_state["done"] = True

    elif event == EdgeEvent.NODE_DATA:
        pass

    elif event == EdgeEvent.EDHOC:
        subtype, node_id, edhoc_bytes, asn_dl, asn_ul = event_data

        if subtype == EDHOC_MSG2:
            if not (10 <= len(edhoc_bytes) <= 200):
                return  # obviously corrupted length — drop before lakers sees it
            session = None
            for src_initiator in [edhoc_state["initiator"], edhoc_state["prev_initiator"]]:
                if src_initiator is None:
                    continue
                try:
                    candidate = src_initiator.clone_after_message_1()
                    _c_r, id_cred_r, _ead_2 = candidate.parse_message_2(edhoc_bytes)
                    valid_cred_r = lakers.credential_check_or_fetch(id_cred_r, CRED_R)
                    candidate.verify_message_2(I, CRED_I, valid_cred_r)
                    session = candidate
                    break
                except BaseException:
                    # Rust panic on corrupted packet — the clone panicked, not the
                    # original initiator, so src_initiator is still valid. Just skip
                    # this corrupted msg2 and let the thread continue normally.
                    break

            if session is None:
                return

            try:
                msg3, _prk_out = session.prepare_message_3(CredentialTransfer.ByReference, None)
            except BaseException:
                return

            edhoc_state["sessions"][node_id] = session
            edhoc_state["pending_msg3"][node_id] = (msg3, time.time(), 0)
            mari.send_edhoc(EDHOC_MSG3, node_id, msg3)

        elif subtype == EDHOC_MSG4:
            edhoc_state["pending_msg3"].pop(node_id, None)
            session = edhoc_state["sessions"].pop(node_id, None)
            if session is None:
                return
            try:
                ead_4 = session.process_message_4(edhoc_bytes)
                attestation_binder = session.edhoc_exporter(2, b'attestation', 32)
                node_state["edhoc_done"].add(node_id)

                if ead_4 is not None:
                    evidence_cbor = ead_4.value()
                    if evidence_cbor is not None:
                        attest_cbor = cbor2.dumps([asn_dl, asn_ul, evidence_cbor, node_id, attestation_binder])
                        attest_total = 1 + len(attest_cbor)
                        mari.send_attestation_to_cloud(node_id, asn_dl, asn_ul, evidence_cbor, attestation_binder)
            except BaseException:
                pass


@click.command()
@click.option("--port", "-p", type=str, default=get_default_port(), show_default=True, help="Serial port (e.g. /dev/ttyACM0)")
@click.option("--mqtt-url", "-m", type=str, default=None, help="MQTT broker URL (default: no cloud)")
@click.option("--metrics-probe-interval", "-i", type=float, default=0, help="Metrics probe interval in seconds (0 = disabled)")
@click.option("--log-dir", default="logs", show_default=True, help="Directory for metric log files", type=click.Path())
@click.option("--eval-log", default="eval_edhoc.csv", show_default=True, help="CSV file (or prefix when --runs > 1)", type=click.Path())
@click.option("--target-nodes", "-N", type=int, default=100, show_default=True, help="Number of nodes expected per run")
@click.option("--runs", "-r", type=int, default=1, show_default=True, help="Number of repeated runs (uses reboot between rounds)")
@click.option("--reboot-wait", type=float, default=5.0, show_default=True, help="Seconds to wait after reboot command before sending msg1")
@click.option("--auto-exit", is_flag=True, default=False, show_default=True, help="Exit after all attestations complete (single-run mode only; always true when --runs > 1)")
@click.option("--round-timeout", type=float, default=300.0, show_default=True, help="Seconds before a round is forced to end even if not all nodes attested (0 = no timeout)")
@click.option("--warmup-runs", type=int, default=1, show_default=True, help="Warm-up rounds to run before recording (results discarded, default: 1)")
def main(port, mqtt_url, metrics_probe_interval, log_dir, eval_log, target_nodes, runs, reboot_wait, auto_exit, round_timeout, warmup_runs):
    """MarilibEdge: EDHOC + attestation initiator. Supports repeated runs via coordinated node reboot."""

    # Shared mutable state — updated in-place between rounds so the closure always sees current values
    edhoc_state: dict = {
        "initiator": None, "prev_initiator": None, "msg1": None,
        "sessions": {}, "last_msg1_sent": 0.0, "pending_msg3": {},
    }
    node_state: dict = {
        "joined": set(), "edhoc_done": set(), "attest_done_nodes": set(),
    }
    eval_state: dict = {
        "t0": None, "done": False, "writer": None,
        "run": 0, "total_runs": runs,
        "accepting_results": False,  # True only while a round is actively measuring
    }

    def on_event_wrapper(event: EdgeEvent, event_data):
        on_event(event, event_data, mari, edhoc_state, node_state, eval_state, target_nodes)

    mari = MarilibEdge(
        on_event_wrapper,
        serial_interface=SerialAdapter(port),
        mqtt_interface=MQTTAdapter.from_url(mqtt_url, is_edge=True) if mqtt_url else None,
        logger=MetricsLogger(log_dir_base=log_dir, rotation_interval_minutes=1440, log_interval_seconds=1.0),
        tui=None,
        main_file=__file__,
        metrics_probe_period=metrics_probe_interval,
    )

    exit_on_done = auto_exit or (runs > 1)

    try:
        for run in range(1 - warmup_runs, runs + 1):
            is_warmup = run <= 0
            warmup_label = f"WARMUP {warmup_runs + run}/{warmup_runs}" if is_warmup else f"{run}/{runs}"

            if is_warmup:
                import io as _io
                eval_file = _io.StringIO()  # discard warmup output
            else:
                csv_path = _csv_path_for_run(eval_log, run, runs)
                eval_file = open(csv_path, "w", newline="")

            writer = csv.writer(eval_file)
            writer.writerow(["type", "timestamp", "node_id", "result"])

            # Reset all per-round state in-place
            edhoc_state.update({
                "initiator": None, "prev_initiator": None, "msg1": None,
                "sessions": {}, "last_msg1_sent": 0.0, "pending_msg3": {},
            })
            node_state.update({"joined": set(), "edhoc_done": set(), "attest_done_nodes": set()})
            eval_state.update({"t0": None, "done": False, "writer": writer, "run": run, "accepting_results": False})

            print(f"\n{'#'*62}")
            if is_warmup:
                print(f"# [EVAL] {warmup_label}  (warm-up — results not recorded)")
            else:
                print(f"# [EVAL] Run {warmup_label}  →  {csv_path}")
            print(f"{'#'*62}\n")

            # Send new msg1 BEFORE rebooting so the gateway beacon carries the new
            # msg1 the moment nodes come back.  If reboot is sent first, the stale msg1
            # remains in the beacon during reboot_wait; rebooted nodes process it and
            # their msg2 is rejected with "no matching session" in the next round.
            initiator, msg1 = _init_edhoc(mari)
            edhoc_state["initiator"] = initiator
            edhoc_state["msg1"] = msg1

            t0 = time.time()
            edhoc_state["last_msg1_sent"] = t0
            mari.send_edhoc(EDHOC_MSG1, None, msg1)
            eval_state["t0"] = t0
            eval_state["accepting_results"] = True
            writer.writerow(["t0", f"{t0:.6f}", "", ""])
            eval_file.flush()
            t0_wall = datetime.fromtimestamp(t0).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[EVAL] T0 = {t0_wall}  msg1 broadcast ({len(msg1)} B)")

            # Reboot all connected nodes — they rejoin with the new msg1 already in
            # the beacon.  Round 1: harmless (no nodes connected yet).
            mari.send_reboot_all()
            if reboot_wait > 0:
                print(f"[EVAL] Reboot sent — waiting {reboot_wait:.0f}s for nodes to restart...")
                time.sleep(reboot_wait)
            print(f"[EVAL] Reboot wait done — round {run} active  (target={target_nodes}, timeout={round_timeout:.0f}s)")

            last_flush = 0.0

            while not eval_state["done"]:
                mari.update()
                now = time.time()

                if round_timeout > 0 and now - t0 >= round_timeout:
                    attested = len(node_state["attest_done_nodes"])
                    print(f"[EVAL] Round {run} TIMEOUT after {round_timeout:.0f}s — {attested}/{target_nodes} attested")
                    writer.writerow(["timeout", f"{now:.6f}", "", f"{attested}/{target_nodes}"])
                    eval_state["accepting_results"] = False
                    eval_state["done"] = True
                    break

                if now - last_flush >= 2.0:
                    eval_file.flush()
                    last_flush = now

                # Retry msg3 for nodes that haven't completed EDHOC yet
                for node_id, (msg3, last_sent, retry_count) in list(edhoc_state["pending_msg3"].items()):
                    if node_id not in node_state["joined"]:
                        edhoc_state["pending_msg3"].pop(node_id, None)
                        continue
                    if retry_count >= MSG3_MAX_RETRIES:
                        edhoc_state["pending_msg3"].pop(node_id, None)
                        continue
                    if now - last_sent >= MSG3_RETRY_INTERVAL:
                        mari.send_edhoc(EDHOC_MSG3, node_id, msg3)
                        edhoc_state["pending_msg3"][node_id] = (msg3, now, retry_count + 1)

                # Rotate msg1 periodically for forward secrecy
                if now - edhoc_state["last_msg1_sent"] >= EDHOC_MSG1_RESEND_INTERVAL:
                    initiator, msg1 = _init_edhoc(mari)
                    edhoc_state["prev_initiator"] = edhoc_state["initiator"]
                    edhoc_state["initiator"] = initiator
                    edhoc_state["msg1"] = msg1
                    mari.send_edhoc(EDHOC_MSG1, None, msg1)
                    edhoc_state["last_msg1_sent"] = now

                # In single-run mode without --auto-exit, loop forever (Ctrl+C to stop)
                if not exit_on_done and eval_state["done"]:
                    break

                time.sleep(0.001)

            eval_file.flush()
            eval_file.close()

            if run < runs:
                label = "Warm-up" if is_warmup else f"Round {run}"
                print(f"[EVAL] {label} complete — starting next round immediately.")

    except KeyboardInterrupt:
        pass
    finally:
        mari.close_tui()
        mari.logger.close()

    if runs > 1:
        stem, ext = os.path.splitext(eval_log)
        print(f"\n[EVAL] All {runs} runs done. CSVs saved as {stem}_001{ext or '.csv'} … {stem}_{runs:03d}{ext or '.csv'}")
        print(f"[EVAL] Plot with:  python plot_avg_cdf.py {os.path.dirname(eval_log) or '.'}/")


if __name__ == "__main__":
    main()
