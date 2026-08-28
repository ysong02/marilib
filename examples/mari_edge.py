import time

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

MSG3_RETRY_INTERVAL = 5.0   # seconds between msg3 retries
MSG3_MAX_RETRIES    = 10    # max msg3 retry attempts per node

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

# Msg1 rotation interval for forward secrecy; must exceed the worst-case EDHOC exchange time.
EDHOC_MSG1_RESEND_INTERVAL = 300.0


def _init_edhoc(mari: MarilibEdge) -> tuple[EdhocInitiator, bytes]:
    """Create a fresh EdhocInitiator and generate message 1 (no EAD_1)."""
    initiator = EdhocInitiator()
    msg1 = initiator.prepare_message_1(c_i=None, ead_1=None)
    return initiator, msg1


def _print_status(node_state: dict) -> None:
    # Uncomment to print a status summary after each join/leave/EDHOC event.
    # joined = node_state["joined"]
    # done   = node_state["edhoc_done"]
    # print(f"[STATUS] {len(joined)} joined, {len(done)} EDHOC complete")
    # if joined:
    #     print(f"  joined      : {', '.join(f'0x{n:016X}' for n in sorted(joined))}")
    # if done:
    #     print(f"  EDHOC done  : {', '.join(f'0x{n:016X}' for n in sorted(done))}")
    pass


def on_event(
    event: EdgeEvent,
    event_data,
    mari: MarilibEdge,
    edhoc_state: dict,
    node_state: dict,
):
    """Application event handler, extended to process EDHOC events."""
    if event == EdgeEvent.NODE_JOINED:
        node_state["joined"].add(event_data.address)
        # Clear edhoc_done on rejoin so a reconnecting node can complete EDHOC again.
        node_state["edhoc_done"].discard(event_data.address)
        # _print_status(node_state)

    elif event == EdgeEvent.NODE_LEFT:
        node_state["joined"].discard(event_data.address)
        edhoc_state["pending_msg3"].pop(event_data.address, None)
        # Do NOT clear edhoc_done: the node completed the handshake, that fact persists.
        # _print_status(node_state)

    elif event == EdgeEvent.NODE_DATA:
        pass  # application logic here

    elif event == EdgeEvent.EDHOC:
        subtype, node_id, edhoc_bytes, asn_dl, asn_ul = event_data

        if subtype == EDHOC_MSG2:
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
                except Exception:
                    pass

            if session is None:
                print(f"[EDHOC] ERROR: msg2 rejected for node 0x{node_id:016X}, no matching session")
                return

            try:
                msg3, _prk_out = session.prepare_message_3(CredentialTransfer.ByReference, None)
            except Exception as e:
                print(f"[EDHOC] ERROR: prepare_message_3 failed for node 0x{node_id:016X}: {e}")
                return

            edhoc_state["sessions"][node_id] = session
            edhoc_state["pending_msg3"][node_id] = (msg3, time.time(), 0)
            mari.send_edhoc(EDHOC_MSG3, node_id, msg3)
            print(f"[EDHOC] msg3 ({len(msg3)} B): {msg3.hex()} → node 0x{node_id:016X}")

        elif subtype == EDHOC_MSG4:
            edhoc_state["pending_msg3"].pop(node_id, None)
            session = edhoc_state["sessions"].pop(node_id, None)
            if session is None:
                # print(f"[EDHOC] ERROR: no session for node 0x{node_id:016X}, ignoring msg4")
                return
            try:
                ead_4 = session.process_message_4(edhoc_bytes)
                attestation_binder = session.edhoc_exporter(2, b'attestation', 32)
                node_state["edhoc_done"].add(node_id)
                # _print_status(node_state)

                # forward attestation evidence from EAD4 to cloud verifier
                if ead_4 is not None:
                    evidence_cbor = ead_4.value()
                    if evidence_cbor is not None:
                        attest_cbor = cbor2.dumps([asn_dl, asn_ul, evidence_cbor, node_id, attestation_binder])
                        attest_total = 1 + len(attest_cbor)  # 0xE4 tag + CBOR body
                        mari.send_attestation_to_cloud(node_id, asn_dl, asn_ul, evidence_cbor, attestation_binder)
                        print(f"[ATTEST] → verifier: node=0x{node_id:016X}, asn_dl={asn_dl}, asn_ul={asn_ul}, offset={asn_ul - asn_dl}")
                        print(f"[ATTEST]   evidence={len(evidence_cbor)} B, binder={len(attestation_binder)} B, total={attest_total} B")
                    else:
                        print(f"[ATTEST] WARNING: EAD4 present but value is empty for node 0x{node_id:016X}")
                else:
                    print(f"[ATTEST] WARNING: no EAD4 in msg4 from node 0x{node_id:016X}")
            except Exception as e:
                print(f"[EDHOC] ERROR: msg4 failed for node 0x{node_id:016X}: {e}")


@click.command()
@click.option(
    "--port",
    "-p",
    type=str,
    default=get_default_port(),
    show_default=True,
    help="Serial port to use (e.g., /dev/ttyACM0)",
)
@click.option(
    "--mqtt-url",
    "-m",
    type=str,
    default=None,
    help="MQTT broker to use (default: None, no cloud)",
)
@click.option(
    "--metrics-probe-interval",
    "-i",
    type=float,
    default=0,
    help="How often to send a metrics probe in seconds (default: 0, no metrics)",
)
@click.option(
    "--log-dir",
    default="logs",
    show_default=True,
    help="Directory to save metric log files.",
    type=click.Path(),
)
def main(port: str | None, mqtt_url: str, metrics_probe_interval: float, log_dir: str):
    """MarilibEdge example with EDHOC key exchange (edge = Initiator)."""

    edhoc_state: dict = {
        "initiator": None,
        "prev_initiator": None,  # fallback for msg2 from previous msg1
        "msg1": None,
        "sessions": {},
        "last_msg1_sent": 0.0,
        "pending_msg3": {},  # node_id → (msg3_bytes, last_sent_ts, retry_count)
    }

    node_state: dict = {
        "joined":     set(),  # node_ids currently connected to the network
        "edhoc_done": set(),  # node_ids that completed the full EDHOC handshake
    }

    def on_event_wrapper(event: EdgeEvent, event_data):
        on_event(event, event_data, mari, edhoc_state, node_state)

    mari = MarilibEdge(
        on_event_wrapper,
        serial_interface=SerialAdapter(port),
        mqtt_interface=MQTTAdapter.from_url(mqtt_url, is_edge=True) if mqtt_url else None,
        logger=MetricsLogger(
            log_dir_base=log_dir, rotation_interval_minutes=1440, log_interval_seconds=1.0
        ),
        tui=None,
        main_file=__file__,
        metrics_probe_period=metrics_probe_interval,
    )

    # Generate EDHOC msg1 and send to gateway for beacon broadcast
    initiator, msg1 = _init_edhoc(mari)
    edhoc_state["initiator"] = initiator
    edhoc_state["msg1"] = msg1
    mari.send_edhoc(EDHOC_MSG1, None, msg1)
    edhoc_state["last_msg1_sent"] = time.time()
    print(f"[EDHOC] msg1 ({len(msg1)} B): {msg1.hex()}")

    last_status_print = 0.0

    try:
        while True:
            mari.update()

            now = time.time()

            # Print a status summary every 5 seconds so progress is visible without flooding.
            if now - last_status_print >= 5.0:
                done = node_state["edhoc_done"]
                print(f"[STATUS] {len(done)} EDHOC complete")
                last_status_print = now

            # Retry msg3 for joined nodes that haven't completed EDHOC yet.
            for node_id, (msg3, last_sent, retry_count) in list(edhoc_state["pending_msg3"].items()):
                if node_id not in node_state["joined"]:
                    edhoc_state["pending_msg3"].pop(node_id, None)
                    continue
                if retry_count >= MSG3_MAX_RETRIES:
                    edhoc_state["pending_msg3"].pop(node_id, None)
                    print(f"[EDHOC] msg3 retry limit reached for node 0x{node_id:016X}, giving up")
                    continue
                if now - last_sent >= MSG3_RETRY_INTERVAL:
                    mari.send_edhoc(EDHOC_MSG3, node_id, msg3)
                    edhoc_state["pending_msg3"][node_id] = (msg3, now, retry_count + 1)
                    print(f"[EDHOC] msg3 retry #{retry_count + 1}/{MSG3_MAX_RETRIES} → node 0x{node_id:016X}")

            # Rotate msg1, keeping the previous initiator one cycle as fallback, but leave sessions alone since nodes with msg3 in flight still need to complete msg4.
            if now - edhoc_state["last_msg1_sent"] >= EDHOC_MSG1_RESEND_INTERVAL:
                initiator, msg1 = _init_edhoc(mari)
                edhoc_state["prev_initiator"] = edhoc_state["initiator"]
                edhoc_state["initiator"] = initiator
                edhoc_state["msg1"] = msg1
                mari.send_edhoc(EDHOC_MSG1, None, msg1)
                edhoc_state["last_msg1_sent"] = now
                print(f"[EDHOC] msg1 rotated ({len(msg1)} B): {msg1.hex()}")

            time.sleep(0.001)
    except KeyboardInterrupt:
        pass
    finally:
        mari.close_tui()
        mari.logger.close()


if __name__ == "__main__":
    main()
