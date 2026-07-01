import csv
import time
import queue
import threading
from datetime import datetime

import click
from marilib.mari_protocol import MARI_BROADCAST_ADDRESS, MARI_NET_ID_DEFAULT, DefaultPayload, Frame
from marilib.marilib_cloud import MarilibCloud
from marilib.model import EdgeEvent, GatewayInfo, MariNode
from marilib.communication_adapter import MQTTAdapter
from marilib.tui_cloud import MarilibTUICloud
from marilib.logger import MetricsLogger

from marilib.marilib_attest_verifier import mr_swarm_verification_result_edhoc

NORMAL_DATA_PAYLOAD = b"NORMAL_APP_DATA"
mari_instance = None

verification_queue = queue.Queue()
verification_stats = {
    'received': 0,
    'processed': 0,
    'succeeded': 0,
    'failed': 0,
    'ignored': 0
}

def is_attestation_request(payload):
    """Check if payload is an EDHOC attestation request (0xE4 tag)."""
    return len(payload) >= 1 and payload[0] == 0xE4

def on_event(event: EdgeEvent, event_data: MariNode | Frame | GatewayInfo):
    """An event handler for the application."""
    global mari_instance, verification_stats

    if event == EdgeEvent.NODE_DATA:
        frame: Frame = event_data
        h = frame.header
        p = frame.payload

        if not is_attestation_request(p):
            verification_stats['ignored'] += 1
            return

        verification_stats['received'] += 1
        verification_queue.put(frame)
        print(f"[VERIFIER] Received from node=0x{h.source:016X}, payload={len(p)} B, queue_size={verification_queue.qsize()}")

@click.command()
@click.option("--mqtt-url", "-m", type=str, default="mqtt://localhost:1883", show_default=True, help="MQTT broker to use")
@click.option("--network-id", "-n", type=lambda x: int(x, 16), default=MARI_NET_ID_DEFAULT, help=f"Network ID to use [default: 0x{MARI_NET_ID_DEFAULT:04X}]")
@click.option("--send-periodic", "-s", type=float, default=0, show_default=True, help="Send periodic packet every N seconds (0 = disabled)")
@click.option("--log-dir", default="logs", show_default=True, help="Directory to save metric log files.", type=click.Path())
@click.option("--target-nodes", "-N", type=int, default=100, show_default=True, help="Target number of nodes for evaluation")
def main(mqtt_url: str, network_id: int, send_periodic: float, log_dir: str, target_nodes: int):
    """A basic example of using the MariLibCloud library."""
    global mari_instance

    print(f"[VERIFIER] Starting verifier for network 0x{network_id:04X}, target={target_nodes} nodes")

    mari_instance = MarilibCloud(
        on_event,
        mqtt_interface=MQTTAdapter.from_url(mqtt_url, is_edge=False),
        logger=MetricsLogger(
            log_dir_base=log_dir, rotation_interval_minutes=1440, log_interval_seconds=1.0
        ),
        tui=MarilibTUICloud(),
        network_id=network_id,
        main_file=__file__,
    )

    def verification_worker():
        """Worker thread that processes verification requests one by one."""
        while True:
            try:
                frame = verification_queue.get(timeout=1.0)
                node_id = frame.header.source
                payload = frame.payload
                print(f"[VERIFIER] Processing attestation from node=0x{node_id:016X}, payload={len(payload)} B")
                try:
                    result = mr_swarm_verification_result_edhoc(payload)
                    verification_stats['processed'] += 1
                    if result:
                        verification_stats['succeeded'] += 1
                    else:
                        verification_stats['failed'] += 1

                    # Send result back to edge for logging and kick-on-fail
                    if mari_instance.mqtt_interface is not None:
                        mari_instance.send_attest_result(node_id, result)

                    s = verification_stats
                    print(f"[VERIFIER] Summary: {s['processed']} evaluated, {s['succeeded']} succeeded, {s['failed']} failed (of {s['received']} received)")
                except Exception as e:
                    print(f"ERROR processing node=0x{node_id:04X}: {e}")
                    verification_stats['failed'] += 1
                finally:
                    verification_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")

    worker_thread = threading.Thread(target=verification_worker, daemon=True)
    worker_thread.start()
    print("[VERIFIER] Worker thread started, waiting for attestation requests...")

    try:
        while True:
            mari_instance.update()
            mari_instance.render_tui()
            time.sleep(0.01)
    except KeyboardInterrupt:
        s = verification_stats
        print(f"\n[VERIFIER] Shutting down. Final stats:")
        print(f"  - Attestation requests received : {s['received']}")
        print(f"  - Evaluated                     : {s['processed']}")
        print(f"  - Succeeded                     : {s['succeeded']}")
        print(f"  - Failed                        : {s['failed']}")
        print(f"  - Non-attestation ignored       : {s['ignored']}")
        print(f"  - Queue remaining               : {verification_queue.qsize()}")
    finally:
        mari_instance.close_tui()
        mari_instance.logger.close()


if __name__ == "__main__":
    main()
