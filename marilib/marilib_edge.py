import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from rich import print
import cbor2

from marilib.metrics import MetricsTester
from marilib.mari_protocol import (
    MARI_BROADCAST_ADDRESS,
    Frame,
    Header,
    DefaultPayload,
    DefaultPayloadType,
)

# EDHOC subtype for MSG4 (mirror of MARI_EDHOC_SUBTYPE_MSG4 in models.h)
_EDHOC_MSG4 = 4
from marilib.model import (
    EdgeEvent,
    GatewayInfo,
    MariGateway,
    MariNode,
    NodeInfoEdge,
    SCHEDULES,
)
from marilib.protocol import ProtocolPayloadParserException
from marilib.communication_adapter import MQTTAdapter, MQTTAdapterDummy, SerialAdapter
from marilib.marilib import MarilibBase
from marilib.tui_edge import MarilibTUIEdge
# for attestation
# from marilib.marilib_attest_rp import mr_is_attest_verif_resp, mr_process_attest_verif_resp

@dataclass
class MarilibEdge(MarilibBase):
    """
    The MarilibEdge class runs in either a computer or a raspberry pi.
    It is used to communicate with:
    - a Mari radio gateway (nRF5340) via serial
    - a Mari cloud instance via MQTT (optional)
    """

    cb_application: Callable[[EdgeEvent, MariNode | Frame], None]
    serial_interface: SerialAdapter
    mqtt_interface: MQTTAdapter | None = None
    tui: MarilibTUIEdge | None = None

    logger: Any | None = None
    gateway: MariGateway = field(default_factory=MariGateway)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    metrics_tester: MetricsTester | None = None
    metrics_probe_period: float | None = None

    started_ts: datetime = field(default_factory=datetime.now)
    last_received_serial_data_ts: datetime = field(default_factory=datetime.now)
    last_received_mqtt_data_ts: datetime = field(default_factory=datetime.now)
    main_file: str | None = None

    def __post_init__(self):
        self.setup_params = {
            "main_file": self.main_file or "unknown",
            "serial_port": self.serial_interface.port,
        }
        if self.mqtt_interface is None:
            self.mqtt_interface = MQTTAdapterDummy()
        self.serial_interface.init(self.on_serial_data_received)
        if self.logger:
            self.logger.log_setup_parameters(self.setup_params)
        self.metrics_tester = MetricsTester(self, self.metrics_probe_period)
        self.metrics_tester.start()

    # ============================ MarilibBase methods =========================

    def update(self):
        with self.lock:
            self.gateway.update()
            if self.logger and self.logger.active:
                self.logger.log_periodic_metrics(self.gateway, self.gateway.nodes)

    @property
    def nodes(self) -> list[MariNode]:
        return self.gateway.nodes

    def add_node(self, address: int, gateway_address: int = None) -> MariNode | None:
        with self.lock:
            return self.gateway.add_node(address)

    def remove_node(self, address: int) -> MariNode | None:
        with self.lock:
            return self.gateway.remove_node(address)

    def send_frame(self, dst: int, payload: bytes):
        """Sends a frame to the gateway via serial."""
        assert self.serial_interface is not None

        mari_frame = Frame(Header(destination=dst), payload=payload)

        with self.lock:
            self.gateway.register_sent_frame(mari_frame)
            if dst == MARI_BROADCAST_ADDRESS:
                for n in self.gateway.nodes:
                    n.register_sent_frame(mari_frame)
            elif n := self.gateway.get_node(dst):
                n.register_sent_frame(mari_frame)

        self.serial_interface.send_data(
            EdgeEvent.to_bytes(EdgeEvent.NODE_DATA) + mari_frame.to_bytes()
        )

    def render_tui(self):
        if self.tui:
            self.tui.render(self)

    def close_tui(self):
        if self.tui:
            self.tui.close()

    # ============================ MarilibEdge methods =========================

    @property
    def uses_mqtt(self) -> bool:
        return not isinstance(self.mqtt_interface, MQTTAdapterDummy)

    @property
    def mqtt_connected(self) -> bool:
        return self.uses_mqtt and self.mqtt_interface.is_ready()

    @property
    def serial_connected(self) -> bool:
        return self.serial_interface is not None

    def get_max_downlink_rate(self) -> float:
        """Calculate the max downlink packets/sec for a given schedule_id."""
        schedule_params = SCHEDULES.get(self.gateway.info.schedule_id)
        if not schedule_params:
            return 0.0
        d_down = schedule_params["d_down"]
        sf_duration_ms = schedule_params["sf_duration"]
        if sf_duration_ms == 0:
            return 0.0
        return d_down / (sf_duration_ms / 1000.0)

    # ============================ Callbacks ===================================

    def on_mqtt_data_received(self, data: bytes):
        """Just forwards the data to the serial interface."""
        if len(data) < 1:
            return

        self.last_received_mqtt_data_ts = datetime.now()

        # Handle kick command from cloud verifier
        try:
            event_type = EdgeEvent(data[0])
        except ValueError:
            return

        if event_type == EdgeEvent.KICK_NODE:
            if len(data) >= 9:
                node_id = int.from_bytes(data[1:9], "little")
                self._send_kick_to_gateway(node_id)
            return

        try:
            frame = Frame().from_bytes(data[1:])
        except ProtocolPayloadParserException:
            return
        if event_type != EdgeEvent.NODE_DATA:
            return
        if frame.header.destination != MARI_BROADCAST_ADDRESS and not self.gateway.get_node(
            frame.header.destination
        ):
            return
        # # for attestation verification response (disabled)
        # if mr_is_attest_verif_resp(frame.payload):
        #     result_payload = mr_process_attest_verif_resp(frame.payload)
        #     self.send_frame(frame.header.destination, result_payload)
        # else:
        self.send_frame(frame.header.destination, frame.payload)

    def _send_kick_to_gateway(self, node_id: int):
        """Send a kick command to the gateway to remove a node from the schedule."""
        buf = bytes([EdgeEvent.KICK_NODE]) + node_id.to_bytes(8, "little")
        self.serial_interface.send_data(buf)

    def handle_serial_data(self, data: bytes) -> tuple[bool, EdgeEvent, Any]:
        """
        Handles the serial data received from the radio gateway.
        """
        if len(data) < 1:
            return False, EdgeEvent.UNKNOWN, None

        self.last_received_serial_data_ts = datetime.now()

        try:
            event_type = EdgeEvent(data[0])
        except ValueError:
            return False, EdgeEvent.UNKNOWN, None

        if event_type == EdgeEvent.NODE_JOINED:
            node_info = NodeInfoEdge().from_bytes(data[1:])
            self.add_node(node_info.address)
            return True, event_type, node_info

        elif event_type == EdgeEvent.NODE_LEFT:
            node_info = NodeInfoEdge().from_bytes(data[1:])
            if self.remove_node(node_info.address):
                return True, event_type, node_info
            else:
                return False, event_type, node_info

        elif event_type == EdgeEvent.NODE_KEEP_ALIVE:
            node_info = NodeInfoEdge().from_bytes(data[1:])
            with self.lock:
                self.gateway.update_node_liveness(node_info.address)
            return True, event_type, node_info

        elif event_type == EdgeEvent.GATEWAY_INFO:
            try:
                with self.lock:
                    self.gateway.set_info(GatewayInfo().from_bytes(data[1:]))
                return True, event_type, self.gateway.info
            except (ValueError, ProtocolPayloadParserException):
                return False, EdgeEvent.UNKNOWN, None

        elif event_type == EdgeEvent.NODE_DATA:
            try:
                frame = Frame().from_bytes(data[1:])
                with self.lock:
                    self.gateway.update_node_liveness(frame.header.source)
                    self.gateway.register_received_frame(frame)

                    # handle metrics probe packets
                    if frame.is_test_packet:
                        payload = self.metrics_tester.handle_response_edge(frame)
                        if payload:
                            frame.payload = payload.to_bytes()

                return True, event_type, frame
            except (ValueError, ProtocolPayloadParserException):
                return False, EdgeEvent.UNKNOWN, None

        elif event_type == EdgeEvent.EDHOC:
            # data: [EDHOC=6][subtype][node_id: 8 bytes][...]
            # MSG4 format: [EDHOC=6][MSG4=4][node_id: 8 bytes][asn_dl: 8 bytes][asn_ul: 8 bytes][edhoc_bytes...]
            # other subtypes: [EDHOC=6][subtype][node_id: 8 bytes][edhoc_bytes...]
            if len(data) < 10:
                return False, event_type, None
            subtype = data[1]
            node_id = int.from_bytes(data[2:10], "little")
            if subtype == _EDHOC_MSG4:
                if len(data) < 26:
                    return False, event_type, None
                asn_dl = int.from_bytes(data[10:18], "little")
                asn_ul = int.from_bytes(data[18:26], "little")
                edhoc_data = data[26:]
            else:
                asn_dl = 0
                asn_ul = 0
                edhoc_data = data[10:]
            return True, event_type, (subtype, node_id, edhoc_data, asn_dl, asn_ul)

        return False, event_type, None

    def send_edhoc(self, subtype: int, node_id: int | None, edhoc_data: bytes):
        """Sends EDHOC data to the gateway. node_id is None for msg1 (broadcast)."""
        buf = bytes([EdgeEvent.EDHOC, subtype])
        if node_id is not None:
            buf += node_id.to_bytes(8, "little")
        buf += edhoc_data
        self.serial_interface.send_data(buf)

    def send_attestation_to_cloud(self, node_id: int, asn_dl: int, asn_ul: int, evidence_cbor: bytes, attestation_binder: bytes):
        """Forwards attestation evidence extracted from EDHOC EAD4 to the cloud verifier via MQTT."""
        payload = bytes([0xE4]) + cbor2.dumps([asn_dl, asn_ul, evidence_cbor, node_id, attestation_binder])
        frame = Frame(Header(source=node_id, destination=self.gateway.info.address), payload=payload)
        data = EdgeEvent.to_bytes(EdgeEvent.NODE_DATA) + frame.to_bytes()
        self.mqtt_interface.send_data_to_cloud(data)

    def on_serial_data_received(self, data: bytes):
        res, event_type, event_data = self.handle_serial_data(data)
        if not res:
            return

        if self.logger and event_type in [EdgeEvent.NODE_JOINED, EdgeEvent.NODE_LEFT]:
            self.logger.log_event(self.gateway.info.address, event_data.address, event_type.name)
        if event_type == EdgeEvent.GATEWAY_INFO:
            self.mqtt_interface.update(event_data.network_id_str, self.on_mqtt_data_received)
            if self.logger:
                self.setup_params["schedule_name"] = self.gateway.info.schedule_name
                self.logger.log_setup_parameters(self.setup_params)

        if event_type in [EdgeEvent.NODE_JOINED, EdgeEvent.NODE_LEFT]:
            self.cb_application(event_type, event_data)

        if event_type == EdgeEvent.NODE_DATA and not event_data.is_test_packet:
            # only notify the application if it's not a test packet
            self.cb_application(event_type, event_data)

        if event_type == EdgeEvent.EDHOC:
            self.cb_application(event_type, event_data)

        self.send_data_to_cloud(event_type, event_data)

    def send_data_to_cloud(
        self, event_type: EdgeEvent, event_data: NodeInfoEdge | GatewayInfo | Frame
    ):
        if event_type == EdgeEvent.EDHOC:
            return  # EDHOC is handled locally, not forwarded to cloud
        if event_type in [EdgeEvent.NODE_JOINED, EdgeEvent.NODE_LEFT, EdgeEvent.NODE_KEEP_ALIVE]:
            event_data = event_data.to_cloud(self.gateway.info.address)
        data = EdgeEvent.to_bytes(event_type) + event_data.to_bytes()
        self.mqtt_interface.send_data_to_cloud(data)

    # ============================ Utility methods =============================

    # def metrics_test_enable(self):
    #     self.metrics_tester.start()

    def metrics_test_disable(self):
        self.metrics_tester.stop()

    # ============================ Private methods =============================

    def _is_test_packet(self, payload: bytes) -> bool:
        """Determines if a packet sent FROM the edge is for testing purposes."""
        payload = DefaultPayload().from_bytes(payload)
        return payload.type_ in [DefaultPayloadType.LOAD_TEST, DefaultPayloadType.LATENCY_TEST]
