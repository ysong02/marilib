"""Generates a NODE_DATA frame for [destination] (default: broadcast); pipe hex output to mosquitto_pub to send it."""

from marilib.mari_protocol import Frame, Header, MARI_BROADCAST_ADDRESS, MetricsProbePayload
from marilib.model import EdgeEvent
from rich import print
import sys

destination = sys.argv[1] if len(sys.argv) > 1 else MARI_BROADCAST_ADDRESS

header = Header(destination=destination)
frame = Frame(header=header, payload=b"NORMAL_APP_DATA")
print(frame)
frame_to_send = EdgeEvent.to_bytes(EdgeEvent.NODE_DATA) + frame.to_bytes()
print(frame_to_send.hex())

probe_payload = MetricsProbePayload()
print(probe_payload.packet_length, probe_payload)
print(probe_payload.to_bytes().hex())
