from abc import ABC, abstractmethod

from marilib.model import MariNode


class MarilibBase(ABC):
    """Base class for Marilib applications."""

    @abstractmethod
    def update(self):
        """Recurrent bookkeeping; call periodically from your main loop."""

    @abstractmethod
    def nodes(self) -> list[MariNode]:
        """Returns all nodes in the network."""

    @abstractmethod
    def add_node(self, address: int, gateway_address: int = None) -> MariNode | None:
        """Adds a node to the network."""

    @abstractmethod
    def remove_node(self, address: int) -> MariNode | None:
        """Removes a node from the network."""

    @abstractmethod
    def send_frame(self, dst: int, payload: bytes):
        """Sends a frame to the network."""

    @abstractmethod
    def render_tui(self):
        """Renders the TUI."""

    @abstractmethod
    def close_tui(self):
        """Closes the TUI."""
