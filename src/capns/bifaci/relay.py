"""CborRelay — Transparent CBOR frame relay with two relay-specific frame types.

The relay is a byte-stream bridge between an engine (master) and a plugin host runtime
(slave). Two relay-specific frame types are intercepted and never leaked through:

- **RelayNotify** (slave -> master): Capability advertisement from the slave's plugin host runtime.
- **RelayState** (master -> slave): Host system resources from the engine.

All other frames pass through transparently in both directions.
"""

import threading
from typing import Optional

from capns.bifaci.frame import Frame, FrameType, Limits
from capns.bifaci.io import (
    FrameReader,
    FrameWriter,
    CborError,
    HandshakeError,
    ProtocolError,
)


class RelayError(CborError):
    """Relay-specific error"""
    pass


class RelaySlave:
    """Slave endpoint of the relay. Sits inside the plugin host process.

    Bridges between a socket connection (to the RelayMaster in the engine)
    and local I/O (to/from the plugin host runtime).

    Two relay-specific frame types are intercepted and never leaked through:
    - RelayNotify (slave -> master): Capability advertisement
    - RelayState (master -> slave): Host system resources

    All other frames pass through transparently in both directions.
    """

    def __init__(self, local_reader: FrameReader, local_writer: FrameWriter):
        self._local_reader = local_reader
        self._local_writer = local_writer
        self._resource_state = b""
        self._resource_state_lock = threading.Lock()

    def resource_state(self) -> bytes:
        """Get the latest resource state payload received from the master."""
        with self._resource_state_lock:
            return bytes(self._resource_state)

    def run(
        self,
        socket_reader: FrameReader,
        socket_writer: FrameWriter,
        initial_notify: Optional[tuple] = None,
    ) -> None:
        """Run the relay bidirectionally. Blocks until one side closes or an error occurs.

        Uses two threads for true bidirectional forwarding:
        - Thread 1 (socket -> local): RelayState stored (not forwarded); others pass through
        - Thread 2 (local -> socket): RelayNotify/RelayState dropped; others pass through

        Args:
            socket_reader: Reader connected to the master relay socket
            socket_writer: Writer connected to the master relay socket
            initial_notify: Optional (manifest_bytes, limits) to send as initial RelayNotify
        """
        # Send initial RelayNotify if provided
        if initial_notify is not None:
            manifest, limits = initial_notify
            self.send_notify(socket_writer, manifest, limits)

        first_error = None
        error_lock = threading.Lock()

        def socket_to_local():
            nonlocal first_error
            try:
                while True:
                    frame = socket_reader.read()
                    if frame is None:
                        return  # Socket closed

                    if frame.frame_type == FrameType.RELAY_STATE:
                        # Intercept: store resource state, don't forward
                        if frame.payload is not None:
                            with self._resource_state_lock:
                                self._resource_state = bytes(frame.payload)
                    elif frame.frame_type == FrameType.RELAY_NOTIFY:
                        pass  # RelayNotify from master? Drop silently
                    else:
                        self._local_writer.write(frame)
            except Exception as e:
                with error_lock:
                    if first_error is None:
                        first_error = e

        def local_to_socket():
            nonlocal first_error
            try:
                while True:
                    frame = self._local_reader.read()
                    if frame is None:
                        return  # Local side closed

                    if frame.frame_type in (FrameType.RELAY_NOTIFY, FrameType.RELAY_STATE):
                        pass  # Relay frames from local side — drop
                    else:
                        socket_writer.write(frame)
            except Exception as e:
                with error_lock:
                    if first_error is None:
                        first_error = e

        t1 = threading.Thread(target=socket_to_local, daemon=True)
        t2 = threading.Thread(target=local_to_socket, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if first_error is not None:
            raise first_error

    @staticmethod
    def send_notify(socket_writer: FrameWriter, manifest: bytes, limits: Limits) -> None:
        """Send a RelayNotify frame to the socket writer.

        Used when capabilities change (plugin discovered, plugin died).

        Args:
            socket_writer: Writer connected to the master relay socket
            manifest: Aggregate manifest JSON of all available plugin capabilities
            limits: Negotiated protocol limits
        """
        frame = Frame.relay_notify(manifest, limits.max_frame, limits.max_chunk, limits.max_reorder_buffer)
        socket_writer.write(frame)


class RelayMaster:
    """Master endpoint of the relay. Sits in the engine process.

    Reads frames from the socket (from slave): RelayNotify -> update internal state; others -> return to caller.
    Can send RelayState frames to the slave.
    """

    def __init__(self, manifest: bytes, limits: Limits):
        self._manifest = manifest
        self._limits = limits

    @classmethod
    def connect(cls, socket_reader: FrameReader) -> "RelayMaster":
        """Connect to a relay slave by reading the initial RelayNotify frame.

        The slave MUST send a RelayNotify as its first frame after connection.

        Args:
            socket_reader: Reader connected to the slave relay socket

        Returns:
            Connected RelayMaster with manifest and limits from the slave

        Raises:
            RelayError: If connection fails or protocol is violated
        """
        frame = socket_reader.read()
        if frame is None:
            raise RelayError("relay connection closed before receiving RelayNotify")

        if frame.frame_type != FrameType.RELAY_NOTIFY:
            raise RelayError(f"expected RelayNotify, got {frame.frame_type}")

        manifest = frame.relay_notify_manifest()
        if manifest is None:
            raise RelayError("RelayNotify missing manifest")

        limits = frame.relay_notify_limits()
        if limits is None:
            raise RelayError("RelayNotify missing limits")

        return cls(manifest=manifest, limits=limits)

    @property
    def manifest(self) -> bytes:
        """Get the aggregate manifest from the slave."""
        return self._manifest

    @property
    def limits(self) -> Limits:
        """Get the negotiated limits from the slave."""
        return self._limits

    @staticmethod
    def send_state(socket_writer: FrameWriter, resources: bytes) -> None:
        """Send a RelayState frame to the slave with host system resource info.

        Args:
            socket_writer: Writer connected to the slave relay socket
            resources: Opaque resource payload
        """
        frame = Frame.relay_state(resources)
        socket_writer.write(frame)

    def read_frame(self, socket_reader: FrameReader) -> Optional[Frame]:
        """Read the next non-relay frame from the socket.

        RelayNotify frames are intercepted: manifest and limits are updated.
        All other frames are returned to the caller.
        Returns None on EOF.

        Args:
            socket_reader: Reader connected to the slave relay socket

        Returns:
            The next protocol frame, or None on EOF
        """
        while True:
            frame = socket_reader.read()
            if frame is None:
                return None

            if frame.frame_type == FrameType.RELAY_NOTIFY:
                # Intercept: update manifest and limits
                m = frame.relay_notify_manifest()
                if m is not None:
                    self._manifest = m
                l = frame.relay_notify_limits()
                if l is not None:
                    self._limits = l
                continue  # Don't return relay frames to caller
            elif frame.frame_type == FrameType.RELAY_STATE:
                # RelayState from slave? Protocol error — drop
                continue

            return frame
