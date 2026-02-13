"""Multi-Plugin Host — Manages N plugin binaries with cap-based routing.

The PluginHost is the host-side runtime that manages all communication with
plugin processes. It handles:

- Plugin registration for on-demand spawning
- Plugin attachment for pre-connected plugins
- HELLO handshake and limit negotiation
- Cap-based request routing (REQ → correct plugin)
- Request continuation routing (STREAM_START/CHUNK/STREAM_END/END → by req_id)
- Heartbeat handling (local, not forwarded)
- Plugin death detection with pending request ERR
- Aggregate capability advertisement

This matches the Rust PluginHostRuntime and Go PluginHost architectures exactly.

Usage:
```python
from capns.plugin_host_runtime import PluginHost

host = PluginHost()
host.register_plugin("/path/to/plugin", ["cap:op=convert"])
host.run(relay_reader, relay_writer, resource_fn=lambda: b"")
```
"""

import json
import subprocess
import threading
import queue
from typing import Optional, List, Callable
from dataclasses import dataclass

from capns.cbor_frame import Frame, FrameType, Limits
from capns.cbor_io import (
    FrameReader,
    FrameWriter,
    handshake,
    CborError,
)
from capns.cap_urn import CapUrn, CapUrnError


# =========================================================================
# Error types
# =========================================================================

class AsyncHostError(Exception):
    """Base error for plugin host"""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class CborErrorWrapper(AsyncHostError):
    """CBOR error wrapper"""
    pass


class IoError(AsyncHostError):
    """I/O error"""
    pass


class PluginError(AsyncHostError):
    """Plugin returned error"""

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.error_message = message


class UnexpectedFrameType(AsyncHostError):
    """Unexpected frame type"""

    def __init__(self, frame_type: FrameType):
        super().__init__(f"Unexpected frame type: {frame_type}")
        self.frame_type = frame_type


class ProcessExited(AsyncHostError):
    """Plugin process exited unexpectedly"""

    def __init__(self):
        super().__init__("Plugin process exited unexpectedly")


class Handshake(AsyncHostError):
    """Handshake failed"""
    pass


class Closed(AsyncHostError):
    """Host is closed"""

    def __init__(self):
        super().__init__("Host is closed")


class SendError(AsyncHostError):
    """Send error: channel closed"""

    def __init__(self):
        super().__init__("Send error: channel closed")


class RecvError(AsyncHostError):
    """Receive error: channel closed"""

    def __init__(self):
        super().__init__("Receive error: channel closed")


class Protocol(AsyncHostError):
    """Generic protocol violation"""
    pass


# =========================================================================
# Response types (used by test harnesses and interop)
# =========================================================================

@dataclass
class ResponseChunk:
    """A response chunk from a plugin"""
    payload: bytes
    seq: int
    offset: Optional[int]
    len: Optional[int]
    is_eof: bool


class PluginResponse:
    """A complete response from a plugin, which may be single or streaming"""

    def __init__(self, chunks: List[ResponseChunk]):
        """Create from list of chunks"""
        self.chunks = chunks

    @staticmethod
    def single(data: bytes) -> "PluginResponse":
        """Create single response"""
        chunk = ResponseChunk(payload=data, seq=0, offset=None, len=None, is_eof=True)
        return PluginResponse([chunk])

    @staticmethod
    def streaming(chunks: List[ResponseChunk]) -> "PluginResponse":
        """Create streaming response"""
        return PluginResponse(chunks)

    def is_single(self) -> bool:
        """Check if this is a single response"""
        return len(self.chunks) == 1 and self.chunks[0].seq == 0

    def is_streaming(self) -> bool:
        """Check if this is a streaming response"""
        return not self.is_single()

    def final_payload(self) -> Optional[bytes]:
        """Get the final chunk's payload (last chunk of streaming, or single payload)"""
        if not self.chunks:
            return None
        return self.chunks[-1].payload

    def concatenated(self) -> bytes:
        """Concatenate all payloads into a single buffer"""
        if self.is_single():
            return self.chunks[0].payload

        result = bytearray()
        for chunk in self.chunks:
            result.extend(chunk.payload)
        return bytes(result)


def cbor_decode_response(response: PluginResponse) -> PluginResponse:
    """CBOR-decode the raw payload from a PluginResponse.

    Plugin emitters CBOR-encode each emission as a CBOR byte string.
    This function decodes the concatenated CBOR values and returns a new
    PluginResponse with decoded payloads.

    Raises on malformed CBOR — no silent fallbacks.
    """
    import io
    import cbor2

    raw = response.concatenated()
    if not raw:
        return PluginResponse.single(b"")

    decoded_chunks = []
    stream = io.BytesIO(raw)
    seq = 0
    while stream.tell() < len(raw):
        value = cbor2.CBORDecoder(stream).decode()
        if isinstance(value, bytes):
            payload = value
        elif isinstance(value, str):
            payload = value.encode("utf-8")
        elif isinstance(value, (int, float, bool, list, dict)):
            payload = json.dumps(value).encode("utf-8")
        elif value is None:
            payload = b"null"
        else:
            raise ValueError(
                f"Cannot decode CBOR value of type {type(value).__name__} to bytes"
            )
        decoded_chunks.append(ResponseChunk(
            payload=payload, seq=seq, offset=None, len=None, is_eof=False
        ))
        seq += 1

    if not decoded_chunks:
        raise ValueError("No CBOR values found in response payload")

    decoded_chunks[-1].is_eof = True

    if len(decoded_chunks) == 1:
        return PluginResponse.single(decoded_chunks[0].payload)
    return PluginResponse.streaming(decoded_chunks)


# =========================================================================
# Internal types
# =========================================================================

@dataclass
class _PluginEvent:
    """Internal event from a plugin reader thread."""
    plugin_idx: int
    frame: Optional[Frame]  # None = death
    is_death: bool


@dataclass
class _CapTableEntry:
    """Maps a cap URN to a plugin index."""
    cap_urn: str
    plugin_idx: int


@dataclass
class _RoutingEntry:
    """Tracks a routed request with its original MessageId."""
    plugin_idx: int
    msg_id: object  # MessageId


class _ManagedPlugin:
    """A plugin managed by the PluginHost."""

    def __init__(self, path: str = "", known_caps: Optional[List[str]] = None):
        self.path = path
        self.process: Optional[subprocess.Popen] = None
        self.writer: Optional[FrameWriter] = None
        self.writer_queue: Optional[queue.Queue] = None
        self.manifest: bytes = b""
        self.limits: Limits = Limits.default()
        self.caps: List[str] = []
        self.known_caps: List[str] = known_caps or []
        self.running: bool = False
        self.hello_failed: bool = False


# =========================================================================
# PluginHost — multi-plugin relay-based host
# =========================================================================

class PluginHost:
    """Manages N plugin binaries with cap-based routing.

    Plugins are either registered (for on-demand spawning) or attached
    (pre-connected). REQ frames from the relay are routed to the correct
    plugin by cap URN. Continuation frames (STREAM_START, CHUNK,
    STREAM_END, END) are routed by request ID.

    Matches the Rust PluginHostRuntime and Go PluginHost architectures.
    """

    def __init__(self):
        self._plugins: List[_ManagedPlugin] = []
        self._cap_table: List[_CapTableEntry] = []
        self._request_routing: dict = {}  # req_id_str → _RoutingEntry
        self._peer_requests: dict = {}  # req_id_str → True (plugin-initiated)
        self._capabilities: Optional[bytes] = None
        self._event_queue: queue.Queue = queue.Queue(maxsize=256)
        self._lock = threading.Lock()

    def register_plugin(self, path: str, known_caps: List[str]) -> None:
        """Register a plugin binary for on-demand spawning.

        The plugin is not spawned until a REQ arrives for one of its known caps.

        Args:
            path: Path to the plugin binary
            known_caps: List of cap URNs this plugin is expected to handle
        """
        with self._lock:
            plugin_idx = len(self._plugins)
            self._plugins.append(_ManagedPlugin(path=path, known_caps=known_caps))

            for cap in known_caps:
                self._cap_table.append(_CapTableEntry(cap_urn=cap, plugin_idx=plugin_idx))

    def attach_plugin(self, plugin_stdout, plugin_stdin) -> int:
        """Attach a pre-connected plugin (already running).

        Performs HELLO handshake immediately and returns the plugin index.

        Args:
            plugin_stdout: Plugin's stdout stream (host reads from this)
            plugin_stdin: Plugin's stdin stream (host writes to this)

        Returns:
            Plugin index

        Raises:
            AsyncHostError: If handshake fails
        """
        reader = FrameReader(plugin_stdout)
        writer = FrameWriter(plugin_stdin)

        try:
            result = handshake(reader, writer)
        except Exception as e:
            raise Handshake(f"handshake failed: {e}")

        caps = _parse_caps_from_manifest(result.manifest)

        with self._lock:
            plugin_idx = len(self._plugins)

            writer_q = queue.Queue(maxsize=64)
            plugin = _ManagedPlugin()
            plugin.writer = writer
            plugin.writer_queue = writer_q
            plugin.manifest = result.manifest
            plugin.limits = result.limits
            plugin.caps = caps
            plugin.running = True

            self._plugins.append(plugin)

            for cap in caps:
                self._cap_table.append(_CapTableEntry(cap_urn=cap, plugin_idx=plugin_idx))
            self._rebuild_capabilities()

        # Start reader and writer threads
        threading.Thread(
            target=self._writer_loop, args=(writer, writer_q),
            daemon=True
        ).start()
        threading.Thread(
            target=self._reader_loop, args=(plugin_idx, reader),
            daemon=True
        ).start()

        return plugin_idx

    def capabilities(self) -> Optional[bytes]:
        """Return the aggregate capabilities of all running plugins as JSON."""
        with self._lock:
            return self._capabilities

    def find_plugin_for_cap(self, cap_urn: str) -> Optional[int]:
        """Find the plugin index that can handle a given cap URN.

        Returns plugin index if found, None if not.
        """
        with self._lock:
            return self._find_plugin_for_cap_locked(cap_urn)

    def _find_plugin_for_cap_locked(self, cap_urn: str) -> Optional[int]:
        """Find plugin for cap (caller must hold lock)."""
        # Exact string match first
        for entry in self._cap_table:
            if entry.cap_urn == cap_urn:
                return entry.plugin_idx

        # URN-level matching: request is pattern, registered cap is instance
        try:
            request_urn = CapUrn.from_string(cap_urn)
        except CapUrnError:
            return None

        for entry in self._cap_table:
            try:
                registered_urn = CapUrn.from_string(entry.cap_urn)
            except CapUrnError:
                continue
            if request_urn.accepts(registered_urn):
                return entry.plugin_idx

        return None

    def run(self, relay_read, relay_write, resource_fn: Optional[Callable] = None) -> None:
        """Run the main event loop, reading from relay and plugins.

        Blocks until relay closes or a fatal error occurs.

        Args:
            relay_read: Relay stdout stream (host reads from this)
            relay_write: Relay stdin stream (host writes to this)
            resource_fn: Optional function returning resource state bytes
        """
        relay_reader = FrameReader(relay_read)
        relay_writer = FrameWriter(relay_write)

        relay_queue = queue.Queue(maxsize=64)
        relay_done = threading.Event()
        relay_error = [None]

        def relay_reader_thread():
            try:
                while True:
                    frame = relay_reader.read()
                    if frame is None:
                        relay_done.set()
                        return
                    relay_queue.put(frame)
            except Exception as e:
                relay_error[0] = e
                relay_done.set()

        threading.Thread(target=relay_reader_thread, daemon=True).start()

        while True:
            # Check relay done
            if relay_done.is_set() and relay_queue.empty():
                self._kill_all_plugins()
                if relay_error[0] is not None:
                    raise IoError(str(relay_error[0]))
                return

            # Try to get a relay frame or plugin event (non-blocking check both)
            try:
                frame = relay_queue.get(timeout=0.01)
                self._handle_relay_frame(frame, relay_writer)
                continue
            except queue.Empty:
                pass

            try:
                event = self._event_queue.get_nowait()
                if event.is_death:
                    self._handle_plugin_death(event.plugin_idx, relay_writer)
                elif event.frame is not None:
                    self._handle_plugin_frame(event.plugin_idx, event.frame, relay_writer)
            except queue.Empty:
                pass

    def _handle_relay_frame(self, frame: Frame, relay_writer: FrameWriter) -> None:
        """Route an incoming frame from the relay to the correct plugin."""
        with self._lock:
            id_key = frame.id.to_string() if hasattr(frame.id, 'to_string') else str(frame.id)

            if frame.frame_type == FrameType.REQ:
                cap_urn = frame.cap or ""

                plugin_idx = self._find_plugin_for_cap_locked(cap_urn)
                if plugin_idx is None:
                    err_frame = Frame.err(frame.id, "NO_HANDLER", f"no plugin handles cap: {cap_urn}")
                    relay_writer.write(err_frame)
                    return

                plugin = self._plugins[plugin_idx]
                if not plugin.running:
                    if plugin.hello_failed:
                        err_frame = Frame.err(frame.id, "SPAWN_FAILED", "plugin previously failed to start")
                        relay_writer.write(err_frame)
                        return
                    err = self._spawn_plugin_locked(plugin_idx)
                    if err is not None:
                        err_frame = Frame.err(frame.id, "SPAWN_FAILED", str(err))
                        relay_writer.write(err_frame)
                        return

                self._request_routing[id_key] = _RoutingEntry(plugin_idx=plugin_idx, msg_id=frame.id)
                self._send_to_plugin(plugin_idx, frame)

            elif frame.frame_type in (FrameType.STREAM_START, FrameType.CHUNK, FrameType.STREAM_END):
                entry = self._request_routing.get(id_key)
                if entry is not None:
                    self._send_to_plugin(entry.plugin_idx, frame)

            elif frame.frame_type in (FrameType.END, FrameType.ERR):
                entry = self._request_routing.get(id_key)
                if entry is not None:
                    self._send_to_plugin(entry.plugin_idx, frame)
                    is_terminal = True
                    # Only remove routing on terminal frames if this is a PEER response
                    # (engine responding to a plugin's peer invoke). For engine-initiated
                    # requests, the relay END is just the end of the request body — the
                    # plugin still needs to respond, so routing must survive.
                    if is_terminal and id_key in self._peer_requests:
                        self._request_routing.pop(id_key, None)
                        self._peer_requests.pop(id_key, None)

            elif frame.frame_type == FrameType.HEARTBEAT:
                # Engine-level heartbeat — not forwarded to plugins
                return

            elif frame.frame_type == FrameType.HELLO:
                raise Protocol("unexpected HELLO from relay")

            elif frame.frame_type in (FrameType.RELAY_NOTIFY, FrameType.RELAY_STATE):
                raise Protocol(f"relay frame {frame.frame_type} reached plugin host")

    def _handle_plugin_frame(self, plugin_idx: int, frame: Frame, relay_writer: FrameWriter) -> None:
        """Process a frame from a plugin."""
        with self._lock:
            id_key = frame.id.to_string() if hasattr(frame.id, 'to_string') else str(frame.id)

            if frame.frame_type == FrameType.HEARTBEAT:
                # Respond to plugin heartbeat locally — don't forward
                response = Frame.heartbeat(frame.id)
                self._send_to_plugin(plugin_idx, response)

            elif frame.frame_type == FrameType.HELLO:
                # HELLO post-handshake — protocol violation, ignore
                return

            elif frame.frame_type == FrameType.REQ:
                # Plugin is invoking a peer cap (sending request to engine)
                self._request_routing[id_key] = _RoutingEntry(plugin_idx=plugin_idx, msg_id=frame.id)
                self._peer_requests[id_key] = True
                relay_writer.write(frame)

            elif frame.frame_type == FrameType.LOG:
                relay_writer.write(frame)

            elif frame.frame_type in (FrameType.STREAM_START, FrameType.CHUNK, FrameType.STREAM_END):
                relay_writer.write(frame)

            elif frame.frame_type == FrameType.END:
                relay_writer.write(frame)
                if id_key not in self._peer_requests:
                    self._request_routing.pop(id_key, None)

            elif frame.frame_type == FrameType.ERR:
                relay_writer.write(frame)
                self._request_routing.pop(id_key, None)
                self._peer_requests.pop(id_key, None)

    def _handle_plugin_death(self, plugin_idx: int, relay_writer: FrameWriter) -> None:
        """Process a plugin death event."""
        with self._lock:
            plugin = self._plugins[plugin_idx]
            plugin.running = False

            if plugin.writer_queue is not None:
                # Signal writer to stop
                plugin.writer_queue.put(None)
                plugin.writer_queue = None

            if plugin.process is not None:
                try:
                    plugin.process.kill()
                except Exception:
                    pass
                plugin.process = None

            # Send ERR for all pending requests routed to this plugin
            failed_keys = []
            failed_entries = []
            for req_id, entry in self._request_routing.items():
                if entry.plugin_idx == plugin_idx:
                    failed_keys.append(req_id)
                    failed_entries.append(entry)

            for i, key in enumerate(failed_keys):
                err_frame = Frame.err(
                    failed_entries[i].msg_id,
                    "PLUGIN_DIED",
                    f"plugin {plugin_idx} died"
                )
                try:
                    relay_writer.write(err_frame)
                except Exception:
                    pass  # Relay might already be gone
                del self._request_routing[key]
                self._peer_requests.pop(key, None)

            self._update_cap_table()
            self._rebuild_capabilities()

    def _send_to_plugin(self, plugin_idx: int, frame: Frame) -> None:
        """Send a frame to a plugin via its writer queue."""
        plugin = self._plugins[plugin_idx]
        if plugin.writer_queue is not None:
            try:
                plugin.writer_queue.put_nowait(frame)
            except queue.Full:
                pass  # Plugin probably dead, frame dropped

    def _writer_loop(self, writer: FrameWriter, q: queue.Queue) -> None:
        """Writer thread — reads frames from queue and writes to plugin."""
        while True:
            frame = q.get()
            if frame is None:  # Shutdown sentinel
                return
            try:
                writer.write(frame)
            except Exception:
                return

    def _reader_loop(self, plugin_idx: int, reader: FrameReader) -> None:
        """Reader thread — reads frames from plugin and sends events."""
        while True:
            try:
                frame = reader.read()
                if frame is None:
                    self._event_queue.put(_PluginEvent(
                        plugin_idx=plugin_idx, frame=None, is_death=True
                    ))
                    return
                self._event_queue.put(_PluginEvent(
                    plugin_idx=plugin_idx, frame=frame, is_death=False
                ))
            except Exception:
                self._event_queue.put(_PluginEvent(
                    plugin_idx=plugin_idx, frame=None, is_death=True
                ))
                return

    def _spawn_plugin_locked(self, plugin_idx: int) -> Optional[str]:
        """Spawn a registered plugin process (caller must hold lock).

        Returns None on success, error message string on failure.
        """
        plugin = self._plugins[plugin_idx]

        if not plugin.path:
            plugin.hello_failed = True
            return "plugin has no path"

        try:
            proc = subprocess.Popen(
                [plugin.path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            plugin.hello_failed = True
            return f"failed to start plugin: {e}"

        plugin.process = proc

        reader = FrameReader(proc.stdout)
        writer = FrameWriter(proc.stdin)

        try:
            result = handshake(reader, writer)
        except Exception as e:
            plugin.hello_failed = True
            try:
                proc.kill()
            except Exception:
                pass
            return f"handshake failed: {e}"

        try:
            caps = _parse_caps_from_manifest(result.manifest)
        except Exception as e:
            plugin.hello_failed = True
            try:
                proc.kill()
            except Exception:
                pass
            return f"failed to parse manifest: {e}"

        plugin.manifest = result.manifest
        plugin.limits = result.limits
        plugin.caps = caps
        plugin.running = True
        plugin.writer = writer

        writer_q = queue.Queue(maxsize=64)
        plugin.writer_queue = writer_q

        self._update_cap_table()
        self._rebuild_capabilities()

        threading.Thread(
            target=self._writer_loop, args=(writer, writer_q),
            daemon=True
        ).start()
        threading.Thread(
            target=self._reader_loop, args=(plugin_idx, reader),
            daemon=True
        ).start()

        return None

    def _update_cap_table(self) -> None:
        """Rebuild the cap table from all plugins."""
        self._cap_table = []
        for idx, plugin in enumerate(self._plugins):
            if plugin.hello_failed:
                continue
            caps = plugin.known_caps
            if plugin.running and len(plugin.caps) > 0:
                caps = plugin.caps
            for cap in caps:
                self._cap_table.append(_CapTableEntry(cap_urn=cap, plugin_idx=idx))

    def _rebuild_capabilities(self) -> None:
        """Rebuild the aggregate capabilities JSON."""
        all_caps = []
        for plugin in self._plugins:
            if plugin.running:
                all_caps.extend(plugin.caps)

        if not all_caps:
            self._capabilities = None
            return

        self._capabilities = json.dumps({"caps": all_caps}).encode("utf-8")

    def _kill_all_plugins(self) -> None:
        """Stop all managed plugins."""
        with self._lock:
            for plugin in self._plugins:
                if plugin.writer_queue is not None:
                    plugin.writer_queue.put(None)
                    plugin.writer_queue = None
                if plugin.process is not None:
                    try:
                        plugin.process.kill()
                    except Exception:
                        pass
                plugin.running = False


# =========================================================================
# Helpers
# =========================================================================

def _parse_caps_from_manifest(manifest: bytes) -> List[str]:
    """Parse cap URNs from a JSON manifest.

    Expected format: {"caps": [{"urn": "cap:op=test", ...}, ...]}
    """
    if not manifest:
        return []

    parsed = json.loads(manifest)
    caps = []
    for cap in parsed.get("caps", []):
        urn = cap.get("urn", "")
        if urn:
            caps.append(urn)
    return caps
