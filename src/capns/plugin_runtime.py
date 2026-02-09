"""Plugin Runtime - Unified I/O handling for plugin binaries

The PluginRuntime provides a unified interface for plugin binaries to handle
cap invocations. Plugins register handlers for caps they provide, and the
runtime handles all I/O mechanics:

- **Automatic mode detection**: CLI mode vs Plugin CBOR mode
- CBOR frame encoding/decoding (Plugin mode)
- CLI argument parsing from cap definitions (CLI mode)
- Handler routing by cap URN
- Real-time streaming response support
- HELLO handshake for limit negotiation
- **Multiplexed concurrent request handling**

# Invocation Modes

- **No CLI arguments**: Plugin CBOR mode - HELLO handshake, REQ/RES frames via stdin/stdout
- **Any CLI arguments**: CLI mode - parse args based on cap definitions

# Example

```python
from capns import PluginRuntime, CapManifest

def main():
    manifest = build_manifest()  # Your manifest with caps
    runtime = PluginRuntime.with_manifest(manifest)

    def my_handler(request, emitter, peer):
        emitter.emit_status("processing", "Starting work...")
        # Do work, emit chunks in real-time
        emitter.emit_bytes(b"partial result")
        # Return final result
        return b"final result"

    runtime.register_raw("cap:in=*;op=my_op;out=*", my_handler)

    # runtime.run() automatically detects CLI vs Plugin CBOR mode
    runtime.run()
```
"""

import sys
import os
import json
import io
import threading
import queue
import glob
from pathlib import Path
from typing import Callable, Protocol, Optional, Dict, List, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
import cbor2

from .cbor_frame import Frame, FrameType, Limits, MessageId, DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK
from .cbor_io import handshake_accept, FrameReader, FrameWriter, CborError
from .caller import CapArgumentValue
from .cap import ArgSource, Cap, CapArg, CliFlagSource
from .cap_urn import CapUrn
from .manifest import CapManifest
from .media_urn import MediaUrn, MediaUrnError, MEDIA_FILE_PATH, MEDIA_FILE_PATH_ARRAY


class RuntimeError(Exception):
    """Errors that can occur in the plugin runtime"""
    pass


class CborRuntimeError(RuntimeError):
    """CBOR error"""
    pass


class IoRuntimeError(RuntimeError):
    """I/O error"""
    pass


class NoHandlerError(RuntimeError):
    """No handler registered for cap"""
    pass


class HandlerError(RuntimeError):
    """Handler error"""
    pass


class CapUrnError(RuntimeError):
    """Cap URN parse error"""
    pass


class DeserializeError(RuntimeError):
    """Deserialization error"""
    pass


class SerializeError(RuntimeError):
    """Serialization error"""
    pass


class PeerRequestError(RuntimeError):
    """Peer request error"""
    pass


class PeerResponseError(RuntimeError):
    """Peer response error"""
    pass


class CliError(RuntimeError):
    """CLI error"""
    pass


class MissingArgumentError(RuntimeError):
    """Missing required argument"""
    pass


class UnknownSubcommandError(RuntimeError):
    """Unknown subcommand"""
    pass


class ManifestError(RuntimeError):
    """Manifest error"""
    pass


class StreamEmitter(Protocol):
    """A streaming emitter that writes chunks immediately to the output.
    Thread-safe for use in concurrent handlers.
    All methods raise exceptions on error - no silent failures.
    """

    def emit_bytes(self, payload: bytes) -> None:
        """Emit raw bytes as a chunk immediately.
        Raises: RuntimeError on write failure."""
        ...

    def emit(self, payload: Any) -> None:
        """Emit a JSON value as a chunk.
        The value is serialized to JSON bytes and sent as the chunk payload.
        Raises: SerializeError on serialization failure, RuntimeError on write failure."""
        data = json.dumps(payload).encode('utf-8')
        self.emit_bytes(data)

    def emit_status(self, operation: str, details: str) -> None:
        """Emit a status/progress message."""
        self.emit({
            "type": "status",
            "operation": operation,
            "details": details
        })

    def log(self, level: str, message: str) -> None:
        """Emit a log message at the given level."""
        ...


class PeerInvoker(Protocol):
    """Allows handlers to invoke caps on the peer (host).

    This trait enables bidirectional communication where a plugin handler can
    invoke caps on the host while processing a request. This is essential for
    sandboxed plugins that need to delegate certain operations (like model
    downloading) to the host.

    The `invoke` method sends a REQ frame to the host and returns an iterator
    that yields response chunks as they arrive.
    """

    def invoke(self, cap_urn: str, arguments: List[CapArgumentValue]) -> Any:
        """Invoke a cap on the host with arguments.

        Sends a REQ frame to the host with the specified cap URN and arguments.
        Arguments are serialized as CBOR with native binary values.
        Returns an iterator that yields response chunks (bytes) or raises errors.

        Args:
            cap_urn: The cap URN to invoke on the host
            arguments: Arguments identified by media_urn

        Returns:
            An iterator that yields bytes for each chunk
        """
        ...


class NoPeerInvoker:
    """A no-op PeerInvoker that always returns an error.
    Used when peer invocation is not supported (CLI mode only).
    """

    def invoke(self, cap_urn: str, arguments: List[CapArgumentValue]) -> Any:
        raise PeerRequestError("Peer invocation not supported in this context")


class PendingPeerRequest:
    """Internal struct to track pending peer requests (plugin invoking host caps)."""
    def __init__(self):
        # Bounded queue for responses (buffer up to 64 chunks)
        self.queue: queue.Queue = queue.Queue(maxsize=64)


@dataclass
class PendingStream:
    """A single stream within a multiplexed request."""
    media_urn: str
    chunks: List[bytes]
    complete: bool


@dataclass
class PendingIncomingRequest:
    """Internal struct to track incoming multiplexed request streams.
    Protocol v2: Requests arrive as REQ (empty) → STREAM_START → CHUNK(s) → STREAM_END → END.
    """
    cap_urn: str
    content_type: Optional[str]
    streams: List  # List of (stream_id, PendingStream) tuples — ordered
    ended: bool  # True after END frame — any stream activity after is FATAL


class PeerInvokerImpl:
    """Implementation of PeerInvoker that sends REQ frames to the host.

    Enables bidirectional communication where a plugin handler can invoke caps
    on the host while processing a request.
    """

    def __init__(self, writer: FrameWriter, writer_lock: threading.Lock, pending_requests: Dict[str, PendingPeerRequest], max_chunk: Optional[int] = None):
        self.writer = writer
        self.writer_lock = writer_lock
        self.pending_requests = pending_requests
        self.pending_lock = threading.Lock()
        self.max_chunk = max_chunk if max_chunk is not None else DEFAULT_MAX_CHUNK

    def invoke(self, cap_urn: str, arguments: List[CapArgumentValue]) -> Any:
        """Invoke a cap on the host with arguments.

        Protocol v2: Sends REQ(empty) + STREAM_START + CHUNK(s) + STREAM_END + END
        for each argument as an independent stream.
        Returns an iterator that yields response chunks (bytes) or raises errors.
        """
        import uuid as _uuid

        request_id = MessageId.new_uuid()
        request_id_str = request_id.to_string()

        pending_req = PendingPeerRequest()

        with self.pending_lock:
            self.pending_requests[request_id_str] = pending_req

        max_chunk = self.max_chunk

        try:
            with self.writer_lock:
                # 1. REQ with empty payload
                req_frame = Frame.req(request_id, cap_urn, b"", "application/cbor")
                self.writer.write(req_frame)

                # 2. Each argument as an independent stream
                for arg in arguments:
                    stream_id = str(_uuid.uuid4())

                    # STREAM_START
                    self.writer.write(Frame.stream_start(request_id, stream_id, arg.media_urn))

                    # CHUNK(s)
                    offset = 0
                    seq = 0
                    while offset < len(arg.value):
                        chunk_size = min(len(arg.value) - offset, max_chunk)
                        chunk_data = arg.value[offset:offset + chunk_size]
                        self.writer.write(Frame.chunk(request_id, stream_id, seq, chunk_data))
                        offset += chunk_size
                        seq += 1

                    # STREAM_END
                    self.writer.write(Frame.stream_end(request_id, stream_id))

                # 3. END
                self.writer.write(Frame.end(request_id, None))

        except Exception as e:
            with self.pending_lock:
                del self.pending_requests[request_id_str]
            raise PeerRequestError(f"Failed to send peer request frames: {e}")

        return self._response_iterator(request_id_str, pending_req)

    def _response_iterator(self, request_id_str: str, pending_req: PendingPeerRequest):
        """Generator that yields response chunks from the queue."""
        while True:
            try:
                # Block waiting for response chunk
                item = pending_req.queue.get(timeout=30.0)  # 30 second timeout

                if item[0] == "ok":
                    # Got a chunk of data
                    yield item[1]
                elif item[0] == "end":
                    # Got final END frame
                    if item[1]:  # If there's final payload
                        yield item[1]
                    break
                elif item[0] == "error":
                    # Got error from host
                    raise PeerResponseError(item[1])
                else:
                    raise PeerResponseError(f"Unknown response type: {item[0]}")

            except queue.Empty:
                # Timeout waiting for response
                with self.pending_lock:
                    if request_id_str in self.pending_requests:
                        del self.pending_requests[request_id_str]
                raise PeerResponseError("Timeout waiting for host response")


class CliStreamEmitter:
    """CLI-mode emitter that writes directly to stdout.
    Used when the plugin is invoked via CLI (with arguments).
    """

    def __init__(self, ndjson: bool = True):
        """Create a new CLI emitter

        Args:
            ndjson: Whether to add newlines after each emit (NDJSON style)
        """
        self.ndjson = ndjson

    @classmethod
    def without_ndjson(cls):
        """Create a CLI emitter without NDJSON formatting"""
        return cls(ndjson=False)

    def emit_bytes(self, payload: bytes) -> None:
        stdout = sys.stdout.buffer
        stdout.write(payload)
        if self.ndjson:
            stdout.write(b'\n')
        stdout.flush()

    def emit_status(self, operation: str, details: str) -> None:
        """In CLI mode, status messages go to stderr so only the final response is on stdout.
        This allows external callers to parse stdout as a single JSON response.
        """
        status = {
            "type": "status",
            "operation": operation,
            "details": details
        }
        try:
            print(json.dumps(status), file=sys.stderr)
        except Exception:
            pass

    def log(self, level: str, message: str) -> None:
        """In CLI mode, logs go to stderr"""
        print(f"[{level.upper()}] {message}", file=sys.stderr)


class ThreadSafeEmitter:
    """Thread-safe implementation of StreamEmitter using Protocol v2 stream multiplexing.

    Automatically sends STREAM_START before the first emission, then CHUNK frames
    with stream_id. Caller MUST call finalize() after handler returns to send
    STREAM_END + END.

    All methods raise exceptions on error - no silent failures.
    """

    def __init__(self, writer: FrameWriter, request_id: MessageId, stream_id: str, media_urn: str, writer_lock: Optional[threading.Lock] = None, max_chunk: Optional[int] = None):
        self.writer = writer
        self.request_id = request_id
        self.stream_id = stream_id
        self.media_urn = media_urn
        self.seq = 0
        self.seq_lock = threading.Lock()
        self.writer_lock = writer_lock if writer_lock is not None else threading.Lock()
        self.max_chunk = max_chunk if max_chunk is not None else DEFAULT_MAX_CHUNK
        self.stream_started = False
        self.stream_lock = threading.Lock()

    def _ensure_stream_started(self) -> None:
        """Send STREAM_START if not yet sent. Must be called with seq_lock held."""
        with self.stream_lock:
            if not self.stream_started:
                self.stream_started = True
                start_frame = Frame.stream_start(self.request_id, self.stream_id, self.media_urn)
                with self.writer_lock:
                    self.writer.write(start_frame)

    def emit_bytes(self, payload: bytes) -> None:
        """CBOR-encode payload as a byte string and send as CHUNK frame(s).
        Matches Rust emit_cbor behavior — all emissions are CBOR-encoded.
        """
        self._ensure_stream_started()

        # CBOR-encode the payload as a CBOR byte string (matches Rust emit_cbor)
        cbor_payload = cbor2.dumps(payload)

        # Auto-chunk the CBOR-encoded payload
        offset = 0
        while offset < len(cbor_payload):
            chunk_size = min(self.max_chunk, len(cbor_payload) - offset)
            chunk_data = cbor_payload[offset:offset + chunk_size]
            offset += chunk_size

            with self.seq_lock:
                seq = self.seq
                self.seq += 1

            frame = Frame.chunk(self.request_id, self.stream_id, seq, chunk_data)
            with self.writer_lock:
                self.writer.write(frame)

    def finalize(self) -> None:
        """Send STREAM_END + END to complete the response.
        Must be called exactly once after the handler returns.
        If handler never emitted, sends STREAM_START first for protocol consistency.
        """
        # Ensure STREAM_START was sent (even if handler emitted nothing)
        with self.stream_lock:
            if not self.stream_started:
                self.stream_started = True
                start_frame = Frame.stream_start(self.request_id, self.stream_id, self.media_urn)
                with self.writer_lock:
                    self.writer.write(start_frame)

        # STREAM_END
        stream_end = Frame.stream_end(self.request_id, self.stream_id)
        with self.writer_lock:
            self.writer.write(stream_end)

        # END
        end_frame = Frame.end(self.request_id, None)
        with self.writer_lock:
            self.writer.write(end_frame)

    def log(self, level: str, message: str) -> None:
        frame = Frame.log(self.request_id, level, message)
        with self.writer_lock:
            self.writer.write(frame)

    def emit_status(self, operation: str, details: str) -> None:
        """Send status as LOG frame (side-channel, best-effort)."""
        try:
            message = f"{operation}: {details}"
            frame = Frame.log(self.request_id, "status", message)
            with self.writer_lock:
                self.writer.write(frame)
        except Exception:
            pass


# Handler function type
HandlerFn = Callable[[bytes, StreamEmitter, PeerInvoker], bytes]


def extract_effective_payload(
    streams: list,
    cap_urn: str
) -> bytes:
    """Extract the effective payload from accumulated request streams.

    Each stream is a (stream_id, PendingStream) tuple where PendingStream has
    media_urn and chunks. The function finds the stream whose media_urn matches
    the cap's expected input type using semantic URN matching.

    This matches the Rust plugin runtime's behavior exactly.
    """
    # Parse the cap URN to get the expected input media URN
    try:
        cap = CapUrn.from_string(cap_urn)
    except Exception as e:
        raise CapUrnError(f"Failed to parse cap URN '{cap_urn}': {e}")

    expected_input = cap.in_spec()
    try:
        expected_media_urn = MediaUrn.from_string(expected_input)
    except Exception:
        expected_media_urn = None

    # Find the stream whose media_urn matches the expected input
    for _stream_id, stream in streams:
        if not stream.complete:
            continue

        stream_data = b''.join(stream.chunks)

        if expected_media_urn is not None:
            try:
                arg_urn = MediaUrn.from_string(stream.media_urn)
                fwd = arg_urn.conforms_to(expected_media_urn)
                rev = expected_media_urn.conforms_to(arg_urn)
                if fwd or rev:
                    return stream_data
            except Exception:
                continue

    # If only one stream, return it (single-argument case)
    complete_streams = [(sid, s) for sid, s in streams if s.complete]
    if len(complete_streams) == 1:
        return b''.join(complete_streams[0][1].chunks)

    # No matching stream found
    raise DeserializeError(
        f"No stream found matching expected input media type '{expected_input}' "
        f"(streams: {[s.media_urn for _, s in streams]})"
    )


class PluginRuntime:
    """The plugin runtime that handles all I/O for plugin binaries.

    Plugins create a runtime with their manifest, register handlers for their caps,
    then call `run()` to process requests.

    The manifest is REQUIRED - plugins MUST provide their manifest which is sent
    in the HELLO response during handshake. This is the ONLY way for plugins to
    communicate their capabilities to the host.

    **Invocation Modes**:
    - No CLI args: Plugin CBOR mode (stdin/stdout binary frames)
    - Any CLI args: CLI mode (parse args from cap definitions)

    **Multiplexed execution** (CBOR mode): Multiple requests can be processed concurrently.
    Each request handler runs in its own thread, allowing the runtime to:
    - Respond to heartbeats while handlers are running
    - Accept new requests while previous ones are still processing
    - Handle multiple concurrent cap invocations
    """

    def __init__(self, manifest_data: bytes):
        """Create a new plugin runtime with the required manifest.

        The manifest is JSON-encoded plugin metadata including:
        - name: Plugin name
        - version: Plugin version
        - caps: Array of capability definitions with args and sources

        This manifest is sent in the HELLO response to the host (CBOR mode)
        and used for CLI argument parsing (CLI mode).
        **Plugins MUST provide a manifest - there is no fallback.**
        """
        self.handlers: Dict[str, HandlerFn] = {}
        self.manifest_data = manifest_data
        self.limits = Limits.default()

        # Try to parse the manifest for CLI mode support
        try:
            manifest_dict = json.loads(manifest_data)
            self.manifest = CapManifest.from_dict(manifest_dict)
        except Exception:
            self.manifest = None

    @classmethod
    def with_manifest(cls, manifest: CapManifest):
        """Create a new plugin runtime with a pre-built CapManifest.
        This is the preferred method as it ensures the manifest is valid.
        """
        manifest_data = json.dumps(manifest.to_dict()).encode('utf-8')
        instance = cls(manifest_data)
        instance.manifest = manifest
        return instance

    @classmethod
    def with_manifest_json(cls, manifest_json: str):
        """Create a new plugin runtime with manifest JSON string."""
        return cls(manifest_json.encode('utf-8'))

    def register(self, cap_urn: str, handler: Callable[[Any, StreamEmitter, PeerInvoker], bytes]) -> None:
        """Register a handler for a cap URN.

        The handler receives:
        - The request payload deserialized from JSON
        - An emitter for streaming output
        - A peer invoker for calling caps on the host

        It returns the final response payload bytes.

        Chunks emitted by the handler are written immediately to stdout.
        This is essential for progress updates and real-time token streaming.

        **Thread safety**: Handlers run in separate threads, so they must be
        thread-safe. The emitter and peer invoker are thread-safe and can be used freely.

        **Peer invocation**: Use the `peer` parameter to invoke caps on the host.
        This is useful for sandboxed plugins that need to delegate operations
        (like network access) to the host.
        """
        def wrapper(payload: bytes, emitter: StreamEmitter, peer: PeerInvoker) -> bytes:
            # Deserialize request from payload bytes (JSON format)
            try:
                request = json.loads(payload)
            except Exception as e:
                raise DeserializeError(f"Failed to parse request: {e}")

            return handler(request, emitter, peer)

        self.handlers[cap_urn] = wrapper

    def register_raw(self, cap_urn: str, handler: HandlerFn) -> None:
        """Register a raw handler that works with bytes directly.

        Use this when you need full control over serialization.
        The handler receives the emitter and peer invoker in addition to the raw payload.
        """
        self.handlers[cap_urn] = handler

    def find_handler(self, cap_urn: str) -> Optional[HandlerFn]:
        """Find a handler for a cap URN.
        Returns the handler if found, None otherwise.
        """
        # First try exact match
        if cap_urn in self.handlers:
            return self.handlers[cap_urn]

        # Then try pattern matching via CapUrn
        try:
            request_urn = CapUrn.from_string(cap_urn)
        except Exception:
            return None

        for pattern, handler in self.handlers.items():
            try:
                pattern_urn = CapUrn.from_string(pattern)
                if pattern_urn.accepts(request_urn):
                    return handler
            except Exception:
                continue

        return None

    def run(self) -> None:
        """Run the plugin runtime.

        **Mode Detection**:
        - No CLI arguments: Plugin CBOR mode (stdin/stdout binary frames)
        - Any CLI arguments: CLI mode (parse args from cap definitions)

        **CLI Mode**:
        - `manifest` subcommand: output manifest JSON
        - `<op>` subcommand: find cap by op tag, parse args, invoke handler
        - `--help`: show available subcommands

        **Plugin CBOR Mode** (no CLI args):
        1. Receive HELLO from host
        2. Send HELLO back with manifest (handshake)
        3. Main loop reads frames:
           - REQ frames: spawn handler thread, continue reading
           - HEARTBEAT frames: respond immediately
           - RES/CHUNK/END frames: route to pending peer requests
           - Other frames: ignore
        4. Exit when stdin closes, wait for active handlers to complete

        **Multiplexing** (CBOR mode): The main loop never blocks on handler execution.
        Handlers run in separate threads, allowing concurrent processing
        of multiple requests and immediate heartbeat responses.

        **Bidirectional communication** (CBOR mode): Handlers can invoke caps on the host
        using the `PeerInvoker` parameter. Response frames from the host are
        routed to the appropriate pending request by MessageId.
        """
        args = sys.argv

        # No CLI arguments at all → Plugin CBOR mode
        if len(args) == 1:
            return self.run_cbor_mode()

        # Any CLI arguments → CLI mode
        return self.run_cli_mode(args)

    def run_cli_mode(self, args: List[str]) -> None:
        """Run in CLI mode - parse arguments and invoke handler."""
        if self.manifest is None:
            raise ManifestError("Failed to parse manifest for CLI mode")

        # Handle --help at top level
        if len(args) == 2 and args[1] in ['--help', '-h']:
            self.print_help(self.manifest)
            return

        subcommand = args[1]

        # Handle manifest subcommand (always provided by runtime)
        if subcommand == 'manifest':
            print(json.dumps(self.manifest.to_dict(), indent=2))
            return

        # Handle subcommand --help
        if len(args) == 3 and args[2] in ['--help', '-h']:
            cap = self.find_cap_by_command(self.manifest, subcommand)
            if cap:
                self.print_cap_help(cap)
                return

        # Find cap by command name
        cap = self.find_cap_by_command(self.manifest, subcommand)
        if cap is None:
            raise UnknownSubcommandError(
                f"Unknown subcommand '{subcommand}'. Run with --help to see available commands."
            )

        # Find handler
        handler = self.find_handler(cap.urn_string())
        if handler is None:
            raise NoHandlerError(f"No handler registered for cap '{cap.urn_string()}'")

        # Build arguments from CLI and convert to synthetic streams
        cli_args = args[2:]
        arguments = self.build_arguments_from_cli(cap, cli_args)
        synthetic_streams = [
            (f"arg-{i}", PendingStream(media_urn=arg.media_urn, chunks=[arg.value], complete=True))
            for i, arg in enumerate(arguments)
        ]

        # Extract effective payload from synthetic streams
        payload = extract_effective_payload(
            synthetic_streams,
            cap.urn_string()
        )

        # Create CLI-mode emitter and no-op peer invoker
        emitter = CliStreamEmitter()
        peer = NoPeerInvoker()

        # Invoke handler
        try:
            result = handler(payload, emitter, peer)

            # Output final response if not empty
            if result:
                sys.stdout.buffer.write(result)
                sys.stdout.buffer.write(b'\n')
                sys.stdout.buffer.flush()
        except Exception as e:
            # Output error as JSON to stderr
            error_json = {
                "error": str(e),
                "code": "HANDLER_ERROR"
            }
            print(json.dumps(error_json), file=sys.stderr)
            raise

    def run_cbor_mode(self) -> None:
        """Run in Plugin CBOR mode - binary frame protocol via stdin/stdout."""
        # Lock stdin for reading (single reader)
        reader = FrameReader(sys.stdin.buffer)
        # Use stdout directly, protected by lock for thread safety
        writer = FrameWriter(sys.stdout.buffer)
        writer_lock = threading.Lock()

        # Perform handshake - send our manifest in the HELLO response
        with writer_lock:
            try:
                limits = handshake_accept(reader, writer, self.manifest_data)
                reader.set_limits(limits)
                writer.set_limits(limits)
                self.limits = limits
            except Exception as e:
                print(f"[PluginRuntime] Handshake failed: {e}", file=sys.stderr)
                raise

        # Track pending peer requests (plugin invoking host caps)
        pending_peer_requests: Dict[str, PendingPeerRequest] = {}
        pending_lock = threading.Lock()

        # Track incoming requests that are being chunked
        pending_incoming: Dict[str, PendingIncomingRequest] = {}
        pending_incoming_lock = threading.Lock()

        # Track active handler threads for cleanup
        active_handlers: List[threading.Thread] = []

        # Process requests - main loop stays responsive
        while True:
            # Clean up finished handlers periodically
            active_handlers = [h for h in active_handlers if h.is_alive()]

            try:
                frame = reader.read()
            except Exception as e:
                print(f"[PluginRuntime] Read error: {e}", file=sys.stderr)
                break

            if frame is None:
                # EOF - stdin closed, exit cleanly
                break

            if frame.frame_type == FrameType.REQ:
                cap_urn = frame.cap
                if cap_urn is None:
                    err_frame = Frame.err(
                        frame.id,
                        "INVALID_REQUEST",
                        "Request missing cap URN"
                    )
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                raw_payload = frame.payload if frame.payload is not None else b""

                # Protocol v2: REQ must have empty payload — arguments come as streams
                if len(raw_payload) > 0:
                    err_frame = Frame.err(
                        frame.id,
                        "PROTOCOL_ERROR",
                        "REQ frame must have empty payload — use STREAM_START for arguments"
                    )
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                # Start tracking this request — streams will be added via STREAM_START
                with pending_incoming_lock:
                    pending_incoming[frame.id.to_string()] = PendingIncomingRequest(
                        cap_urn=cap_urn,
                        content_type=frame.content_type,
                        streams=[],
                        ended=False
                    )
                continue  # Wait for STREAM_START/CHUNK/STREAM_END/END frames

            elif frame.frame_type == FrameType.HEARTBEAT:
                # Respond to heartbeat immediately - never blocked by handlers
                response = Frame.heartbeat(frame.id)
                with writer_lock:
                    try:
                        writer.write(response)
                    except Exception as e:
                        print(f"[PluginRuntime] Failed to write heartbeat response: {e}", file=sys.stderr)
                        break

            elif frame.frame_type == FrameType.HELLO:
                # Unexpected HELLO after handshake - protocol error
                err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "Unexpected HELLO after handshake")
                with writer_lock:
                    try:
                        writer.write(err_frame)
                    except Exception:
                        pass

            elif frame.frame_type == FrameType.CHUNK:
                # Protocol v2: CHUNK must have stream_id
                if frame.stream_id is None:
                    err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "CHUNK frame missing stream_id")
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                stream_id = frame.stream_id

                # Check if this is a chunk for an incoming request
                with pending_incoming_lock:
                    frame_id_str = frame.id.to_string()
                    if frame_id_str in pending_incoming:
                        pending_req = pending_incoming[frame_id_str]

                        # FAIL HARD: Request already ended
                        if pending_req.ended:
                            del pending_incoming[frame_id_str]
                            err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "CHUNK after request END")
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception:
                                    pass
                            continue

                        # FAIL HARD: Unknown stream
                        found_stream = None
                        for sid, stream in pending_req.streams:
                            if sid == stream_id:
                                found_stream = stream
                                break

                        if found_stream is None:
                            del pending_incoming[frame_id_str]
                            err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", f"CHUNK for unknown stream_id: {stream_id}")
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception:
                                    pass
                            continue

                        # FAIL HARD: Stream already ended
                        if found_stream.complete:
                            del pending_incoming[frame_id_str]
                            err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", f"CHUNK for ended stream: {stream_id}")
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception:
                                    pass
                            continue

                        # Valid chunk for active stream
                        if frame.payload:
                            found_stream.chunks.append(frame.payload)
                        continue  # Wait for more chunks or STREAM_END

                # Not an incoming request chunk - must be a peer response chunk
                frame_id_str = frame.id.to_string()
                with pending_lock:
                    if frame_id_str in pending_peer_requests:
                        pending_req = pending_peer_requests[frame_id_str]
                        payload = frame.payload if frame.payload is not None else b""
                        pending_req.queue.put(("ok", payload))

            elif frame.frame_type == FrameType.END:
                # Protocol v2: END marks the end of all streams for this request
                pending_req = None
                with pending_incoming_lock:
                    frame_id_str = frame.id.to_string()
                    if frame_id_str in pending_incoming:
                        pending_req = pending_incoming.pop(frame_id_str)
                        if pending_req:
                            pending_req.ended = True

                if pending_req:
                    # Find handler
                    handler = self.find_handler(pending_req.cap_urn)
                    if not handler:
                        err_frame = Frame.err(frame.id, "NO_HANDLER", f"No handler registered for cap: {pending_req.cap_urn}")
                        with writer_lock:
                            try:
                                writer.write(err_frame)
                            except Exception:
                                pass
                        continue

                    # Clone what we need for the handler thread
                    request_id = frame.id
                    streams_snapshot = list(pending_req.streams)
                    cap_urn_clone = pending_req.cap_urn
                    max_chunk = self.limits.max_chunk

                    # Spawn thread to invoke handler with stream multiplexing response
                    def handle_streamed_request():
                        import uuid as _uuid
                        response_stream_id = f"resp-{_uuid.uuid4().hex[:8]}"
                        emitter = ThreadSafeEmitter(writer, request_id, response_stream_id, "media:bytes", writer_lock, max_chunk)
                        peer_invoker = PeerInvokerImpl(writer, writer_lock, pending_peer_requests, max_chunk)

                        # Extract effective payload from streams
                        try:
                            payload = extract_effective_payload(
                                streams_snapshot,
                                cap_urn_clone
                            )
                        except Exception as e:
                            err_frame = Frame.err(request_id, "PAYLOAD_ERROR", str(e))
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception as write_err:
                                    print(f"[PluginRuntime] Failed to write error response: {write_err}", file=sys.stderr)
                            return

                        # Execute handler — response emitted via emitter, finalized at end
                        try:
                            result = handler(payload, emitter, peer_invoker)

                            # Emit handler's return value through the emitter
                            if result:
                                emitter.emit_bytes(result)

                            # Finalize: STREAM_END + END
                            emitter.finalize()

                        except Exception as e:
                            err_frame = Frame.err(request_id, "HANDLER_ERROR", str(e))
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception as write_err:
                                    print(f"[PluginRuntime] Failed to write error response: {write_err}", file=sys.stderr)

                    thread = threading.Thread(target=handle_streamed_request, daemon=True)
                    thread.start()
                    active_handlers.append(thread)
                    continue

                # Not an incoming request end - must be a peer response end
                frame_id_str = frame.id.to_string()
                with pending_lock:
                    if frame_id_str in pending_peer_requests:
                        pending_req = pending_peer_requests[frame_id_str]
                        payload = frame.payload if frame.payload is not None else b""
                        pending_req.queue.put(("end", payload))
                        del pending_peer_requests[frame_id_str]

            elif frame.frame_type == FrameType.STREAM_START:
                # Protocol v2: A new stream is starting for a request
                if frame.stream_id is None:
                    err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "STREAM_START missing stream_id")
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                if frame.media_urn is None:
                    err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "STREAM_START missing media_urn")
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                stream_id = frame.stream_id
                media_urn = frame.media_urn

                with pending_incoming_lock:
                    frame_id_str = frame.id.to_string()
                    if frame_id_str in pending_incoming:
                        pending_req = pending_incoming[frame_id_str]

                        # FAIL HARD: Request already ended
                        if pending_req.ended:
                            del pending_incoming[frame_id_str]
                            err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "STREAM_START after request END")
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception:
                                    pass
                            continue

                        # FAIL HARD: Duplicate stream_id
                        for sid, _ in pending_req.streams:
                            if sid == stream_id:
                                del pending_incoming[frame_id_str]
                                err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", f"Duplicate stream_id: {stream_id}")
                                with writer_lock:
                                    try:
                                        writer.write(err_frame)
                                    except Exception:
                                        pass
                                break
                        else:
                            # No duplicate — add new stream
                            pending_req.streams.append((stream_id, PendingStream(
                                media_urn=media_urn,
                                chunks=[],
                                complete=False
                            )))
                    else:
                        print(f"[PluginRuntime] STREAM_START for unknown request_id: {frame.id}", file=sys.stderr)

            elif frame.frame_type == FrameType.STREAM_END:
                # Protocol v2: A stream has ended for a request
                if frame.stream_id is None:
                    err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", "STREAM_END missing stream_id")
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                stream_id = frame.stream_id

                with pending_incoming_lock:
                    frame_id_str = frame.id.to_string()
                    if frame_id_str in pending_incoming:
                        pending_req = pending_incoming[frame_id_str]

                        # Find and mark stream as complete
                        found = False
                        for sid, stream in pending_req.streams:
                            if sid == stream_id:
                                stream.complete = True
                                found = True
                                break

                        if not found:
                            del pending_incoming[frame_id_str]
                            err_frame = Frame.err(frame.id, "PROTOCOL_ERROR", f"STREAM_END for unknown stream_id: {stream_id}")
                            with writer_lock:
                                try:
                                    writer.write(err_frame)
                                except Exception:
                                    pass
                    else:
                        print(f"[PluginRuntime] STREAM_END for unknown request_id: {frame.id}", file=sys.stderr)

            elif frame.frame_type == FrameType.ERR:
                # Error frame from host - could be response to peer request
                frame_id_str = frame.id.to_string()
                with pending_lock:
                    if frame_id_str in pending_peer_requests:
                        pending_req = pending_peer_requests[frame_id_str]
                        code = frame.error_code() or "UNKNOWN"
                        message = frame.error_message() or "Unknown error"
                        pending_req.queue.put(("error", f"[{code}] {message}"))
                        del pending_peer_requests[frame_id_str]

            elif frame.frame_type == FrameType.LOG:
                # Log frames from host - shouldn't normally receive these, ignore
                continue

        # Wait for all active handlers to complete before exiting
        for thread in active_handlers:
            thread.join(timeout=5.0)  # 5 second timeout per thread

    def find_cap_by_command(self, manifest: CapManifest, command_name: str) -> Optional[Cap]:
        """Find a cap by its command name (the CLI subcommand)."""
        for cap in manifest.caps:
            if cap.command == command_name:
                return cap
        return None

    def _get_positional_args(self, args: List[str]) -> List[str]:
        """Get positional arguments (non-flag arguments).

        Filters out CLI flags (starting with '-') and their values.
        """
        positional = []
        skip_next = False

        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg.startswith('-'):
                # This is a flag - skip its value too
                if '=' not in arg:
                    skip_next = True
            else:
                positional.append(arg)

        return positional

    def _get_cli_flag_value(self, args: List[str], flag: str) -> Optional[str]:
        """Get value for a CLI flag (e.g., --model "value").

        Supports both formats:
        - --flag value
        - --flag=value
        """
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == flag:
                if i + 1 < len(args):
                    return args[i + 1]
                return None
            # Handle --flag=value format
            if arg.startswith(f"{flag}="):
                return arg[len(flag) + 1:]
            i += 1
        return None

    def _read_stdin_if_available(self) -> Optional[bytes]:
        """Read stdin if data is available (non-blocking check).

        Returns None if stdin is a terminal (interactive) or if empty.
        """
        # Don't read from stdin if it's a terminal (interactive)
        if sys.stdin.isatty():
            return None

        # Check if we're in a test environment where stdin is captured
        # (DontReadFromInput from pytest)
        if hasattr(sys.stdin, 'read') and 'DontReadFromInput' in type(sys.stdin).__name__:
            return None

        try:
            data = sys.stdin.buffer.read()
            if not data:
                return None
            return data
        except (OSError, IOError):
            # stdin not available or can't be read
            return None

    def _read_file_path_to_bytes(self, path_value: str, is_array: bool) -> bytes:
        """Read file(s) for file-path arguments and return bytes.

        This method implements automatic file-path to bytes conversion when:
        - arg.media_urn is "media:file-path" or "media:file-path-array"
        - arg has a stdin source (indicating bytes are the canonical type)

        Args:
            path_value: File path string (single path or JSON array of path patterns)
            is_array: True if media:file-path-array (read multiple files with glob expansion)

        Returns:
            - For single file: bytes containing raw file bytes
            - For array: CBOR-encoded array of file bytes (each element is one file's contents)

        Raises:
            RuntimeError: If file cannot be read with clear error message
        """
        if is_array:
            # Parse JSON array of path patterns
            try:
                path_patterns = json.loads(path_value)
            except json.JSONDecodeError as e:
                raise CliError(
                    f"Failed to parse file-path-array: expected JSON array of path patterns, "
                    f"got '{path_value}': {e}"
                )

            if not isinstance(path_patterns, list):
                raise CliError(
                    f"Failed to parse file-path-array: expected JSON array of path patterns, "
                    f"got '{path_value}'"
                )

            # Expand globs and collect all file paths
            all_files = []
            for pattern in path_patterns:
                # Check if this is a literal path (no glob metacharacters) or a glob pattern
                is_glob = '*' in pattern or '?' in pattern or '[' in pattern

                if not is_glob:
                    # Literal path - verify it exists and is a file
                    path = Path(pattern)
                    if not path.exists():
                        raise IoRuntimeError(
                            f"Failed to read file '{pattern}' from file-path-array: "
                            f"No such file or directory"
                        )
                    if path.is_file():
                        all_files.append(path)
                    # Skip directories silently for consistency with glob behavior
                else:
                    # Glob pattern - expand it
                    # Python's glob doesn't validate patterns, but we can check for common errors
                    # Check for unclosed brackets
                    bracket_count = 0
                    for char in pattern:
                        if char == '[':
                            bracket_count += 1
                        elif char == ']':
                            bracket_count -= 1
                            if bracket_count < 0:
                                raise CliError(f"Invalid glob pattern '{pattern}': unmatched ']'")
                    if bracket_count != 0:
                        raise CliError(f"Invalid glob pattern '{pattern}': unclosed '['")

                    try:
                        paths = glob.glob(pattern)
                    except Exception as e:
                        raise CliError(f"Invalid glob pattern '{pattern}': {e}")

                    for path_str in paths:
                        path = Path(path_str)
                        # Only include files (skip directories)
                        if path.is_file():
                            all_files.append(path)

            # Read each file sequentially
            files_data = []
            for path in all_files:
                try:
                    file_bytes = path.read_bytes()
                    files_data.append(file_bytes)
                except IOError as e:
                    raise IoRuntimeError(
                        f"Failed to read file '{path}' from file-path-array: {e}"
                    )

            # Encode as CBOR array
            try:
                return cbor2.dumps(files_data)
            except Exception as e:
                raise SerializeError(f"Failed to encode CBOR array: {e}")
        else:
            # Single file path - read and return raw bytes
            try:
                path = Path(path_value)
                return path.read_bytes()
            except IOError as e:
                raise IoRuntimeError(f"Failed to read file '{path_value}': {e}")

    def build_arguments_from_cli(self, cap: Cap, cli_args: List[str]) -> List[CapArgumentValue]:
        """Build CapArgumentValue list from CLI arguments based on cap's arg definitions."""
        # Check for stdin data if cap accepts stdin
        stdin_data = None
        if cap.accepts_stdin():
            stdin_data = self._read_stdin_if_available()

        # If no arguments are defined but stdin data exists, wrap as single argument
        if not cap.get_args() and stdin_data is not None:
            return [CapArgumentValue(cap.in_spec(), stdin_data)]

        # Build list of CapArgumentValue objects
        arguments: List[CapArgumentValue] = []

        for arg_def in cap.get_args():
            value = self._extract_arg_value(arg_def, cli_args, stdin_data)

            if value is None:
                if arg_def.required:
                    raise MissingArgumentError(f"Required argument '{arg_def.media_urn}' not provided")
                continue

            # Validate media URN
            try:
                arg_media_urn = MediaUrn.from_string(arg_def.media_urn)
            except MediaUrnError as e:
                raise CliError(f"Invalid media URN '{arg_def.media_urn}': {e}")

            # Check if this arg requires file-path to bytes conversion
            from .cap import StdinSource

            file_path_pattern = MediaUrn.from_string(MEDIA_FILE_PATH)
            file_path_array_pattern = MediaUrn.from_string(MEDIA_FILE_PATH_ARRAY)

            # Check array first (more specific), then single file-path
            is_array = file_path_array_pattern.accepts(arg_media_urn)
            is_file_path = is_array or file_path_pattern.accepts(arg_media_urn)

            # Get stdin source media URN if it exists (tells us target type)
            has_stdin_source = any(
                isinstance(s, StdinSource)
                for s in arg_def.sources
            )

            # If file-path type with stdin source, use stdin's media URN instead
            if is_file_path and has_stdin_source:
                # Find the stdin source to get its media URN
                stdin_media_urn = None
                for source in arg_def.sources:
                    if isinstance(source, StdinSource):
                        stdin_media_urn = source.stdin
                        break

                if stdin_media_urn:
                    # Use stdin's media URN as the argument media URN (bytes, not file-path)
                    arguments.append(CapArgumentValue(
                        media_urn=stdin_media_urn,
                        value=value
                    ))
                else:
                    # Fallback to arg's media URN
                    arguments.append(CapArgumentValue(
                        media_urn=arg_def.media_urn,
                        value=value
                    ))
            else:
                # Not a file-path type, use arg's media URN
                arguments.append(CapArgumentValue(
                    media_urn=arg_def.media_urn,
                    value=value
                ))

        return arguments

    def _extract_arg_value(
        self,
        arg_def: CapArg,
        cli_args: List[str],
        stdin_data: Optional[bytes]
    ) -> Optional[bytes]:
        """Extract a single argument value from CLI args or stdin.

        This method implements automatic file-path to bytes conversion when:
        - arg.media_urn is "media:file-path" or "media:file-path-array"
        - arg has a stdin source (indicating bytes are the canonical type)
        """
        from .cap import StdinSource, PositionSource, CliFlagSource

        # Check if this arg requires file-path to bytes conversion using proper URN matching
        try:
            arg_media_urn = MediaUrn.from_string(arg_def.media_urn)
        except MediaUrnError as e:
            raise CliError(f"Invalid media URN '{arg_def.media_urn}': {e}")

        file_path_pattern = MediaUrn.from_string(MEDIA_FILE_PATH)
        file_path_array_pattern = MediaUrn.from_string(MEDIA_FILE_PATH_ARRAY)

        # Check array first (more specific), then single file-path
        is_array = file_path_array_pattern.accepts(arg_media_urn)
        is_file_path = is_array or file_path_pattern.accepts(arg_media_urn)

        # Get stdin source media URN if it exists (tells us target type)
        has_stdin_source = any(
            isinstance(s, StdinSource)
            for s in arg_def.sources
        )

        # Try each source in order
        for source in arg_def.sources:
            if isinstance(source, CliFlagSource):
                value = self._get_cli_flag_value(cli_args, source.cli_flag)
                if value is not None:
                    # If file-path type with stdin source, read file(s)
                    if is_file_path and has_stdin_source:
                        return self._read_file_path_to_bytes(value, is_array)
                    return value.encode('utf-8')
            elif isinstance(source, PositionSource):
                # Positional args: filter out flags and their values
                positional = self._get_positional_args(cli_args)
                pos = source.position
                if pos < len(positional):
                    value = positional[pos]
                    # If file-path type with stdin source, read file(s)
                    if is_file_path and has_stdin_source:
                        return self._read_file_path_to_bytes(value, is_array)
                    return value.encode('utf-8')
            elif isinstance(source, StdinSource):
                if stdin_data is not None:
                    return stdin_data

        # Try default value
        if arg_def.default_value is not None:
            try:
                return json.dumps(arg_def.default_value).encode('utf-8')
            except Exception as e:
                raise SerializeError(str(e))

        return None


    def print_help(self, manifest: CapManifest) -> None:
        """Print help message showing all available subcommands."""
        print(f"{manifest.name} v{manifest.version}", file=sys.stderr)
        print(manifest.description, file=sys.stderr)
        print(file=sys.stderr)
        print("USAGE:", file=sys.stderr)
        print(f"    {manifest.name.lower()} <COMMAND> [OPTIONS]", file=sys.stderr)
        print(file=sys.stderr)
        print("COMMANDS:", file=sys.stderr)
        print("    manifest    Output the plugin manifest as JSON", file=sys.stderr)

        for cap in manifest.caps:
            desc = cap.cap_description or cap.title
            print(f"    {cap.command:<12} {desc}", file=sys.stderr)

        print(file=sys.stderr)
        print(f"Run '{manifest.name.lower()} <COMMAND> --help' for more information on a command.", file=sys.stderr)

    def print_cap_help(self, cap: Cap) -> None:
        """Print help for a specific cap."""
        print(cap.title, file=sys.stderr)
        if cap.cap_description:
            print(cap.cap_description, file=sys.stderr)
        print(file=sys.stderr)
        print("USAGE:", file=sys.stderr)
        print(f"    plugin {cap.command} [OPTIONS]", file=sys.stderr)
        print(file=sys.stderr)

        args = cap.get_args()
        if args:
            print("OPTIONS:", file=sys.stderr)
            for arg in args:
                required = " (required)" if arg.required else ""
                desc = arg.arg_description or ""

                for source in arg.sources:
                    if isinstance(source, dict) and 'cli_flag' in source:
                        print(f"    {source['cli_flag']:<16} {desc}{required}", file=sys.stderr)
                    elif isinstance(source, dict) and 'position' in source:
                        print(f"    <arg{source['position']}>          {desc}{required}", file=sys.stderr)
                    elif isinstance(source, dict) and 'stdin' in source:
                        print(f"    (stdin: {source['stdin']}) {desc}{required}", file=sys.stderr)

    def get_limits(self) -> Limits:
        """Get the current protocol limits"""
        return self.limits
