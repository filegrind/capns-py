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
from typing import Callable, Protocol, Optional, Dict, List, Any
from abc import ABC, abstractmethod
import cbor2

from .cbor_frame import Frame, FrameType, Limits, MessageId, DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK
from .cbor_io import handshake_accept, FrameReader, FrameWriter, CborError
from .caller import CapArgumentValue
from .cap import ArgSource, Cap, CapArg
from .cap_urn import CapUrn
from .manifest import CapManifest
from .media_urn import MediaUrn


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
    """

    def emit_bytes(self, payload: bytes) -> None:
        """Emit raw bytes as a chunk immediately."""
        ...

    def emit(self, payload: Any) -> None:
        """Emit a JSON value as a chunk.
        The value is serialized to JSON bytes and sent as the chunk payload.
        """
        try:
            data = json.dumps(payload).encode('utf-8')
            self.emit_bytes(data)
        except Exception as e:
            print(f"[PluginRuntime] Failed to serialize payload: {e}", file=sys.stderr)

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
        """Invoke a cap on the host with unified arguments.

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


class PeerInvokerImpl:
    """Implementation of PeerInvoker that sends REQ frames to the host.

    Enables bidirectional communication where a plugin handler can invoke caps
    on the host while processing a request.
    """

    def __init__(self, writer: FrameWriter, writer_lock: threading.Lock, pending_requests: Dict[str, PendingPeerRequest]):
        self.writer = writer
        self.writer_lock = writer_lock
        self.pending_requests = pending_requests
        self.pending_lock = threading.Lock()

    def invoke(self, cap_urn: str, arguments: List[CapArgumentValue]) -> Any:
        """Invoke a cap on the host with unified arguments.

        Sends a REQ frame to the host with the specified cap URN and arguments.
        Arguments are serialized as CBOR with native binary values.
        Returns an iterator that yields response chunks (bytes) or raises errors.

        The iterator will block waiting for responses until the host sends END or ERR.
        """
        # Generate a new message ID for this request
        request_id = MessageId.new_uuid()
        request_id_str = request_id.to_string()

        # Create a pending request tracker
        pending_req = PendingPeerRequest()

        # Register the pending request before sending
        with self.pending_lock:
            self.pending_requests[request_id_str] = pending_req

        # Serialize arguments as CBOR - binary values stay binary (no base64 needed)
        try:
            cbor_args = [
                {
                    "media_urn": arg.media_urn,
                    "value": arg.value
                }
                for arg in arguments
            ]
            payload_bytes = cbor2.dumps(cbor_args)
        except Exception as e:
            # Remove the pending request on serialization failure
            with self.pending_lock:
                del self.pending_requests[request_id_str]
            raise SerializeError(f"Failed to serialize arguments: {e}")

        # Create and send the REQ frame with CBOR payload
        frame = Frame.req(
            request_id,
            cap_urn,
            payload_bytes,
            "application/cbor"
        )

        try:
            with self.writer_lock:
                self.writer.write(frame)
        except Exception as e:
            # Remove the pending request on send failure
            with self.pending_lock:
                del self.pending_requests[request_id_str]
            raise PeerRequestError(f"Failed to send REQ frame: {e}")

        # Return an iterator that yields response chunks
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
    """Thread-safe implementation of StreamEmitter that writes CBOR frames.
    Uses threading.Lock for safe concurrent access from multiple handler threads.
    """

    def __init__(self, writer: FrameWriter, request_id: MessageId, writer_lock: Optional[threading.Lock] = None):
        self.writer = writer
        self.request_id = request_id
        self.seq = 0
        self.seq_lock = threading.Lock()
        self.writer_lock = writer_lock if writer_lock is not None else threading.Lock()

    def emit_bytes(self, payload: bytes) -> None:
        with self.seq_lock:
            seq = self.seq
            self.seq += 1

        frame = Frame.chunk(self.request_id, seq, payload)

        with self.writer_lock:
            try:
                self.writer.write(frame)
            except Exception as e:
                print(f"[PluginRuntime] Failed to write chunk: {e}", file=sys.stderr)

    def log(self, level: str, message: str) -> None:
        frame = Frame.log(self.request_id, level, message)

        with self.writer_lock:
            try:
                self.writer.write(frame)
            except Exception as e:
                print(f"[PluginRuntime] Failed to write log: {e}", file=sys.stderr)

    def emit_status(self, operation: str, details: str) -> None:
        """Override emit_status to send LOG frames, not CHUNK frames.
        Status messages are progress/status updates, not response data.
        """
        message = f"{operation}: {details}"
        frame = Frame.log(self.request_id, "status", message)

        with self.writer_lock:
            try:
                self.writer.write(frame)
            except Exception as e:
                print(f"[PluginRuntime] Failed to write status: {e}", file=sys.stderr)


# Handler function type
HandlerFn = Callable[[bytes, StreamEmitter, PeerInvoker], bytes]


def extract_effective_payload(
    payload: bytes,
    content_type: Optional[str],
    cap_urn: str
) -> bytes:
    """Extract the effective payload from a REQ frame.

    If the content_type is "application/cbor", the payload is expected to be
    CBOR unified arguments: `[{media_urn: string, value: bytes}, ...]`
    The function extracts the value whose media_urn matches the cap's input type.

    For other content types (or if content_type is None), returns the raw payload.
    """
    # Check if this is CBOR unified arguments
    if content_type != "application/cbor":
        # Not CBOR unified arguments - return raw payload
        return payload

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

    # Parse the CBOR payload as an array of argument maps
    try:
        cbor_value = cbor2.loads(payload)
    except Exception as e:
        raise DeserializeError(f"Failed to parse CBOR unified arguments: {e}")

    if not isinstance(cbor_value, list):
        raise DeserializeError("CBOR unified arguments must be an array")

    # Find the argument with matching media_urn
    for arg in cbor_value:
        if not isinstance(arg, dict):
            continue

        media_urn_str = arg.get("media_urn")
        value = arg.get("value")

        if media_urn_str is None or value is None:
            continue

        # Check if this argument matches the expected input using semantic URN matching
        if expected_media_urn is not None:
            try:
                arg_urn = MediaUrn.from_string(media_urn_str)
                # Use semantic matching in both directions
                fwd = arg_urn.matches(expected_media_urn)
                rev = expected_media_urn.matches(arg_urn)
                if fwd or rev:
                    return value
            except Exception:
                continue

    # No matching argument found - this is an error, no fallbacks
    raise DeserializeError(
        f"No argument found matching expected input media type '{expected_input}' in CBOR unified arguments"
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
                if pattern_urn.matches(request_urn):
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

        # Build arguments from CLI
        cli_args = args[2:]
        payload = self.build_payload_from_cli(cap, cli_args)

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

                handler = self.find_handler(cap_urn)
                if handler is None:
                    err_frame = Frame.err(
                        frame.id,
                        "NO_HANDLER",
                        f"No handler registered for cap: {cap_urn}"
                    )
                    with writer_lock:
                        try:
                            writer.write(err_frame)
                        except Exception:
                            pass
                    continue

                # Clone what we need for the handler thread
                request_id = frame.id
                raw_payload = frame.payload if frame.payload is not None else b""
                content_type = frame.content_type
                cap_urn_clone = cap_urn

                # Spawn handler in separate thread - main loop continues immediately
                def handler_thread():
                    emitter = ThreadSafeEmitter(writer, request_id, writer_lock)
                    # Note: writer is shared via emitter, emitter handles locking via writer_lock

                    # Create peer invoker for bidirectional communication
                    peer_invoker = PeerInvokerImpl(writer, writer_lock, pending_peer_requests)

                    # Extract effective payload from unified arguments if content_type is CBOR
                    try:
                        payload = extract_effective_payload(
                            raw_payload,
                            content_type,
                            cap_urn_clone
                        )
                    except Exception as e:
                        # Failed to extract payload - send error response
                        err_frame = Frame.err(request_id, "PAYLOAD_ERROR", str(e))
                        with writer_lock:
                            try:
                                writer.write(err_frame)
                            except Exception as write_err:
                                print(f"[PluginRuntime] Failed to write error response: {write_err}", file=sys.stderr)
                        return

                    try:
                        result = handler(payload, emitter, peer_invoker)
                        # Write final response (END)
                        response_frame = Frame.end(request_id, result)
                    except Exception as e:
                        # Handler error
                        response_frame = Frame.err(request_id, "HANDLER_ERROR", str(e))

                    with writer_lock:
                        try:
                            writer.write(response_frame)
                        except Exception as e:
                            print(f"[PluginRuntime] Failed to write response: {e}", file=sys.stderr)

                thread = threading.Thread(target=handler_thread, daemon=True)
                thread.start()
                active_handlers.append(thread)

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

            elif frame.frame_type in (FrameType.RES, FrameType.CHUNK, FrameType.END):
                # Response frames from host - route to pending peer request by frame.id
                frame_id_str = frame.id.to_string() if hasattr(frame.id, 'to_string') else str(frame.id)
                with pending_lock:
                    if frame_id_str in pending_peer_requests:
                        pending_req = pending_peer_requests[frame_id_str]
                        payload = frame.payload if frame.payload is not None else b""

                        # CHUNK frames: add to queue, keep request pending
                        if frame.frame_type == FrameType.CHUNK:
                            pending_req.queue.put(("ok", payload))
                        # RES or END frames: final response, mark as complete
                        elif frame.frame_type == FrameType.RES:
                            pending_req.queue.put(("ok", payload))
                            pending_req.queue.put(("end", b""))
                            del pending_peer_requests[frame_id_str]
                        elif frame.frame_type == FrameType.END:
                            pending_req.queue.put(("end", payload))
                            del pending_peer_requests[frame_id_str]

            elif frame.frame_type == FrameType.ERR:
                # Error frame from host - could be response to peer request
                frame_id_str = frame.id.to_string() if hasattr(frame.id, 'to_string') else str(frame.id)
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

    def build_payload_from_cli(self, cap: Cap, cli_args: List[str]) -> bytes:
        """Build payload from CLI arguments based on cap's arg definitions."""
        arguments: List[CapArgumentValue] = []

        # Check for stdin data if cap accepts stdin
        stdin_data = None
        if cap.accepts_stdin():
            stdin_data = self.read_stdin_if_available()

        # Process each cap argument
        for arg_def in cap.get_args():
            value = self.extract_arg_value(arg_def, cli_args, stdin_data)

            if value is not None:
                arguments.append(CapArgumentValue(
                    media_urn=arg_def.media_urn,
                    value=value
                ))
            elif arg_def.required:
                raise MissingArgumentError(f"Required argument '{arg_def.media_urn}' not provided")

        # If no arguments are defined but stdin data exists, use it as raw payload
        if not cap.get_args() and stdin_data is not None:
            return stdin_data

        # If we have structured arguments, serialize as JSON
        if arguments:
            # Build a JSON object from the arguments
            json_obj = {}
            for arg in arguments:
                # Try to parse value as JSON first, fall back to string
                try:
                    value = json.loads(arg.value)
                except Exception:
                    try:
                        value = arg.value.decode('utf-8')
                    except UnicodeDecodeError:
                        # Binary data - keep as raw bytes
                        raise CliError("Binary data cannot be passed via CLI flags. Use stdin instead.")

                # Use the last part of media_urn as key (e.g., "model-spec" from "media:model-spec;...")
                key = arg.media_urn.removeprefix("media:").split(';')[0].replace('-', '_')
                json_obj[key] = value

            return json.dumps(json_obj).encode('utf-8')
        else:
            # No arguments, no stdin - return empty object
            return b'{}'

    def extract_arg_value(
        self,
        arg_def: CapArg,
        cli_args: List[str],
        stdin_data: Optional[bytes]
    ) -> Optional[bytes]:
        """Extract a single argument value from CLI args or stdin."""
        # Try each source in order
        for source in arg_def.sources:
            if isinstance(source, dict) and 'cli_flag' in source:
                value = self.get_cli_flag_value(cli_args, source['cli_flag'])
                if value is not None:
                    return value.encode('utf-8')
            elif isinstance(source, dict) and 'position' in source:
                # Positional args: filter out flags and their values
                positional = self.get_positional_args(cli_args)
                pos = source['position']
                if pos < len(positional):
                    return positional[pos].encode('utf-8')
            elif isinstance(source, dict) and 'stdin' in source:
                if stdin_data is not None:
                    return stdin_data

        # Try default value
        if arg_def.default_value is not None:
            try:
                return json.dumps(arg_def.default_value).encode('utf-8')
            except Exception as e:
                raise SerializeError(str(e))

        return None

    def get_cli_flag_value(self, args: List[str], flag: str) -> Optional[str]:
        """Get value for a CLI flag (e.g., --model "value")"""
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == flag:
                if i + 1 < len(args):
                    return args[i + 1]
                return None
            # Handle --flag=value format
            if arg.startswith(f"{flag}="):
                return arg[len(flag)+1:]
            i += 1
        return None

    def get_positional_args(self, args: List[str]) -> List[str]:
        """Get positional arguments (non-flag arguments)"""
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

    def read_stdin_if_available(self) -> Optional[bytes]:
        """Read stdin if data is available (non-blocking check)."""
        # Don't read from stdin if it's a terminal (interactive)
        if sys.stdin.isatty():
            return None

        data = sys.stdin.buffer.read()
        if not data:
            return None
        return data

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
