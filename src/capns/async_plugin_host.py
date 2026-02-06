"""Async Plugin Host - Native async runtime for communicating with plugin processes

The AsyncPluginHost is the host-side runtime that manages all communication with
a running plugin process using fully async I/O. It handles:

- HELLO handshake and limit negotiation
- Sending cap requests
- Receiving and routing responses
- Heartbeat handling (transparent)
- Multiplexed concurrent requests (transparent)
- Clean cancellation and shutdown

**This is the ONLY way for the host to communicate with plugins.**
No fallbacks, no alternative protocols.

Usage:
```python
import asyncio
from capns.async_plugin_host import AsyncPluginHost

async def main():
    process = await asyncio.create_subprocess_exec(
        "./my-plugin",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE
    )

    host = await AsyncPluginHost.new(process.stdout, process.stdin)

    # Send request and receive response
    response = await host.call("cap:op=test", b"payload", "application/json")
```
"""

import asyncio
from typing import Optional, List, Dict
from dataclasses import dataclass

from capns.cbor_frame import Frame, FrameType, Limits, MessageId
from capns.cbor_io import handshake_async, AsyncFrameReader, AsyncFrameWriter, CborError
from capns.caller import CapArgumentValue


class AsyncHostError(Exception):
    """Base error for async plugin host"""

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
        """Get the complete payload by concatenating all chunks"""
        if not self.chunks:
            return None
        # Concatenate all chunks to get the full payload
        return b''.join(chunk.payload for chunk in self.chunks)

    def concatenated(self) -> bytes:
        """Concatenate all payloads into a single buffer"""
        if self.is_single():
            return self.chunks[0].payload

        result = bytearray()
        for chunk in self.chunks:
            result.extend(chunk.payload)
        return bytes(result)


class StreamingResponse:
    """A streaming response from a plugin that can be iterated asynchronously"""

    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    async def next(self) -> Optional[ResponseChunk]:
        """Get the next chunk from the stream"""
        try:
            item = await self.queue.get()
            if isinstance(item, Exception):
                raise item
            return item
        except asyncio.QueueEmpty:
            return None


class WriterCommand:
    """Commands sent to the writer task"""
    pass


@dataclass
class WriteFrame(WriterCommand):
    """Write a frame"""
    frame: Frame


@dataclass
class Shutdown(WriterCommand):
    """Shutdown the writer"""
    pass


class HostState:
    """Internal shared state for the async plugin host"""

    def __init__(self):
        self.pending: Dict[MessageId, asyncio.Queue] = {}
        self.pending_heartbeats: set = set()
        self.closed: bool = False
        self.capabilities: Dict[str, callable] = {}  # cap_urn -> async handler function


class AsyncPluginHost:
    """Async host-side runtime for communicating with a plugin process

    Uses native asyncio async I/O with clean cancellation support.
    """

    def __init__(
        self,
        writer_queue: asyncio.Queue,
        state: HostState,
        limits: Limits,
        plugin_manifest: bytes,
        reader_task: asyncio.Task,
        writer_task: asyncio.Task,
    ):
        """Internal constructor - use new() instead"""
        self._writer_queue = writer_queue
        self._state = state
        self.limits = limits
        self.plugin_manifest = plugin_manifest
        self.reader_task = reader_task
        self.writer_task = writer_task

    @classmethod
    async def new(cls, stdout, stdin) -> "AsyncPluginHost":
        """Create a new async plugin host and perform handshake

        This sends a HELLO frame, waits for the plugin's HELLO (which MUST include manifest),
        negotiates protocol limits, then starts the background reader and writer tasks.

        Args:
            stdout: Plugin stdout stream for reading
            stdin: Plugin stdin stream for writing

        Returns:
            AsyncPluginHost instance

        Raises:
            AsyncHostError: If handshake fails
        """
        reader = AsyncFrameReader(stdout)
        writer = AsyncFrameWriter(stdin)

        # Perform handshake
        handshake_result = await handshake_async(reader, writer)
        limits = handshake_result.limits
        plugin_manifest = handshake_result.manifest

        # Create queues and state
        writer_queue = asyncio.Queue(maxsize=64)
        state = HostState()

        # Start writer task
        writer_task = asyncio.create_task(cls._writer_loop(writer, writer_queue))

        # Start reader task
        reader_task = asyncio.create_task(
            cls._reader_loop(reader, state, writer_queue)
        )

        return cls(writer_queue, state, limits, plugin_manifest, reader_task, writer_task)

    @staticmethod
    async def _writer_loop(writer: AsyncFrameWriter, queue: asyncio.Queue):
        """Writer loop - sends frames from the queue"""
        while True:
            cmd = await queue.get()
            if isinstance(cmd, Shutdown):
                break
            elif isinstance(cmd, WriteFrame):
                try:
                    await writer.write(cmd.frame)
                except Exception as e:
                    print(f"AsyncPluginHost writer error: {e}")
                    break

    @staticmethod
    async def _reader_loop(
        reader: AsyncFrameReader,
        state: HostState,
        writer_queue: asyncio.Queue,
    ):
        """Reader loop - reads frames and dispatches to waiting requests"""
        while True:
            try:
                frame = await reader.read()

                if frame is None:
                    # EOF - plugin closed
                    state.closed = True
                    # Notify all pending requests
                    for queue in state.pending.values():
                        await queue.put(ProcessExited())
                    break

                # Handle heartbeats transparently
                if frame.frame_type == FrameType.HEARTBEAT:
                    if frame.id not in state.pending_heartbeats:
                        # Respond to heartbeat from plugin
                        response = Frame.heartbeat(frame.id)
                        await writer_queue.put(WriteFrame(response))
                    else:
                        # Remove from pending heartbeats
                        state.pending_heartbeats.discard(frame.id)
                    continue

                # Handle incoming REQ frames (peer invocations from plugin)
                if frame.frame_type == FrameType.REQ and frame.id not in state.pending:
                    # This is a peer invocation - plugin is calling a host capability
                    asyncio.create_task(
                        AsyncPluginHost._handle_peer_request(frame, state, writer_queue)
                    )
                    continue

                # Route frame to appropriate pending request
                if frame.id in state.pending:
                    queue = state.pending[frame.id]
                    should_remove = False

                    if frame.frame_type == FrameType.CHUNK:
                        chunk = ResponseChunk(
                            payload=frame.payload or b"",
                            seq=frame.seq,
                            offset=frame.offset,
                            len=frame.len,
                            is_eof=frame.is_eof(),
                        )
                        await queue.put(chunk)
                        should_remove = chunk.is_eof

                    elif frame.frame_type == FrameType.RES:
                        chunk = ResponseChunk(
                            payload=frame.payload or b"",
                            seq=0,
                            offset=None,
                            len=None,
                            is_eof=True,
                        )
                        await queue.put(chunk)
                        should_remove = True

                    elif frame.frame_type == FrameType.END:
                        if frame.payload:
                            chunk = ResponseChunk(
                                payload=frame.payload,
                                seq=frame.seq,
                                offset=frame.offset,
                                len=frame.len,
                                is_eof=True,
                            )
                            await queue.put(chunk)
                        should_remove = True

                    elif frame.frame_type == FrameType.LOG:
                        # LOG frames are transparent
                        should_remove = False

                    elif frame.frame_type == FrameType.ERR:
                        code = frame.error_code() or "UNKNOWN"
                        message = frame.error_message() or "Unknown error"
                        await queue.put(PluginError(code, message))
                        should_remove = True

                    else:
                        await queue.put(UnexpectedFrameType(frame.frame_type))
                        should_remove = True

                    # Remove completed request
                    if should_remove:
                        del state.pending[frame.id]

            except Exception as e:
                # Read error
                state.closed = True
                error = CborErrorWrapper(str(e))
                for queue in state.pending.values():
                    await queue.put(error)
                break

    async def request(
        self,
        cap_urn: str,
        payload: bytes,
        content_type: str,
    ) -> asyncio.Queue:
        """Send a cap request and receive responses via a queue

        Args:
            cap_urn: Cap URN to invoke
            payload: Request payload
            content_type: Content type of payload

        Returns:
            Queue for receiving response chunks

        Raises:
            Closed: If host is closed
            SendError: If send fails
        """
        if self._state.closed:
            raise Closed()

        request_id = MessageId.new_uuid()
        request = Frame.req(request_id, cap_urn, payload, content_type)

        # Create queue for responses
        queue = asyncio.Queue(maxsize=32)
        self._state.pending[request_id] = queue

        # Send request
        try:
            await self._writer_queue.put(WriteFrame(request))
        except:
            raise SendError()

        return queue

    async def call(
        self,
        cap_urn: str,
        payload: bytes,
        content_type: str,
    ) -> PluginResponse:
        """Send a cap request and wait for the complete response

        Args:
            cap_urn: Cap URN to invoke
            payload: Request payload
            content_type: Content type of payload

        Returns:
            Complete PluginResponse

        Raises:
            AsyncHostError: If call fails
        """
        queue = await self.request(cap_urn, payload, content_type)
        return await self._collect_response(queue)

    @staticmethod
    async def _collect_response(queue: asyncio.Queue) -> PluginResponse:
        """Collect all response chunks from a queue into a PluginResponse"""
        chunks = []

        while True:
            item = await queue.get()

            if isinstance(item, Exception):
                raise item

            chunk = item
            chunks.append(chunk)

            if chunk.is_eof:
                break

        if not chunks:
            raise RecvError()

        if len(chunks) == 1 and chunks[0].seq == 0:
            return PluginResponse.single(chunks[0].payload)
        else:
            return PluginResponse.streaming(chunks)

    def get_limits(self) -> Limits:
        """Get the negotiated protocol limits"""
        return self.limits

    def get_plugin_manifest(self) -> bytes:
        """Get the plugin manifest extracted from HELLO handshake"""
        return self.plugin_manifest

    async def call_streaming(
        self,
        cap_urn: str,
        payload: bytes,
        content_type: str,
    ) -> StreamingResponse:
        """Send a cap request and get a streaming response iterator

        Args:
            cap_urn: Cap URN to invoke
            payload: Request payload
            content_type: Content type of payload

        Returns:
            StreamingResponse for iterating chunks
        """
        queue = await self.request(cap_urn, payload, content_type)
        return StreamingResponse(queue)

    async def send_heartbeat(self) -> None:
        """Send a heartbeat and wait for response

        Raises:
            Closed: If host is closed
            SendError: If send fails
        """
        if self._state.closed:
            raise Closed()

        heartbeat_id = MessageId.new_uuid()
        heartbeat = Frame.heartbeat(heartbeat_id)

        # Track this heartbeat
        self._state.pending_heartbeats.add(heartbeat_id)

        # Send heartbeat
        try:
            await self._writer_queue.put(WriteFrame(heartbeat))
        except:
            raise SendError()

        # Wait for response (with timeout)
        try:
            await asyncio.wait_for(
                self._wait_for_heartbeat_response(heartbeat_id),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            self._state.pending_heartbeats.discard(heartbeat_id)
            raise AsyncHostError("Heartbeat timeout")

    async def _wait_for_heartbeat_response(self, heartbeat_id: MessageId):
        """Wait for heartbeat response"""
        while heartbeat_id in self._state.pending_heartbeats:
            await asyncio.sleep(0.01)

    def register_capability(self, cap_urn: str, handler):
        """Register a host-side capability that the plugin can invoke via PeerInvoker.

        Args:
            cap_urn: Capability URN (wildcards supported in matching)
            handler: Async function that takes (bytes) and returns bytes
        """
        self._state.capabilities[cap_urn] = handler

    @staticmethod
    async def _handle_peer_request(frame, state, writer_queue):
        """Handle an incoming REQ frame from the plugin (peer invocation).

        Args:
            frame: The REQ frame from the plugin
            state: HostState with registered capabilities
            writer_queue: Queue for sending response frames
        """
        try:
            cap_urn = frame.cap

            # Find matching handler
            handler = None
            for registered_urn, registered_handler in state.capabilities.items():
                # Simple wildcard matching: cap:in=*;op=X;out=* matches any in/out
                # Match on operation name
                if "op=" in cap_urn and "op=" in registered_urn:
                    cap_op = cap_urn.split("op=")[1].split(";")[0]
                    reg_op = registered_urn.split("op=")[1].split(";")[0]
                    if cap_op == reg_op:
                        handler = registered_handler
                        break

            if handler is None:
                # No handler found - send ERR frame
                err_frame = Frame.err(
                    frame.id,
                    "NO_HANDLER",
                    f"No handler registered for capability: {cap_urn}"
                )
                await writer_queue.put(WriteFrame(err_frame))
                return

            # Execute handler
            try:
                # Decode the payload - PeerInvoker sends arguments as CBOR array of {value, media_urn}
                import cbor2
                payload = frame.payload or b""

                # Try to decode as CBOR array of arguments
                try:
                    args = cbor2.loads(payload)
                    if isinstance(args, list) and len(args) > 0:
                        # First argument's value
                        arg = args[0]
                        if isinstance(arg, dict) and "value" in arg:
                            payload = arg["value"]
                            if isinstance(payload, str):
                                payload = payload.encode()
                except:
                    # Not CBOR args format, use as-is
                    pass

                result = await handler(payload)

                # Send RES frame with result
                res_frame = Frame.res(frame.id, result, frame.content_type or "media:bytes")
                await writer_queue.put(WriteFrame(res_frame))

            except Exception as e:
                # Handler error - send ERR frame
                err_frame = Frame.err(
                    frame.id,
                    "HANDLER_ERROR",
                    str(e)
                )
                await writer_queue.put(WriteFrame(err_frame))

        except Exception as e:
            # Protocol error - send ERR frame
            try:
                err_frame = Frame.err(
                    frame.id,
                    "PROTOCOL_ERROR",
                    str(e)
                )
                await writer_queue.put(WriteFrame(err_frame))
            except:
                pass  # Best effort

    async def shutdown(self):
        """Shutdown the host and clean up resources"""
        # Send shutdown to writer
        try:
            await self._writer_queue.put(Shutdown())
        except:
            pass

        # Cancel tasks
        if not self.reader_task.done():
            self.reader_task.cancel()
        if not self.writer_task.done():
            self.writer_task.cancel()

        # Wait for tasks to complete
        try:
            await asyncio.gather(self.reader_task, self.writer_task, return_exceptions=True)
        except:
            pass
