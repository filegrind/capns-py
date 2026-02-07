"""CBOR I/O - Reading and Writing CBOR Frames

This module provides streaming CBOR frame encoding/decoding over stdio pipes.
Frames are written as length-prefixed CBOR (same framing as before, but CBOR payload).

## Wire Format

```
┌─────────────────────────────────────────────────────────┐
│  4 bytes: u32 big-endian length                         │
├─────────────────────────────────────────────────────────┤
│  N bytes: CBOR-encoded Frame                            │
└─────────────────────────────────────────────────────────┘
```

The CBOR payload is a map with integer keys (see cbor_frame.py).
"""

import asyncio
import io
from typing import BinaryIO, Optional
from dataclasses import dataclass

try:
    import cbor2
    CBOR2_AVAILABLE = True
except ImportError:
    CBOR2_AVAILABLE = False

from capns.cbor_frame import (
    Frame,
    FrameType,
    MessageId,
    Limits,
    Keys,
    DEFAULT_MAX_FRAME,
    DEFAULT_MAX_CHUNK,
    PROTOCOL_VERSION,
)


# Maximum frame size (16 MB) - hard limit to prevent memory exhaustion
MAX_FRAME_HARD_LIMIT = 16 * 1024 * 1024


class CborError(Exception):
    """Base CBOR I/O error"""
    pass


class EncodeError(CborError):
    """CBOR encoding error"""
    pass


class DecodeError(CborError):
    """CBOR decoding error"""
    pass


class FrameTooLargeError(CborError):
    """Frame exceeds size limits"""
    def __init__(self, size: int, max_size: int):
        super().__init__(f"Frame too large: {size} bytes (max {max_size})")
        self.size = size
        self.max = max_size


class InvalidFrameError(CborError):
    """Invalid frame structure"""
    pass


class UnexpectedEofError(CborError):
    """Unexpected end of stream"""
    pass


class ProtocolError(CborError):
    """Protocol error"""
    pass


class HandshakeError(CborError):
    """Handshake failed"""
    pass


def encode_frame(frame: Frame) -> bytes:
    """Encode a frame to CBOR bytes

    Args:
        frame: Frame to encode

    Returns:
        CBOR-encoded bytes

    Raises:
        EncodeError: If encoding fails
    """
    if not CBOR2_AVAILABLE:
        raise EncodeError("cbor2 not available")

    frame_map = {}

    # Required fields
    frame_map[Keys.VERSION] = frame.version
    frame_map[Keys.FRAME_TYPE] = int(frame.frame_type)

    # Message ID
    if frame.id.is_uuid():
        frame_map[Keys.ID] = frame.id.uuid_bytes  # CBOR bytes
    else:
        frame_map[Keys.ID] = frame.id.uint_value  # CBOR integer

    # Sequence number
    frame_map[Keys.SEQ] = frame.seq

    # Optional fields
    if frame.content_type is not None:
        frame_map[Keys.CONTENT_TYPE] = frame.content_type

    if frame.meta is not None:
        frame_map[Keys.META] = frame.meta

    if frame.payload is not None:
        frame_map[Keys.PAYLOAD] = frame.payload

    if frame.len is not None:
        frame_map[Keys.LEN] = frame.len

    if frame.offset is not None:
        frame_map[Keys.OFFSET] = frame.offset

    if frame.eof is not None:
        frame_map[Keys.EOF] = frame.eof

    if frame.cap is not None:
        frame_map[Keys.CAP] = frame.cap

    try:
        return cbor2.dumps(frame_map)
    except Exception as e:
        raise EncodeError(f"CBOR encoding failed: {e}")


def decode_frame(data: bytes) -> Frame:
    """Decode a frame from CBOR bytes

    Args:
        data: CBOR-encoded bytes

    Returns:
        Decoded Frame

    Raises:
        DecodeError: If decoding fails
        InvalidFrameError: If frame structure is invalid
    """
    if not CBOR2_AVAILABLE:
        raise DecodeError("cbor2 not available")

    try:
        frame_map = cbor2.loads(data)
    except Exception as e:
        raise DecodeError(f"CBOR decoding failed: {e}")

    if not isinstance(frame_map, dict):
        raise InvalidFrameError("expected map")

    # Convert keys to integers if they're not already
    lookup = {}
    for k, v in frame_map.items():
        if isinstance(k, int):
            lookup[k] = v

    # Extract required fields
    version = lookup.get(Keys.VERSION)
    if version is None:
        raise InvalidFrameError("missing version")

    frame_type_u8 = lookup.get(Keys.FRAME_TYPE)
    if frame_type_u8 is None:
        raise InvalidFrameError("missing frame_type")

    frame_type = FrameType.from_u8(frame_type_u8)
    if frame_type is None:
        raise InvalidFrameError(f"invalid frame_type: {frame_type_u8}")

    # Extract ID
    id_value = lookup.get(Keys.ID)
    if id_value is None:
        id_obj = MessageId.default()
    elif isinstance(id_value, bytes):
        if len(id_value) == 16:
            id_obj = MessageId(id_value)
        else:
            # Treat as uint fallback
            id_obj = MessageId(0)
    elif isinstance(id_value, int):
        id_obj = MessageId(id_value)
    else:
        id_obj = MessageId(0)

    # Extract seq
    seq = lookup.get(Keys.SEQ, 0)

    # Optional fields
    content_type = lookup.get(Keys.CONTENT_TYPE)
    meta = lookup.get(Keys.META)
    payload = lookup.get(Keys.PAYLOAD)
    len_field = lookup.get(Keys.LEN)
    offset = lookup.get(Keys.OFFSET)
    eof = lookup.get(Keys.EOF)
    cap = lookup.get(Keys.CAP)

    return Frame(
        frame_type=frame_type,
        id=id_obj,
        version=version,
        seq=seq,
        content_type=content_type,
        meta=meta,
        payload=payload,
        len=len_field,
        offset=offset,
        eof=eof,
        cap=cap,
    )


def write_frame(writer: BinaryIO, frame: Frame, limits: Limits) -> None:
    """Write a length-prefixed CBOR frame

    Args:
        writer: Binary output stream
        frame: Frame to write
        limits: Protocol limits

    Raises:
        FrameTooLargeError: If frame exceeds limits
        CborError: If write fails
    """
    frame_bytes = encode_frame(frame)

    if len(frame_bytes) > limits.max_frame:
        raise FrameTooLargeError(len(frame_bytes), limits.max_frame)

    if len(frame_bytes) > MAX_FRAME_HARD_LIMIT:
        raise FrameTooLargeError(len(frame_bytes), MAX_FRAME_HARD_LIMIT)

    length = len(frame_bytes)
    length_bytes = length.to_bytes(4, byteorder='big')

    try:
        writer.write(length_bytes)
        writer.write(frame_bytes)
        writer.flush()
    except Exception as e:
        raise CborError(f"Write failed: {e}")


def read_frame(reader: BinaryIO, limits: Limits) -> Optional[Frame]:
    """Read a length-prefixed CBOR frame from a reader

    Returns Ok(None) on clean EOF, Err(UnexpectedEof) on partial read.

    Args:
        reader: Binary input stream
        limits: Protocol limits

    Returns:
        Frame or None on EOF

    Raises:
        UnexpectedEofError: On partial read
        FrameTooLargeError: If frame exceeds limits
        CborError: If read fails
    """
    # Read 4-byte length prefix
    try:
        len_buf = reader.read(4)
    except Exception as e:
        raise CborError(f"Read failed: {e}")

    if len(len_buf) == 0:
        # Clean EOF
        return None

    if len(len_buf) < 4:
        raise UnexpectedEofError()

    length = int.from_bytes(len_buf, byteorder='big')

    # Validate length
    if length > limits.max_frame or length > MAX_FRAME_HARD_LIMIT:
        raise FrameTooLargeError(length, min(limits.max_frame, MAX_FRAME_HARD_LIMIT))

    # Read payload
    try:
        payload = reader.read(length)
    except Exception as e:
        raise CborError(f"Read failed: {e}")

    if len(payload) < length:
        raise UnexpectedEofError()

    frame = decode_frame(payload)
    return frame


class FrameReader:
    """CBOR frame reader with buffering"""

    def __init__(self, reader: BinaryIO, limits: Optional[Limits] = None):
        """Create a new frame reader

        Args:
            reader: Binary input stream
            limits: Optional limits (defaults to Limits.default())
        """
        self.reader = reader
        self.limits = limits if limits is not None else Limits.default()

    @classmethod
    def new(cls, reader: BinaryIO) -> "FrameReader":
        """Create a new frame reader with default limits"""
        return cls(reader)

    @classmethod
    def with_limits(cls, reader: BinaryIO, limits: Limits) -> "FrameReader":
        """Create a new frame reader with specified limits"""
        return cls(reader, limits)

    def set_limits(self, limits: Limits) -> None:
        """Update limits (after handshake)"""
        self.limits = limits

    def read(self) -> Optional[Frame]:
        """Read the next frame

        Returns:
            Frame or None on EOF

        Raises:
            CborError: If read fails
        """
        return read_frame(self.reader, self.limits)

    def get_limits(self) -> Limits:
        """Get the current limits"""
        return self.limits

    def inner_mut(self) -> BinaryIO:
        """Get mutable access to the underlying reader"""
        return self.reader


class FrameWriter:
    """CBOR frame writer with buffering"""

    def __init__(self, writer: BinaryIO, limits: Optional[Limits] = None):
        """Create a new frame writer

        Args:
            writer: Binary output stream
            limits: Optional limits (defaults to Limits.default())
        """
        self.writer = writer
        self.limits = limits if limits is not None else Limits.default()

    @classmethod
    def new(cls, writer: BinaryIO) -> "FrameWriter":
        """Create a new frame writer with default limits"""
        return cls(writer)

    @classmethod
    def with_limits(cls, writer: BinaryIO, limits: Limits) -> "FrameWriter":
        """Create a new frame writer with specified limits"""
        return cls(writer, limits)

    def set_limits(self, limits: Limits) -> None:
        """Update limits (after handshake)"""
        self.limits = limits

    def write(self, frame: Frame) -> None:
        """Write a frame

        Args:
            frame: Frame to write

        Raises:
            CborError: If write fails
        """
        write_frame(self.writer, frame, self.limits)

    def write_response_with_chunking(self, request_id: MessageId, payload: bytes) -> None:
        """Write a response with automatic chunking for large payloads.

        Payloads <= max_chunk produce a single END frame.
        Payloads > max_chunk produce CHUNK frames + final END frame.

        Args:
            request_id: The request message ID
            payload: The full response payload

        Raises:
            CborError: If write fails
        """
        max_chunk = self.limits.max_chunk

        if len(payload) <= max_chunk:
            frame = Frame.end(request_id, payload)
            self.write(frame)
            return

        offset = 0
        seq = 0
        while offset < len(payload):
            chunk_size = min(len(payload) - offset, max_chunk)
            chunk_data = payload[offset:offset + chunk_size]
            offset += chunk_size

            if offset < len(payload):
                frame = Frame.chunk(request_id, seq, chunk_data)
                self.write(frame)
                seq += 1
            else:
                frame = Frame.end(request_id, chunk_data)
                self.write(frame)

    def get_limits(self) -> Limits:
        """Get the current limits"""
        return self.limits

    def inner_mut(self) -> BinaryIO:
        """Get mutable access to the underlying writer"""
        return self.writer


@dataclass
class HandshakeResult:
    """Result of handshake negotiation"""
    limits: Limits
    manifest: bytes


def handshake(
    reader: FrameReader,
    writer: FrameWriter,
) -> HandshakeResult:
    """Perform HELLO handshake and extract plugin manifest (host side - sends first)

    Args:
        reader: Frame reader
        writer: Frame writer

    Returns:
        HandshakeResult with negotiated limits and manifest

    Raises:
        HandshakeError: If handshake fails
    """
    # Send our HELLO
    our_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)
    writer.write(our_hello)

    # Read their HELLO (should include manifest)
    their_frame = reader.read()
    if their_frame is None:
        raise HandshakeError("connection closed before receiving HELLO")

    if their_frame.frame_type != FrameType.HELLO:
        raise HandshakeError(f"expected HELLO, got {their_frame.frame_type}")

    # Extract manifest - REQUIRED for plugins
    manifest = their_frame.hello_manifest()
    if manifest is None:
        raise HandshakeError("Plugin HELLO missing required manifest")

    # Negotiate minimum of both
    their_max_frame = their_frame.hello_max_frame() or DEFAULT_MAX_FRAME
    their_max_chunk = their_frame.hello_max_chunk() or DEFAULT_MAX_CHUNK

    limits = Limits(
        max_frame=min(DEFAULT_MAX_FRAME, their_max_frame),
        max_chunk=min(DEFAULT_MAX_CHUNK, their_max_chunk),
    )

    # Update both reader and writer with negotiated limits
    reader.set_limits(limits)
    writer.set_limits(limits)

    return HandshakeResult(limits=limits, manifest=bytes(manifest))


def handshake_accept(
    reader: FrameReader,
    writer: FrameWriter,
    manifest: bytes,
) -> Limits:
    """Accept HELLO handshake with manifest (plugin side - receives first, sends manifest in response)

    Reads host's HELLO, sends our HELLO with manifest, returns negotiated limits.
    The manifest is REQUIRED - plugins MUST provide their manifest.

    Args:
        reader: Frame reader
        writer: Frame writer
        manifest: Plugin manifest bytes (REQUIRED)

    Returns:
        Negotiated limits

    Raises:
        HandshakeError: If handshake fails
    """
    # Read their HELLO first (host initiates)
    their_frame = reader.read()
    if their_frame is None:
        raise HandshakeError("connection closed before receiving HELLO")

    if their_frame.frame_type != FrameType.HELLO:
        raise HandshakeError(f"expected HELLO, got {their_frame.frame_type}")

    # Negotiate minimum of both
    their_max_frame = their_frame.hello_max_frame() or DEFAULT_MAX_FRAME
    their_max_chunk = their_frame.hello_max_chunk() or DEFAULT_MAX_CHUNK

    limits = Limits(
        max_frame=min(DEFAULT_MAX_FRAME, their_max_frame),
        max_chunk=min(DEFAULT_MAX_CHUNK, their_max_chunk),
    )

    # Send our HELLO with manifest
    our_hello = Frame.hello_with_manifest(limits.max_frame, limits.max_chunk, manifest)
    writer.write(our_hello)

    # Update both reader and writer with negotiated limits
    reader.set_limits(limits)
    writer.set_limits(limits)

    return limits


# =============================================================================
# Async I/O - for AsyncPluginHost
# =============================================================================


class AsyncFrameReader:
    """Async frame reader for reading CBOR frames from an async stream"""

    def __init__(self, stream):
        """Create async frame reader

        Args:
            stream: Async readable stream (asyncio.StreamReader or similar)
        """
        self.stream = stream
        self.limits = Limits(max_frame=DEFAULT_MAX_FRAME, max_chunk=DEFAULT_MAX_CHUNK)

    def set_limits(self, limits: Limits):
        """Update frame size limits"""
        self.limits = limits

    async def read(self) -> Optional[Frame]:
        """Read one frame from the stream

        Returns:
            Frame if read successfully, None on EOF

        Raises:
            CborError: If read fails
        """
        # Read 4-byte length prefix
        try:
            length_bytes = await self.stream.readexactly(4)
        except asyncio.IncompleteReadError:
            return None  # EOF
        except Exception as e:
            raise UnexpectedEofError(f"Failed to read length prefix: {e}")

        frame_len = int.from_bytes(length_bytes, byteorder='big')

        # Check against limits
        if frame_len > self.limits.max_frame:
            raise FrameTooLargeError(frame_len, self.limits.max_frame)

        # Read frame data
        try:
            frame_data = await self.stream.readexactly(frame_len)
        except asyncio.IncompleteReadError:
            raise UnexpectedEofError("Incomplete frame data")
        except Exception as e:
            raise CborError(f"Failed to read frame data: {e}")

        # Decode frame
        return decode_frame(frame_data)


class AsyncFrameWriter:
    """Async frame writer for writing CBOR frames to an async stream"""

    def __init__(self, stream):
        """Create async frame writer

        Args:
            stream: Async writable stream (asyncio.StreamWriter or similar)
        """
        self.stream = stream
        self.limits = Limits(max_frame=DEFAULT_MAX_FRAME, max_chunk=DEFAULT_MAX_CHUNK)

    def set_limits(self, limits: Limits):
        """Update frame size limits"""
        self.limits = limits

    async def write(self, frame: Frame):
        """Write one frame to the stream

        Args:
            frame: Frame to write

        Raises:
            CborError: If write fails
        """
        # Encode frame
        frame_data = encode_frame(frame)
        frame_len = len(frame_data)

        # Check against limits
        if frame_len > self.limits.max_frame:
            raise FrameTooLargeError(frame_len, self.limits.max_frame)

        # Write length prefix + frame data
        length_bytes = frame_len.to_bytes(4, byteorder='big')
        self.stream.write(length_bytes + frame_data)
        await self.stream.drain()


@dataclass
class HandshakeResult:
    """Result of handshake"""
    limits: Limits
    manifest: bytes


async def handshake_async(
    reader: AsyncFrameReader,
    writer: AsyncFrameWriter,
) -> HandshakeResult:
    """Perform HELLO handshake (host side - sends first, expects manifest in response)

    Sends host's HELLO, reads plugin's HELLO with manifest, returns negotiated limits and manifest.

    Args:
        reader: Async frame reader
        writer: Async frame writer

    Returns:
        HandshakeResult with limits and manifest

    Raises:
        HandshakeError: If handshake fails
    """
    # Send our HELLO
    our_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)
    await writer.write(our_hello)

    # Read their HELLO (should include manifest)
    their_frame = await reader.read()
    if their_frame is None:
        raise HandshakeError("connection closed before receiving HELLO")

    if their_frame.frame_type != FrameType.HELLO:
        raise HandshakeError(f"expected HELLO, got {their_frame.frame_type}")

    # Extract manifest - REQUIRED for plugins
    manifest = their_frame.hello_manifest()
    if manifest is None:
        raise HandshakeError("Plugin HELLO missing required manifest")

    # Negotiate minimum of both
    their_max_frame = their_frame.hello_max_frame() or DEFAULT_MAX_FRAME
    their_max_chunk = their_frame.hello_max_chunk() or DEFAULT_MAX_CHUNK

    limits = Limits(
        max_frame=min(DEFAULT_MAX_FRAME, their_max_frame),
        max_chunk=min(DEFAULT_MAX_CHUNK, their_max_chunk),
    )

    # Update both reader and writer with negotiated limits
    reader.set_limits(limits)
    writer.set_limits(limits)

    return HandshakeResult(limits=limits, manifest=bytes(manifest))
