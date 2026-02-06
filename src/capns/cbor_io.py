"""CBOR I/O - Reading and Writing CBOR Frames

This module provides streaming CBOR frame encoding/decoding over pipes.
Frames are written as length-prefixed CBOR.

## Wire Format

```
┌─────────────────────────────────────────────────────────┐
│  4 bytes: u32 big-endian length                         │
├─────────────────────────────────────────────────────────┤
│  N bytes: CBOR-encoded Frame                            │
└─────────────────────────────────────────────────────────┘
```

The CBOR payload is a map with integer keys.
"""

import struct
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
)


# Maximum frame size (16 MB) - hard limit to prevent memory exhaustion
MAX_FRAME_HARD_LIMIT = 16 * 1024 * 1024


class CborError(Exception):
    """Base CBOR error"""
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
        frame_map[Keys.ID] = frame.id.as_bytes()
    else:
        frame_map[Keys.ID] = frame.id.uint_value

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
        raise EncodeError(str(e))


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
        raise DecodeError(str(e))

    if not isinstance(frame_map, dict):
        raise InvalidFrameError("expected map")

    # Extract required fields
    if Keys.VERSION not in frame_map:
        raise InvalidFrameError("missing version")
    version = int(frame_map[Keys.VERSION])

    if Keys.FRAME_TYPE not in frame_map:
        raise InvalidFrameError("missing frame_type")
    frame_type_u8 = int(frame_map[Keys.FRAME_TYPE])
    frame_type = FrameType.from_u8(frame_type_u8)
    if frame_type is None:
        raise InvalidFrameError(f"invalid frame_type: {frame_type_u8}")

    if Keys.ID not in frame_map:
        raise InvalidFrameError("missing id")
    id_value = frame_map[Keys.ID]
    if isinstance(id_value, bytes):
        if len(id_value) == 16:
            id = MessageId(id_value)
        else:
            # Invalid UUID length, treat as uint 0
            id = MessageId(0)
    elif isinstance(id_value, int):
        id = MessageId(id_value)
    else:
        id = MessageId(0)

    seq = int(frame_map.get(Keys.SEQ, 0))

    # Optional fields
    content_type = frame_map.get(Keys.CONTENT_TYPE)
    meta = frame_map.get(Keys.META)
    payload = frame_map.get(Keys.PAYLOAD)
    len_value = frame_map.get(Keys.LEN)
    offset = frame_map.get(Keys.OFFSET)
    eof = frame_map.get(Keys.EOF)
    cap = frame_map.get(Keys.CAP)

    return Frame(
        version=version,
        frame_type=frame_type,
        id=id,
        seq=seq,
        content_type=content_type,
        meta=meta,
        payload=payload,
        len=len_value,
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
    """
    frame_bytes = encode_frame(frame)

    if len(frame_bytes) > limits.max_frame:
        raise FrameTooLargeError(len(frame_bytes), limits.max_frame)

    if len(frame_bytes) > MAX_FRAME_HARD_LIMIT:
        raise FrameTooLargeError(len(frame_bytes), MAX_FRAME_HARD_LIMIT)

    # Write 4-byte length prefix (big-endian)
    length = struct.pack(">I", len(frame_bytes))
    writer.write(length)
    writer.write(frame_bytes)
    writer.flush()


def read_frame(reader: BinaryIO, limits: Limits) -> Optional[Frame]:
    """Read a length-prefixed CBOR frame

    Args:
        reader: Binary input stream
        limits: Protocol limits

    Returns:
        Frame if available, None on clean EOF

    Raises:
        UnexpectedEofError: On partial read
        FrameTooLargeError: If frame exceeds limits
    """
    # Read 4-byte length prefix
    length_bytes = reader.read(4)
    if len(length_bytes) == 0:
        # Clean EOF
        return None
    if len(length_bytes) < 4:
        raise UnexpectedEofError()

    length = struct.unpack(">I", length_bytes)[0]

    # Validate length
    max_allowed = min(limits.max_frame, MAX_FRAME_HARD_LIMIT)
    if length > max_allowed:
        raise FrameTooLargeError(length, max_allowed)

    # Read payload
    payload = reader.read(length)
    if len(payload) < length:
        raise UnexpectedEofError()

    return decode_frame(payload)


class FrameReader:
    """CBOR frame reader with buffering"""

    def __init__(self, reader: BinaryIO, limits: Optional[Limits] = None):
        """Create a new frame reader

        Args:
            reader: Binary input stream
            limits: Optional protocol limits (defaults to standard limits)
        """
        self.reader = reader
        self.limits = limits or Limits.default()

    def set_limits(self, limits: Limits) -> None:
        """Update limits (after handshake)"""
        self.limits = limits

    def read(self) -> Optional[Frame]:
        """Read the next frame"""
        return read_frame(self.reader, self.limits)


class FrameWriter:
    """CBOR frame writer with buffering"""

    def __init__(self, writer: BinaryIO, limits: Optional[Limits] = None):
        """Create a new frame writer

        Args:
            writer: Binary output stream
            limits: Optional protocol limits (defaults to standard limits)
        """
        self.writer = writer
        self.limits = limits or Limits.default()

    def set_limits(self, limits: Limits) -> None:
        """Update limits (after handshake)"""
        self.limits = limits

    def write(self, frame: Frame) -> None:
        """Write a frame"""
        write_frame(self.writer, frame, self.limits)

    def write_chunked(self, id: MessageId, content_type: str, data: bytes) -> None:
        """Write a large payload as multiple chunks

        This splits the payload into chunks respecting max_chunk and writes
        them as CHUNK frames with proper offset/len/eof markers.

        Args:
            id: Message ID for all chunks
            content_type: Content type
            data: Payload data to chunk
        """
        total_len = len(data)
        max_chunk = self.limits.max_chunk

        if total_len == 0:
            # Empty payload - send single chunk with eof
            frame = Frame.chunk(id, 0, b"")
            frame.content_type = content_type
            frame.len = 0
            frame.offset = 0
            frame.eof = True
            self.write(frame)
            return

        seq = 0
        offset = 0

        while offset < total_len:
            chunk_size = min(max_chunk, total_len - offset)
            is_last = (offset + chunk_size >= total_len)

            chunk_data = data[offset:offset + chunk_size]

            frame = Frame.chunk(id, seq, chunk_data)
            frame.offset = offset

            # Set content_type and total len on first chunk
            if seq == 0:
                frame.content_type = content_type
                frame.len = total_len

            if is_last:
                frame.eof = True

            self.write(frame)

            seq += 1
            offset += chunk_size


@dataclass
class HandshakeResult:
    """Handshake result including manifest

    Returned by host side after receiving plugin's HELLO with manifest.
    """
    limits: Limits
    manifest: bytes  # Plugin manifest JSON data (REQUIRED from plugin)


def handshake(reader: FrameReader, writer: FrameWriter) -> HandshakeResult:
    """Perform HELLO handshake and extract plugin manifest (host side - sends first)

    Args:
        reader: Frame reader
        writer: Frame writer

    Returns:
        HandshakeResult with negotiated limits and plugin manifest

    Raises:
        HandshakeError: If handshake fails or manifest is missing
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

    return HandshakeResult(limits=limits, manifest=manifest)


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
        manifest: Plugin manifest JSON bytes (REQUIRED)

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
