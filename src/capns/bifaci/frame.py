"""CBOR Frame Types for Plugin Communication

This module defines the binary CBOR frame format for plugin communication.
Frames use integer keys for compact encoding and support native binary payloads.

## Frame Format

Each frame is a CBOR map with integer keys:
{
  0: version (u8, always 2)
  1: frame_type (u8)
  2: id (bytes[16] or uint)
  3: seq (u64)
  4: content_type (tstr, optional)
  5: meta (map, optional)
  6: payload (bstr, optional)
  7: len (u64, optional - total payload length for chunked)
  8: offset (u64, optional - byte offset in chunked stream)
  9: eof (bool, optional - true on final chunk)
  10: cap (tstr, optional - cap URN for requests)
}

## Frame Types

- HELLO (0): Handshake to negotiate limits
- REQ (1): Request to invoke a cap
- CHUNK (3): Streaming data chunk
- END (4): Stream complete marker
- LOG (5): Log/progress message
- ERR (6): Error message
- HEARTBEAT (7): Health monitoring ping/pong
- STREAM_START (8): Announce new stream for request
- STREAM_END (9): End a specific stream
- RELAY_NOTIFY (10): Relay capability advertisement (slave → master)
- RELAY_STATE (11): Relay host system resources + cap demands (master → slave)
"""

import uuid as uuid_module
from typing import Optional, Dict, Any
from enum import IntEnum
from dataclasses import dataclass


# Protocol version. Version 2: Result-based emitters, negotiated chunk limits, per-request errors.
PROTOCOL_VERSION = 2

# Default maximum frame size (3.5 MB) - safe margin below 3.75MB limit
# Larger payloads automatically use CHUNK frames
DEFAULT_MAX_FRAME = 3_670_016

# Default maximum chunk size (256 KB)
DEFAULT_MAX_CHUNK = 262_144


class FrameType(IntEnum):
    """Frame type discriminator"""
    HELLO = 0  # Handshake frame for negotiating limits
    REQ = 1  # Request to invoke a cap
    # RES (2) removed in Protocol v2 — use STREAM_START/CHUNK/STREAM_END/END
    CHUNK = 3  # Streaming data chunk
    END = 4  # Stream complete marker
    LOG = 5  # Log/progress message
    ERR = 6  # Error message
    HEARTBEAT = 7  # Health monitoring ping/pong
    STREAM_START = 8  # Announce new stream for request (multiplexed streaming)
    STREAM_END = 9  # End a specific stream (multiplexed streaming)
    RELAY_NOTIFY = 10  # Relay capability advertisement (slave → master)
    RELAY_STATE = 11   # Relay host system resources + cap demands (master → slave)

    @classmethod
    def from_u8(cls, v: int) -> Optional["FrameType"]:
        """Convert u8 to FrameType, returns None if invalid"""
        try:
            return cls(v)
        except ValueError:
            return None


class MessageId:
    """Message ID - either a 16-byte UUID or a simple integer"""

    def __init__(self, value):
        """Create MessageId from UUID bytes or integer

        Args:
            value: Either bytes (16-byte UUID) or int (uint64)
        """
        if isinstance(value, bytes):
            if len(value) != 16:
                raise ValueError("UUID must be exactly 16 bytes")
            self.uuid_bytes = value
            self.uint_value = None
        elif isinstance(value, int):
            if value < 0:
                raise ValueError("Uint must be non-negative")
            self.uuid_bytes = None
            self.uint_value = value
        else:
            raise TypeError(f"MessageId must be bytes or int, got {type(value)}")

    @classmethod
    def new_uuid(cls) -> "MessageId":
        """Create a new random UUID message ID"""
        return cls(uuid_module.uuid4().bytes)

    @classmethod
    def from_uuid_str(cls, s: str) -> Optional["MessageId"]:
        """Create from a UUID string"""
        try:
            u = uuid_module.UUID(s)
            return cls(u.bytes)
        except ValueError:
            return None

    @classmethod
    def from_cbor(cls, value) -> "MessageId":
        """Create MessageId from CBOR value (bytes for UUID, int for Uint)"""
        if isinstance(value, bytes):
            return cls(value)
        elif isinstance(value, int):
            return cls(value)
        else:
            raise TypeError(f"CBOR value must be bytes or int for MessageId, got {type(value)}")

    def to_uuid_string(self) -> Optional[str]:
        """Convert to UUID string if this is a UUID"""
        if self.uuid_bytes is not None:
            return str(uuid_module.UUID(bytes=self.uuid_bytes))
        return None

    def to_string(self) -> str:
        """Convert to string representation (works for both UUID and uint)"""
        if self.uuid_bytes is not None:
            return str(uuid_module.UUID(bytes=self.uuid_bytes))
        else:
            return str(self.uint_value)

    def as_bytes(self) -> bytes:
        """Get as bytes for comparison"""
        if self.uuid_bytes is not None:
            return self.uuid_bytes
        else:
            # Convert uint to 8-byte big-endian
            return self.uint_value.to_bytes(8, byteorder='big')

    def is_uuid(self) -> bool:
        """Check if this is a UUID variant"""
        return self.uuid_bytes is not None

    def to_cbor(self):
        """Convert to CBOR-encodable value (bytes for UUID, int for Uint)."""
        if self.uuid_bytes is not None:
            return self.uuid_bytes
        else:
            return self.uint_value

    def is_uint(self) -> bool:
        """Check if this is a Uint variant"""
        return self.uint_value is not None

    def __eq__(self, other):
        if not isinstance(other, MessageId):
            return False
        # Different variants are never equal
        if self.is_uuid() != other.is_uuid():
            return False
        if self.is_uuid():
            return self.uuid_bytes == other.uuid_bytes
        else:
            return self.uint_value == other.uint_value

    def __hash__(self):
        if self.uuid_bytes is not None:
            return hash(('uuid', self.uuid_bytes))
        else:
            return hash(('uint', self.uint_value))

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        if self.uuid_bytes is not None:
            return f"MessageId::Uuid({self.to_string()})"
        else:
            return f"MessageId::Uint({self.to_string()})"

    @classmethod
    def default(cls) -> "MessageId":
        """Create default MessageId (UUID)"""
        return cls.new_uuid()


@dataclass
class Limits:
    """Negotiated protocol limits"""
    max_frame: int  # Maximum frame size in bytes
    max_chunk: int  # Maximum chunk payload size in bytes

    @classmethod
    def default(cls) -> "Limits":
        """Create default limits"""
        return cls(
            max_frame=DEFAULT_MAX_FRAME,
            max_chunk=DEFAULT_MAX_CHUNK,
        )


def compute_checksum(data: bytes) -> int:
    """Compute FNV-1a 64-bit checksum of bytes.

    This is a simple, fast hash function suitable for detecting transmission errors.
    """
    FNV_OFFSET_BASIS = 0xcbf29ce484222325
    FNV_PRIME = 0x100000001b3

    hash_value = FNV_OFFSET_BASIS
    for byte in data:
        hash_value ^= byte
        hash_value = (hash_value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF  # Keep 64-bit
    return hash_value


class Frame:
    """A CBOR protocol frame"""

    def __init__(
        self,
        frame_type: FrameType,
        id: MessageId,
        version: int = PROTOCOL_VERSION,
        seq: int = 0,
        content_type: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        payload: Optional[bytes] = None,
        len: Optional[int] = None,
        offset: Optional[int] = None,
        eof: Optional[bool] = None,
        cap: Optional[str] = None,
        stream_id: Optional[str] = None,
        media_urn: Optional[str] = None,
        routing_id: Optional[MessageId] = None,
        index: Optional[int] = None,
        chunk_count: Optional[int] = None,
        checksum: Optional[int] = None,
    ):
        """Create a new frame

        Args:
            frame_type: Type of frame
            id: Message ID for correlation
            version: Protocol version (always 2)
            seq: Sequence number within a stream
            content_type: Content type of payload (MIME-like)
            meta: Metadata map
            payload: Binary payload
            len: Total length for chunked transfers (first chunk only)
            offset: Byte offset in chunked stream
            eof: End of stream marker
            cap: Cap URN (for requests)
            stream_id: Stream identifier for multiplexing
            media_urn: Media URN for stream typing
            routing_id: Routing ID assigned by RelaySwitch (separates logical ID from routing)
            index: Chunk sequence index within stream (CHUNK frames only, starts at 0)
            chunk_count: Total chunk count (STREAM_END frames only, by source's reckoning)
            checksum: FNV-1a checksum of payload (CHUNK frames only)
        """
        self.version = version
        self.frame_type = frame_type
        self.id = id
        self.seq = seq
        self.content_type = content_type
        self.meta = meta
        self.payload = payload
        self.len = len
        self.offset = offset
        self.eof = eof
        self.cap = cap
        self.stream_id = stream_id
        self.media_urn = media_urn
        self.routing_id = routing_id
        self.index = index
        self.chunk_count = chunk_count
        self.checksum = checksum

    @classmethod
    def new(cls, frame_type: FrameType, id: MessageId) -> "Frame":
        """Create a new frame with required fields"""
        return cls(frame_type=frame_type, id=id)

    @classmethod
    def hello(cls, max_frame: int, max_chunk: int) -> "Frame":
        """Create a HELLO frame for handshake (host side - no manifest)"""
        meta = {
            "max_frame": max_frame,
            "max_chunk": max_chunk,
            "version": PROTOCOL_VERSION,
        }
        frame = cls.new(FrameType.HELLO, MessageId(0))
        frame.meta = meta
        return frame

    @classmethod
    def hello_with_manifest(cls, max_frame: int, max_chunk: int, manifest: bytes) -> "Frame":
        """Create a HELLO frame for handshake with manifest (plugin side)

        The manifest is JSON-encoded plugin metadata including name, version, and caps.
        This is the ONLY way for plugins to communicate their capabilities.
        """
        meta = {
            "max_frame": max_frame,
            "max_chunk": max_chunk,
            "version": PROTOCOL_VERSION,
            "manifest": manifest,
        }
        frame = cls.new(FrameType.HELLO, MessageId(0))
        frame.meta = meta
        return frame

    @classmethod
    def req(cls, id: MessageId, cap_urn: str, payload: bytes, content_type: str) -> "Frame":
        """Create a REQ frame for invoking a cap"""
        frame = cls.new(FrameType.REQ, id)
        frame.cap = cap_urn
        frame.payload = payload
        frame.content_type = content_type
        return frame

    @classmethod
    def chunk(cls, req_id: MessageId, stream_id: str, seq: int, payload: bytes, index: int, checksum: int) -> "Frame":
        """Create a CHUNK frame for streaming (Protocol v2: stream_id required)"""
        frame = cls.new(FrameType.CHUNK, req_id)
        frame.stream_id = stream_id
        frame.seq = seq
        frame.payload = payload
        frame.index = index
        frame.checksum = checksum
        return frame

    @classmethod
    def chunk_with_offset(
        cls,
        req_id: MessageId,
        stream_id: str,
        seq: int,
        payload: bytes,
        offset: int,
        total_len: Optional[int],
        is_last: bool,
    ) -> "Frame":
        """Create a CHUNK frame with offset info (Protocol v2: stream_id required)"""
        frame = cls.new(FrameType.CHUNK, req_id)
        frame.stream_id = stream_id
        frame.seq = seq
        frame.payload = payload
        frame.offset = offset
        if seq == 0:
            frame.len = total_len
        if is_last:
            frame.eof = True
        return frame

    @classmethod
    def end(cls, id: MessageId, final_payload: Optional[bytes] = None) -> "Frame":
        """Create an END frame to mark stream completion"""
        frame = cls.new(FrameType.END, id)
        frame.payload = final_payload
        frame.eof = True
        return frame

    @classmethod
    def log(cls, id: MessageId, level: str, message: str) -> "Frame":
        """Create a LOG frame for progress/status"""
        meta = {
            "level": level,
            "message": message,
        }
        frame = cls.new(FrameType.LOG, id)
        frame.meta = meta
        return frame

    @classmethod
    def err(cls, id: MessageId, code: str, message: str) -> "Frame":
        """Create an ERR frame"""
        meta = {
            "code": code,
            "message": message,
        }
        frame = cls.new(FrameType.ERR, id)
        frame.meta = meta
        return frame

    @classmethod
    def heartbeat(cls, id: MessageId) -> "Frame":
        """Create a HEARTBEAT frame for health monitoring

        Either side can send; receiver must respond with HEARTBEAT using the same ID.
        """
        return cls.new(FrameType.HEARTBEAT, id)

    @classmethod
    def stream_start(cls, req_id: MessageId, stream_id: str, media_urn: str) -> "Frame":
        """Create a STREAM_START frame to announce a new stream within a request.
        Used for multiplexed streaming - multiple streams can exist per request.

        Args:
            req_id: Request message ID this stream belongs to
            stream_id: Unique identifier for this stream within the request
            media_urn: Media URN describing the stream's content type
        """
        frame = cls.new(FrameType.STREAM_START, req_id)
        frame.stream_id = stream_id
        frame.media_urn = media_urn
        return frame

    @classmethod
    def stream_end(cls, req_id: MessageId, stream_id: str, chunk_count: int) -> "Frame":
        """Create a STREAM_END frame to mark completion of a specific stream.
        After this, any CHUNK for this stream_id is a fatal protocol error.

        Args:
            req_id: Request message ID this stream belongs to
            stream_id: Identifier of the stream that is ending
            chunk_count: Total number of chunks sent in this stream (by source's reckoning)
        """
        frame = cls.new(FrameType.STREAM_END, req_id)
        frame.stream_id = stream_id
        frame.chunk_count = chunk_count
        return frame

    @classmethod
    def relay_notify(cls, manifest: bytes, max_frame: int, max_chunk: int) -> "Frame":
        """Create a RELAY_NOTIFY frame for capability advertisement (slave → master).

        Args:
            manifest: Aggregate manifest bytes (JSON-encoded list of all plugin caps)
            max_frame: Maximum frame size for the relay connection
            max_chunk: Maximum chunk size for the relay connection
        """
        frame = cls.new(FrameType.RELAY_NOTIFY, MessageId(0))
        frame.meta = {
            "manifest": manifest,
            "max_frame": max_frame,
            "max_chunk": max_chunk,
        }
        return frame

    @classmethod
    def relay_state(cls, resources: bytes) -> "Frame":
        """Create a RELAY_STATE frame for host system resources + cap demands (master → slave).

        Args:
            resources: Opaque resource payload (CBOR or JSON encoded by the host)
        """
        frame = cls.new(FrameType.RELAY_STATE, MessageId(0))
        frame.payload = resources
        return frame

    def relay_notify_manifest(self) -> Optional[bytes]:
        """Extract manifest from RelayNotify metadata.
        Returns None if not a RelayNotify frame or no manifest present."""
        if self.frame_type != FrameType.RELAY_NOTIFY:
            return None
        if self.meta is None:
            return None
        manifest = self.meta.get("manifest")
        if isinstance(manifest, bytes):
            return manifest
        return None

    def relay_notify_limits(self) -> Optional["Limits"]:
        """Extract limits from RelayNotify metadata.
        Returns None if not a RelayNotify frame or limits are missing."""
        if self.frame_type != FrameType.RELAY_NOTIFY:
            return None
        if self.meta is None:
            return None
        max_frame = self.meta.get("max_frame")
        max_chunk = self.meta.get("max_chunk")
        if not isinstance(max_frame, int) or not isinstance(max_chunk, int):
            return None
        if max_frame <= 0 or max_chunk <= 0:
            return None
        return Limits(max_frame=max_frame, max_chunk=max_chunk)

    def is_eof(self) -> bool:
        """Check if this is the final frame in a stream"""
        return self.eof is True

    def is_flow_frame(self) -> bool:
        """Return True if this frame type participates in flow ordering (seq tracking).
        Non-flow frames (Hello, Heartbeat, RelayNotify, RelayState) bypass seq assignment.
        (matches Rust Frame::is_flow_frame and Go Frame.IsFlowFrame)
        """
        return self.frame_type not in (
            FrameType.HELLO,
            FrameType.HEARTBEAT,
            FrameType.RELAY_NOTIFY,
            FrameType.RELAY_STATE,
        )

    def error_code(self) -> Optional[str]:
        """Get error code if this is an ERR frame"""
        if self.frame_type != FrameType.ERR:
            return None
        if self.meta is None:
            return None
        code = self.meta.get("code")
        return code if isinstance(code, str) else None

    def error_message(self) -> Optional[str]:
        """Get error message if this is an ERR frame"""
        if self.frame_type != FrameType.ERR:
            return None
        if self.meta is None:
            return None
        message = self.meta.get("message")
        return message if isinstance(message, str) else None

    def log_level(self) -> Optional[str]:
        """Get log level if this is a LOG frame"""
        if self.frame_type != FrameType.LOG:
            return None
        if self.meta is None:
            return None
        level = self.meta.get("level")
        return level if isinstance(level, str) else None

    def log_message(self) -> Optional[str]:
        """Get log message if this is a LOG frame"""
        if self.frame_type != FrameType.LOG:
            return None
        if self.meta is None:
            return None
        message = self.meta.get("message")
        return message if isinstance(message, str) else None

    def hello_max_frame(self) -> Optional[int]:
        """Extract max_frame from HELLO metadata"""
        if self.frame_type != FrameType.HELLO:
            return None
        if self.meta is None:
            return None
        max_frame = self.meta.get("max_frame")
        if isinstance(max_frame, int) and max_frame > 0:
            return max_frame
        return None

    def hello_max_chunk(self) -> Optional[int]:
        """Extract max_chunk from HELLO metadata"""
        if self.frame_type != FrameType.HELLO:
            return None
        if self.meta is None:
            return None
        max_chunk = self.meta.get("max_chunk")
        if isinstance(max_chunk, int) and max_chunk > 0:
            return max_chunk
        return None

    def hello_manifest(self) -> Optional[bytes]:
        """Extract manifest from HELLO metadata (plugin side sends this)

        Returns None if no manifest present (host HELLO) or not a HELLO frame.
        The manifest is JSON-encoded plugin metadata.
        """
        if self.frame_type != FrameType.HELLO:
            return None
        if self.meta is None:
            return None
        manifest = self.meta.get("manifest")
        if isinstance(manifest, bytes):
            return manifest
        return None

    @classmethod
    def default(cls) -> "Frame":
        """Create default frame (REQ with UUID)"""
        return cls.new(FrameType.REQ, MessageId.default())


# Integer keys for CBOR map fields
class Keys:
    """Integer keys for CBOR map fields"""
    VERSION = 0
    FRAME_TYPE = 1
    ID = 2
    SEQ = 3
    CONTENT_TYPE = 4
    META = 5
    PAYLOAD = 6
    LEN = 7
    OFFSET = 8
    EOF = 9
    CAP = 10
    STREAM_ID = 11
    MEDIA_URN = 12
    ROUTING_ID = 13
    INDEX = 14
    CHUNK_COUNT = 15
    CHECKSUM = 16


# =============================================================================
# FLOW KEY — Composite key for frame ordering (RID + optional XID)
# =============================================================================

class FlowKey:
    """Composite key identifying a frame flow for seq ordering.
    Absence of XID (routing_id) is a valid separate flow from presence of XID.
    (matches Rust FlowKey and Go FlowKey)
    """
    __slots__ = ("_rid", "_xid")

    def __init__(self, rid: str, xid: str):
        self._rid = rid
        self._xid = xid

    @classmethod
    def from_frame(cls, frame: "Frame") -> "FlowKey":
        """Extract a FlowKey from a frame."""
        rid = frame.id.to_string()
        xid = frame.routing_id.to_string() if frame.routing_id is not None else ""
        return cls(rid, xid)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlowKey):
            return NotImplemented
        return self._rid == other._rid and self._xid == other._xid

    def __hash__(self) -> int:
        return hash((self._rid, self._xid))

    def __repr__(self) -> str:
        return f"FlowKey(rid={self._rid!r}, xid={self._xid!r})"


# =============================================================================
# SEQ ASSIGNER — Centralized seq assignment at output stages
# =============================================================================

class SeqAssigner:
    """Assigns monotonically increasing seq numbers per FlowKey (RID + optional XID).
    Used at output stages (writer threads) to ensure each flow's frames
    carry a contiguous, gap-free seq sequence starting at 0.
    Non-flow frames (Hello, Heartbeat, RelayNotify, RelayState) are skipped.
    (matches Rust SeqAssigner and Go SeqAssigner)
    """

    def __init__(self):
        self._counters: dict = {}

    def assign(self, frame: "Frame") -> None:
        """Assign the next seq number to a frame.
        Non-flow frames are left unchanged (seq stays 0).
        """
        if not frame.is_flow_frame():
            return
        key = FlowKey.from_frame(frame)
        counter = self._counters.get(key, 0)
        frame.seq = counter
        self._counters[key] = counter + 1

    def remove(self, key: FlowKey) -> None:
        """Remove tracking for a flow (call after END/ERR delivery)."""
        self._counters.pop(key, None)
