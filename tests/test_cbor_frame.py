"""Tests for cbor_frame - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns.cbor_frame import (
    FrameType,
    MessageId,
    Limits,
    Frame,
    Keys,
    PROTOCOL_VERSION,
    DEFAULT_MAX_FRAME,
    DEFAULT_MAX_CHUNK,
)


# TEST171: Test all FrameType discriminants roundtrip through u8 conversion preserving identity
def test_frame_type_roundtrip():
    """Test all frame types roundtrip through u8 conversion"""
    for t in [
        FrameType.HELLO,
        FrameType.REQ,
        FrameType.RES,
        FrameType.CHUNK,
        FrameType.END,
        FrameType.LOG,
        FrameType.ERR,
        FrameType.HEARTBEAT,
    ]:
        v = int(t)
        recovered = FrameType.from_u8(v)
        assert recovered is not None, f"should recover frame type {t}"
        assert t == recovered


# TEST172: Test FrameType::from_u8 returns None for values outside the valid discriminant range
def test_invalid_frame_type():
    """Test invalid frame type values return None"""
    assert FrameType.from_u8(10) is None, "value 10 is one past StreamEnd"
    assert FrameType.from_u8(100) is None
    assert FrameType.from_u8(255) is None


# TEST173: Test FrameType discriminant values match the wire protocol specification exactly
def test_frame_type_discriminant_values():
    """Test frame type values match protocol specification"""
    assert FrameType.HELLO == 0
    assert FrameType.REQ == 1
    assert FrameType.RES == 2
    assert FrameType.CHUNK == 3
    assert FrameType.END == 4
    assert FrameType.LOG == 5
    assert FrameType.ERR == 6
    assert FrameType.HEARTBEAT == 7
    assert FrameType.STREAM_START == 8
    assert FrameType.STREAM_END == 9


# TEST174: Test MessageId::new_uuid generates valid UUID that roundtrips through string conversion
def test_message_id_uuid():
    """Test MessageId UUID generation and string roundtrip"""
    id = MessageId.new_uuid()
    s = id.to_uuid_string()
    assert s is not None, "should be uuid"
    recovered = MessageId.from_uuid_str(s)
    assert recovered is not None, "should parse"
    assert id == recovered


# TEST175: Test two MessageId::new_uuid calls produce distinct IDs (no collisions)
def test_message_id_uuid_uniqueness():
    """Test UUID uniqueness"""
    id1 = MessageId.new_uuid()
    id2 = MessageId.new_uuid()
    assert id1 != id2, "two UUIDs must be distinct"


# TEST176: Test MessageId::Uint does not produce a UUID string, to_uuid_string returns None
def test_message_id_uint_has_no_uuid_string():
    """Test Uint IDs have no UUID string representation"""
    id = MessageId(42)
    assert id.to_uuid_string() is None, "Uint IDs have no UUID representation"


# TEST177: Test MessageId::from_uuid_str rejects invalid UUID strings
def test_message_id_from_invalid_uuid_str():
    """Test invalid UUID strings are rejected"""
    assert MessageId.from_uuid_str("not-a-uuid") is None
    assert MessageId.from_uuid_str("") is None
    assert MessageId.from_uuid_str("12345678") is None


# TEST178: Test MessageId::as_bytes produces correct byte representations for Uuid and Uint variants
def test_message_id_as_bytes():
    """Test MessageId as_bytes for both variants"""
    uuid_id = MessageId.new_uuid()
    uuid_bytes = uuid_id.as_bytes()
    assert len(uuid_bytes) == 16, "UUID must be 16 bytes"

    uint_id = MessageId(0x0102030405060708)
    uint_bytes = uint_id.as_bytes()
    assert len(uint_bytes) == 8, "Uint ID must be 8 bytes big-endian"
    assert uint_bytes == bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])


# TEST179: Test MessageId::default creates a UUID variant (not Uint)
def test_message_id_default_is_uuid():
    """Test default MessageId is UUID"""
    id = MessageId.default()
    assert id.to_uuid_string() is not None, "default MessageId must be UUID"


# TEST180: Test Frame::hello without manifest produces correct HELLO frame for host side
def test_hello_frame():
    """Test HELLO frame creation (host side)"""
    frame = Frame.hello(1_000_000, 100_000)
    assert frame.frame_type == FrameType.HELLO
    assert frame.version == PROTOCOL_VERSION
    assert frame.hello_max_frame() == 1_000_000
    assert frame.hello_max_chunk() == 100_000
    assert frame.hello_manifest() is None, "Host HELLO must not include manifest"
    assert frame.payload is None, "HELLO has no payload"
    # ID should be Uint(0) for HELLO
    assert frame.id == MessageId(0)


# TEST181: Test Frame::hello_with_manifest produces HELLO with manifest bytes for plugin side
def test_hello_frame_with_manifest():
    """Test HELLO frame with manifest (plugin side)"""
    manifest_json = b'{"name":"TestPlugin","version":"1.0.0","description":"Test","caps":[]}'
    frame = Frame.hello_with_manifest(1_000_000, 100_000, manifest_json)
    assert frame.frame_type == FrameType.HELLO
    assert frame.hello_max_frame() == 1_000_000
    assert frame.hello_max_chunk() == 100_000
    manifest = frame.hello_manifest()
    assert manifest is not None, "Plugin HELLO must include manifest"
    assert manifest == manifest_json


# TEST182: Test Frame::req stores cap URN, payload, and content_type correctly
def test_req_frame():
    """Test REQ frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.req(id, "cap:op=test", b"payload", "application/json")
    assert frame.frame_type == FrameType.REQ
    assert frame.id == id
    assert frame.cap == "cap:op=test"
    assert frame.payload == b"payload"
    assert frame.content_type == "application/json"
    assert frame.version == PROTOCOL_VERSION


# TEST183: Test Frame::res stores payload and content_type for single complete response
def test_res_frame():
    """Test RES frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.res(id, b"result", "text/plain")
    assert frame.frame_type == FrameType.RES
    assert frame.id == id
    assert frame.payload == b"result"
    assert frame.content_type == "text/plain"


# TEST184: Test Frame::chunk stores seq and payload for streaming
def test_chunk_frame():
    """Test CHUNK frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.chunk(id, 3, b"data")
    assert frame.frame_type == FrameType.CHUNK
    assert frame.id == id
    assert frame.seq == 3
    assert frame.payload == b"data"
    assert not frame.is_eof(), "plain chunk should not be EOF"


# TEST185: Test Frame::err stores error code and message in metadata
def test_err_frame():
    """Test ERR frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.err(id, "NOT_FOUND", "Cap not found")
    assert frame.frame_type == FrameType.ERR
    assert frame.error_code() == "NOT_FOUND"
    assert frame.error_message() == "Cap not found"


# TEST186: Test Frame::log stores level and message in metadata
def test_log_frame():
    """Test LOG frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.log(id, "info", "Processing started")
    assert frame.frame_type == FrameType.LOG
    assert frame.id == id
    assert frame.log_level() == "info"
    assert frame.log_message() == "Processing started"


# TEST187: Test Frame::end with payload sets eof and optional final payload
def test_end_frame_with_payload():
    """Test END frame with payload"""
    id = MessageId.new_uuid()
    frame = Frame.end(id, b"final")
    assert frame.frame_type == FrameType.END
    assert frame.is_eof()
    assert frame.payload == b"final"


# TEST188: Test Frame::end without payload still sets eof marker
def test_end_frame_without_payload():
    """Test END frame without payload"""
    id = MessageId.new_uuid()
    frame = Frame.end(id, None)
    assert frame.frame_type == FrameType.END
    assert frame.is_eof()
    assert frame.payload is None


# TEST189: Test chunk_with_offset sets offset on all chunks but len only on seq=0
def test_chunk_with_offset():
    """Test CHUNK frame with offset information"""
    id = MessageId.new_uuid()

    # First chunk carries total len
    first = Frame.chunk_with_offset(id, 0, b"data", 0, 1000, False)
    assert first.seq == 0
    assert first.offset == 0
    assert first.len == 1000, "first chunk must carry total len"
    assert not first.is_eof()

    # Middle chunk doesn't carry len
    mid = Frame.chunk_with_offset(id, 3, b"mid", 500, 9999, False)
    assert mid.len is None, "non-first chunk must not carry len, seq != 0"
    assert mid.offset == 500

    # Last chunk sets EOF
    last = Frame.chunk_with_offset(id, 5, b"last", 900, None, True)
    assert last.is_eof()
    assert last.len is None


# TEST190: Test Frame::heartbeat creates minimal frame with no payload or metadata
def test_heartbeat_frame():
    """Test HEARTBEAT frame creation"""
    id = MessageId.new_uuid()
    frame = Frame.heartbeat(id)
    assert frame.frame_type == FrameType.HEARTBEAT
    assert frame.id == id
    assert frame.payload is None
    assert frame.meta is None
    assert frame.seq == 0


# TEST191: Test error_code and error_message return None for non-Err frame types
def test_error_accessors_on_non_err_frame():
    """Test error accessors return None for non-ERR frames"""
    req = Frame.req(MessageId.new_uuid(), "cap:op=test", b"", "text/plain")
    assert req.error_code() is None, "REQ must have no error_code"
    assert req.error_message() is None, "REQ must have no error_message"

    hello = Frame.hello(1000, 500)
    assert hello.error_code() is None


# TEST192: Test log_level and log_message return None for non-Log frame types
def test_log_accessors_on_non_log_frame():
    """Test log accessors return None for non-LOG frames"""
    req = Frame.req(MessageId.new_uuid(), "cap:op=test", b"", "text/plain")
    assert req.log_level() is None, "REQ must have no log_level"
    assert req.log_message() is None, "REQ must have no log_message"


# TEST193: Test hello_max_frame and hello_max_chunk return None for non-Hello frame types
def test_hello_accessors_on_non_hello_frame():
    """Test hello accessors return None for non-HELLO frames"""
    err = Frame.err(MessageId.new_uuid(), "E", "m")
    assert err.hello_max_frame() is None
    assert err.hello_max_chunk() is None
    assert err.hello_manifest() is None


# TEST194: Test Frame::new sets version and defaults correctly, optional fields are None
def test_frame_new_defaults():
    """Test Frame.new sets correct defaults"""
    id = MessageId.new_uuid()
    frame = Frame.new(FrameType.CHUNK, id)
    assert frame.version == PROTOCOL_VERSION
    assert frame.frame_type == FrameType.CHUNK
    assert frame.id == id
    assert frame.seq == 0
    assert frame.content_type is None
    assert frame.meta is None
    assert frame.payload is None
    assert frame.len is None
    assert frame.offset is None
    assert frame.eof is None
    assert frame.cap is None


# TEST195: Test Frame::default creates a Req frame (the documented default)
def test_frame_default():
    """Test Frame.default creates REQ frame"""
    frame = Frame.default()
    assert frame.frame_type == FrameType.REQ
    assert frame.version == PROTOCOL_VERSION


# TEST196: Test is_eof returns false when eof field is None (unset)
def test_is_eof_when_none():
    """Test is_eof with None"""
    frame = Frame.new(FrameType.CHUNK, MessageId(0))
    assert not frame.is_eof(), "eof=None must mean not EOF"


# TEST197: Test is_eof returns false when eof field is explicitly Some(false)
def test_is_eof_when_false():
    """Test is_eof with explicit False"""
    frame = Frame.new(FrameType.CHUNK, MessageId(0))
    frame.eof = False
    assert not frame.is_eof()


# TEST198: Test Limits::default provides the documented default values
def test_limits_default():
    """Test Limits.default values"""
    limits = Limits.default()
    assert limits.max_frame == DEFAULT_MAX_FRAME
    assert limits.max_chunk == DEFAULT_MAX_CHUNK
    assert limits.max_frame == 3_670_016, "default max_frame = 3.5 MB"
    assert limits.max_chunk == 262_144, "default max_chunk = 256 KB"


# TEST199: Test PROTOCOL_VERSION is 2
def test_protocol_version_constant():
    """Test PROTOCOL_VERSION constant"""
    assert PROTOCOL_VERSION == 2


# TEST200: Test integer key constants match the protocol specification
def test_key_constants():
    """Test Keys constants match specification"""
    assert Keys.VERSION == 0
    assert Keys.FRAME_TYPE == 1
    assert Keys.ID == 2
    assert Keys.SEQ == 3
    assert Keys.CONTENT_TYPE == 4
    assert Keys.META == 5
    assert Keys.PAYLOAD == 6
    assert Keys.LEN == 7
    assert Keys.OFFSET == 8
    assert Keys.EOF == 9
    assert Keys.CAP == 10


# TEST201: Test hello_with_manifest preserves binary manifest data (not just JSON text)
def test_hello_manifest_binary_data():
    """Test manifest preserves binary data"""
    binary_manifest = bytes([0x00, 0x01, 0xFF, 0xFE, 0x80])
    frame = Frame.hello_with_manifest(1000, 500, binary_manifest)
    assert frame.hello_manifest() == binary_manifest


# TEST202: Test MessageId Eq/Hash semantics: equal UUIDs are equal, different ones are not
def test_message_id_equality_and_hash():
    """Test MessageId equality and hashing"""
    id1 = MessageId(bytes([1] * 16))
    id2 = MessageId(bytes([1] * 16))
    id3 = MessageId(bytes([2] * 16))

    assert id1 == id2
    assert id1 != id3

    # Test hashing
    id_set = {id1}
    assert id2 in id_set, "equal IDs must hash the same"
    assert id3 not in id_set

    uint1 = MessageId(42)
    uint2 = MessageId(42)
    uint3 = MessageId(43)

    assert uint1 == uint2
    assert uint1 != uint3


# TEST203: Test Uuid and Uint variants of MessageId are never equal even for coincidental byte values
def test_message_id_cross_variant_inequality():
    """Test UUID and Uint variants are never equal"""
    uuid_id = MessageId(bytes([0] * 16))
    uint_id = MessageId(0)
    assert uuid_id != uint_id, "different variants must not be equal"


# TEST204: Test Frame::req with empty payload stores Some(empty vec) not None
def test_req_frame_empty_payload():
    """Test REQ frame with empty payload"""
    frame = Frame.req(MessageId.new_uuid(), "cap:op=test", b"", "text/plain")
    assert frame.payload == b"", "empty payload is still bytes, not None"
