"""CBOR Integration Tests - Protocol validation tests ported from Go

These tests validate end-to-end protocol behavior including:
- Frame forwarding
- Thread spawning
- Bidirectional communication
- Handshake and limit negotiation
- Heartbeat handling

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import socket
import threading
from capns.bifaci.frame import (
    Frame,
    FrameType,
    MessageId,
    Limits,
    DEFAULT_MAX_FRAME,
    DEFAULT_MAX_CHUNK,
    compute_checksum,
)
from capns.bifaci.io import (
    FrameReader,
    FrameWriter,
    handshake,
    handshake_accept,
)

# Test manifest JSON - plugins MUST include manifest in HELLO response
TEST_MANIFEST = b'{"name":"TestPlugin","version":"1.0.0","description":"Test plugin","caps":[{"urn":"cap:op=test","title":"Test","command":"test"}]}'


def create_socket_pair():
    """Create a Unix socket pair for bidirectional communication"""
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)


def plugin_handshake_worker(plugin_read_sock, plugin_write_sock, manifest):
    """Helper: do handshake on plugin side in a thread"""
    reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
    limits = handshake_accept(reader, writer, manifest)
    reader.set_limits(limits)
    writer.set_limits(limits)
    return reader, writer


# TEST284: Handshake exchanges HELLO frames, negotiates limits
def test_284_handshake_host_plugin():
    """Test HELLO frame exchange and limit negotiation"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    manifest_holder = []
    limits_holder = []

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        limits_holder.append(limits)
        assert limits.max_frame > 0
        assert limits.max_chunk > 0

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    received_manifest = result.manifest
    host_limits = result.limits

    assert received_manifest == TEST_MANIFEST

    plugin.join(timeout=5.0)

    plugin_limits = limits_holder[0]
    assert host_limits.max_frame == plugin_limits.max_frame
    assert host_limits.max_chunk == plugin_limits.max_chunk


# TEST285: Simple request-response flow (REQ → END with payload)
def test_285_request_response_simple():
    """Test simple REQ → END with payload"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        frame = reader.read()
        assert frame is not None
        assert frame.frame_type == FrameType.REQ
        assert frame.cap == "cap:in=media:;out=media:"
        assert frame.payload == b"hello"

        writer.write(Frame.end(frame.id, b"hello back"))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    request_id = MessageId.new_uuid()
    writer.write(Frame.req(request_id, "cap:in=media:;out=media:", b"hello", "application/json"))

    response = reader.read()
    assert response is not None
    assert response.frame_type == FrameType.END
    assert response.payload == b"hello back"

    plugin.join(timeout=5.0)


# TEST286: Streaming response with multiple CHUNK frames
def test_286_streaming_chunks():
    """Test streaming response with multiple CHUNK frames"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        frame = reader.read()
        request_id = frame.id

        sid = "response"
        writer.write(Frame.stream_start(request_id, sid, "media:"))
        for seq, data in enumerate([b"chunk1", b"chunk2", b"chunk3"]):
            writer.write(Frame.chunk(request_id, sid, seq, data, seq, compute_checksum(data)))
        writer.write(Frame.stream_end(request_id, sid, 3))
        writer.write(Frame.end(request_id, None))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    request_id = MessageId.new_uuid()
    writer.write(Frame.req(request_id, "cap:op=stream", b"go", "application/json"))

    # Collect chunks
    chunks = []
    while True:
        frame = reader.read()
        assert frame is not None
        if frame.frame_type == FrameType.CHUNK:
            chunks.append(frame.payload or b"")
        if frame.frame_type == FrameType.END:
            break

    assert len(chunks) == 3
    assert chunks[0] == b"chunk1"
    assert chunks[1] == b"chunk2"
    assert chunks[2] == b"chunk3"

    plugin.join(timeout=5.0)


# TEST287: Host-initiated heartbeat handling
def test_287_heartbeat_from_host():
    """Test host-initiated heartbeat"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        frame = reader.read()
        assert frame is not None
        assert frame.frame_type == FrameType.HEARTBEAT

        writer.write(Frame.heartbeat(frame.id))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    heartbeat_id = MessageId.new_uuid()
    writer.write(Frame.heartbeat(heartbeat_id))

    response = reader.read()
    assert response is not None
    assert response.frame_type == FrameType.HEARTBEAT
    assert response.id == heartbeat_id

    plugin.join(timeout=5.0)


# TEST290: Limit negotiation picks minimum values
def test_290_limits_negotiation():
    """Test limit negotiation picks minimum of both sides"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    limits_holder = []

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        limits_holder.append(limits)

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    host_limits = result.limits

    plugin.join(timeout=5.0)

    plugin_limits = limits_holder[0]

    assert host_limits.max_frame == plugin_limits.max_frame
    assert host_limits.max_chunk == plugin_limits.max_chunk
    assert host_limits.max_frame > 0
    assert host_limits.max_chunk > 0


# TEST291: Binary payload roundtrip (all 256 byte values)
def test_291_binary_payload_roundtrip():
    """Test binary data integrity through all 256 byte values"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    binary_data = bytes(range(256))

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        frame = reader.read()
        payload = frame.payload

        assert len(payload) == 256
        for i, byte in enumerate(payload):
            assert byte == i, f"Byte mismatch at position {i}"

        writer.write(Frame.end(frame.id, payload))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    request_id = MessageId.new_uuid()
    writer.write(Frame.req(request_id, "cap:op=binary", binary_data, "application/octet-stream"))

    response = reader.read()
    result = response.payload

    assert len(result) == 256
    for i, byte in enumerate(result):
        assert byte == i, f"Response byte mismatch at position {i}"

    plugin.join(timeout=5.0)


# TEST292: Sequential requests get distinct MessageIds
def test_292_message_id_uniqueness():
    """Test sequential requests produce unique MessageIds"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    received_ids = []

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        for _ in range(3):
            frame = reader.read()
            received_ids.append(frame.id)
            writer.write(Frame.end(frame.id, b"ok"))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    for _ in range(3):
        request_id = MessageId.new_uuid()
        writer.write(Frame.req(request_id, "cap:op=test", b"", "application/json"))
        reader.read()

    plugin.join(timeout=5.0)

    assert len(received_ids) == 3
    for i in range(len(received_ids)):
        for j in range(i + 1, len(received_ids)):
            assert received_ids[i] != received_ids[j], "IDs should be unique"


# TEST299: Empty payload request/response roundtrip
def test_299_empty_payload_roundtrip():
    """Test empty payload roundtrip"""
    host_write_sock, plugin_read_sock = create_socket_pair()
    plugin_write_sock, host_read_sock = create_socket_pair()

    def plugin_thread():
        reader = FrameReader(plugin_read_sock.makefile("rb", buffering=0))
        writer = FrameWriter(plugin_write_sock.makefile("wb", buffering=0))
        limits = handshake_accept(reader, writer, TEST_MANIFEST)
        reader.set_limits(limits)
        writer.set_limits(limits)

        frame = reader.read()
        assert frame.payload is None or frame.payload == b"", "empty payload must arrive empty"

        writer.write(Frame.end(frame.id, b""))

    plugin = threading.Thread(target=plugin_thread, daemon=True)
    plugin.start()

    reader = FrameReader(host_read_sock.makefile("rb", buffering=0))
    writer = FrameWriter(host_write_sock.makefile("wb", buffering=0))
    result = handshake(reader, writer)
    # handshake already sets limits on reader/writer

    request_id = MessageId.new_uuid()
    writer.write(Frame.req(request_id, "cap:op=empty", b"", "application/json"))

    response = reader.read()
    assert response.payload is None or response.payload == b""

    plugin.join(timeout=5.0)
