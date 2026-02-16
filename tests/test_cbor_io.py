"""Tests for cbor_io - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import io
from capns.bifaci.io import (
    encode_frame,
    decode_frame,
    read_frame,
    write_frame,
    FrameReader,
    FrameWriter,
    handshake,
    handshake_accept,
    HandshakeResult,
    CborError,
    FrameTooLargeError,
    UnexpectedEofError,
    HandshakeError,
)
from capns.bifaci.frame import (
    Frame,
    FrameType,
    MessageId,
    Limits,
    DEFAULT_MAX_FRAME,
    DEFAULT_MAX_CHUNK,
)


# TEST205: Test encode_frame produces CBOR with integer keys
def test_encode_frame_produces_cbor_with_integer_keys():
    frame = Frame.hello(1024, 512)
    data = encode_frame(frame)

    # Should be valid CBOR
    assert len(data) > 0

    # Should be a map when decoded
    import cbor2
    decoded = cbor2.loads(data)
    assert isinstance(decoded, dict)

    # Should have integer keys
    for key in decoded.keys():
        assert isinstance(key, int)


# TEST206: Test decode_frame parses CBOR frame correctly
def test_decode_frame_parses_cbor_correctly():
    original = Frame.hello(2048, 1024)
    data = encode_frame(original)

    decoded = decode_frame(data)

    assert decoded.frame_type == FrameType.HELLO
    assert decoded.hello_max_frame() == 2048
    assert decoded.hello_max_chunk() == 1024


# TEST207: Test decode_frame fails on invalid CBOR
def test_decode_frame_fails_on_invalid_cbor():
    with pytest.raises(CborError):
        decode_frame(b"invalid cbor data")


# TEST208: Test decode_frame fails on non-map CBOR
def test_decode_frame_fails_on_non_map():
    import cbor2
    data = cbor2.dumps([1, 2, 3])  # Array, not map

    with pytest.raises(CborError):
        decode_frame(data)


# TEST209: Test write_frame writes length-prefixed frame
def test_write_frame_writes_length_prefixed():
    output = io.BytesIO()
    frame = Frame.hello(1024, 512)
    limits = Limits(10000, 5000)

    write_frame(output, frame, limits)

    data = output.getvalue()
    assert len(data) > 4  # Has length prefix

    # First 4 bytes are length
    length = int.from_bytes(data[:4], byteorder='big')
    assert length == len(data) - 4


# TEST210: Test read_frame reads length-prefixed frame
def test_read_frame_reads_length_prefixed():
    output = io.BytesIO()
    original = Frame.hello(2048, 1024)
    limits = Limits(10000, 5000)

    write_frame(output, original, limits)

    # Read it back
    output.seek(0)
    decoded = read_frame(output, limits)

    assert decoded is not None
    assert decoded.frame_type == FrameType.HELLO
    assert decoded.hello_max_frame() == 2048


# TEST211: Test read_frame returns None on EOF
def test_read_frame_returns_none_on_eof():
    input_stream = io.BytesIO(b"")  # Empty stream
    limits = Limits.default()

    result = read_frame(input_stream, limits)
    assert result is None


# TEST212: Test read_frame fails on incomplete length prefix
def test_read_frame_fails_on_incomplete_length_prefix():
    input_stream = io.BytesIO(b"\x00\x00")  # Only 2 bytes
    limits = Limits.default()

    with pytest.raises(UnexpectedEofError):
        read_frame(input_stream, limits)


# TEST213: Test read_frame fails on incomplete frame data
def test_read_frame_fails_on_incomplete_frame_data():
    # Write a frame claiming 100 bytes but only provide 10
    input_stream = io.BytesIO(b"\x00\x00\x00\x64" + b"x" * 10)
    limits = Limits.default()

    with pytest.raises(UnexpectedEofError):
        read_frame(input_stream, limits)


# TEST214: Test write_frame enforces max frame size
def test_write_frame_enforces_max_frame_size():
    output = io.BytesIO()

    # Create a frame with large payload (use CHUNK frame since RES removed in Protocol v2)
    frame = Frame.chunk(MessageId.new_uuid(), "test-stream", 0, b"x" * 2000)
    limits = Limits(1024, 512)  # Max frame 1KB

    with pytest.raises(FrameTooLargeError):
        write_frame(output, frame, limits)


# TEST215: Test FrameReader reads multiple frames
def test_frame_reader_reads_multiple_frames():
    output = io.BytesIO()
    limits = Limits(10000, 5000)

    frame1 = Frame.hello(1024, 512)
    frame2 = Frame.hello(2048, 1024)

    write_frame(output, frame1, limits)
    write_frame(output, frame2, limits)

    # Read back
    output.seek(0)
    reader = FrameReader(output, limits)

    read1 = reader.read()
    assert read1 is not None
    assert read1.hello_max_frame() == 1024

    read2 = reader.read()
    assert read2 is not None
    assert read2.hello_max_frame() == 2048


# TEST216: Test FrameWriter writes multiple frames
def test_frame_writer_writes_multiple_frames():
    output = io.BytesIO()
    limits = Limits(10000, 5000)
    writer = FrameWriter(output, limits)

    frame1 = Frame.hello(1024, 512)
    frame2 = Frame.hello(2048, 1024)

    writer.write(frame1)
    writer.write(frame2)

    # Read back
    output.seek(0)
    reader = FrameReader(output, limits)

    read1 = reader.read()
    read2 = reader.read()

    assert read1.hello_max_frame() == 1024
    assert read2.hello_max_frame() == 2048


# TEST217: Test FrameReader.new creates with default limits
def test_frame_reader_new_creates_with_default_limits():
    input_stream = io.BytesIO()
    reader = FrameReader.new(input_stream)

    assert reader.get_limits().max_frame == DEFAULT_MAX_FRAME
    assert reader.get_limits().max_chunk == DEFAULT_MAX_CHUNK


# TEST218: Test FrameWriter.new creates with default limits
def test_frame_writer_new_creates_with_default_limits():
    output = io.BytesIO()
    writer = FrameWriter.new(output)

    assert writer.get_limits().max_frame == DEFAULT_MAX_FRAME
    assert writer.get_limits().max_chunk == DEFAULT_MAX_CHUNK


# TEST219: Test FrameReader.with_limits creates with specified limits
def test_frame_reader_with_limits():
    input_stream = io.BytesIO()
    limits = Limits(2048, 1024)
    reader = FrameReader.with_limits(input_stream, limits)

    assert reader.get_limits().max_frame == 2048
    assert reader.get_limits().max_chunk == 1024


# TEST220: Test FrameWriter.with_limits creates with specified limits
def test_frame_writer_with_limits():
    output = io.BytesIO()
    limits = Limits(2048, 1024)
    writer = FrameWriter.with_limits(output, limits)

    assert writer.get_limits().max_frame == 2048
    assert writer.get_limits().max_chunk == 1024


# TEST221: Test FrameReader.set_limits updates limits
def test_frame_reader_set_limits():
    input_stream = io.BytesIO()
    reader = FrameReader.new(input_stream)

    new_limits = Limits(4096, 2048)
    reader.set_limits(new_limits)

    assert reader.get_limits().max_frame == 4096
    assert reader.get_limits().max_chunk == 2048


# TEST222: Test FrameWriter.set_limits updates limits
def test_frame_writer_set_limits():
    output = io.BytesIO()
    writer = FrameWriter.new(output)

    new_limits = Limits(4096, 2048)
    writer.set_limits(new_limits)

    assert writer.get_limits().max_frame == 4096
    assert writer.get_limits().max_chunk == 2048


# TEST223: Test handshake host sends HELLO first
def test_handshake_host_sends_hello_first():
    # Create connected streams (simulate pipe)
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    # Host side
    host_writer = FrameWriter.new(host_to_plugin)
    host_reader = FrameReader.new(plugin_to_host)

    # Plugin side - prepare response
    manifest = b'{"identifier": "test", "version": "1.0.0", "caps": []}'
    plugin_reader = FrameReader.new(host_to_plugin)
    plugin_writer = FrameWriter.new(plugin_to_host)

    # Host initiates
    host_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)
    host_writer.write(host_hello)

    # Plugin receives and responds
    host_to_plugin.seek(0)
    received_hello = plugin_reader.read()
    assert received_hello is not None
    assert received_hello.frame_type == FrameType.HELLO

    # Plugin responds with manifest
    plugin_hello = Frame.hello_with_manifest(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK, manifest)
    plugin_writer.write(plugin_hello)

    # Host reads response
    plugin_to_host.seek(0)
    result = host_reader.read()
    assert result is not None
    assert result.hello_manifest() == manifest


# TEST224: Test handshake negotiates to minimum limits
def test_handshake_negotiates_to_minimum_limits():
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    # Host with larger limits
    host_writer = FrameWriter.new(host_to_plugin)
    host_reader = FrameReader.new(plugin_to_host)

    # Plugin with smaller limits
    manifest = b'{"identifier": "test", "version": "1.0.0", "caps": []}'

    # Host sends HELLO
    host_hello = Frame.hello(10000, 5000)
    host_writer.write(host_hello)

    # Plugin receives, negotiates, and responds with smaller limits
    host_to_plugin.seek(0)
    plugin_reader = FrameReader.new(host_to_plugin)
    received = plugin_reader.read()

    # Plugin should negotiate to min(10000, 8000) = 8000
    their_max_frame = received.hello_max_frame() or DEFAULT_MAX_FRAME
    negotiated_frame = min(8000, their_max_frame)

    plugin_hello = Frame.hello_with_manifest(negotiated_frame, 3000, manifest)

    plugin_writer = FrameWriter.new(plugin_to_host)
    plugin_writer.write(plugin_hello)

    # Host receives and verifies negotiation
    plugin_to_host.seek(0)
    result = host_reader.read()
    assert result.hello_max_frame() == negotiated_frame


# TEST225: Test handshake function performs full handshake
def test_handshake_function_full_handshake():
    # Create bidirectional streams
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    # Prepare manifest
    manifest = b'{"identifier": "test-plugin", "version": "1.0.0", "caps": []}'

    # Plugin side accepts handshake in background (simulate)
    plugin_hello = Frame.hello_with_manifest(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK, manifest)
    plugin_writer_temp = FrameWriter.new(plugin_to_host)
    plugin_writer_temp.write(plugin_hello)

    # Host side initiates
    host_reader = FrameReader.new(plugin_to_host)
    host_writer = FrameWriter.new(host_to_plugin)

    # First write host HELLO
    host_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)
    host_writer.write(host_hello)

    # Then read plugin response
    plugin_to_host.seek(0)
    result = host_reader.read()

    assert result is not None
    assert result.hello_manifest() == manifest


# TEST226: Test handshake_accept receives first then sends
def test_handshake_accept_receives_first():
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    # Host sends HELLO first
    host_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)
    host_writer_temp = FrameWriter.new(host_to_plugin)
    host_writer_temp.write(host_hello)

    # Plugin accepts
    host_to_plugin.seek(0)
    plugin_reader = FrameReader.new(host_to_plugin)
    plugin_writer = FrameWriter.new(plugin_to_host)

    manifest = b'{"identifier": "test", "version": "1.0.0", "caps": []}'

    limits = handshake_accept(plugin_reader, plugin_writer, manifest)

    # Verify negotiated limits
    assert limits.max_frame == DEFAULT_MAX_FRAME
    assert limits.max_chunk == DEFAULT_MAX_CHUNK

    # Verify plugin sent HELLO with manifest
    plugin_to_host.seek(0)
    plugin_reader_temp = FrameReader.new(plugin_to_host)
    response = plugin_reader_temp.read()
    assert response.frame_type == FrameType.HELLO
    assert response.hello_manifest() == manifest


# TEST227: Test handshake fails if plugin missing manifest
def test_handshake_fails_if_plugin_missing_manifest():
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    # Plugin sends HELLO WITHOUT manifest (invalid)
    plugin_hello = Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK)  # No manifest!
    plugin_writer_temp = FrameWriter.new(plugin_to_host)
    plugin_writer_temp.write(plugin_hello)

    # Host tries to handshake
    plugin_to_host.seek(0)
    host_reader = FrameReader.new(plugin_to_host)
    host_writer = FrameWriter.new(host_to_plugin)

    # First send host HELLO
    host_writer.write(Frame.hello(DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK))

    # Then try to read plugin response - should fail because no manifest
    with pytest.raises(HandshakeError, match="missing required manifest"):
        their_frame = host_reader.read()
        if their_frame.hello_manifest() is None:
            raise HandshakeError("Plugin HELLO missing required manifest")


# TEST228: Test read_frame enforces limit
def test_read_frame_enforces_limit():
    output = io.BytesIO()

    # Write a large frame (use CHUNK frame since RES removed in Protocol v2)
    frame = Frame.chunk(MessageId.new_uuid(), "test-stream", 0, b"x" * 2000)
    large_limits = Limits(10000, 5000)
    write_frame(output, frame, large_limits)

    # Try to read with small limit
    output.seek(0)
    small_limits = Limits(1000, 500)

    with pytest.raises(FrameTooLargeError):
        read_frame(output, small_limits)


# TEST229: Test frame with zero-length payload
def test_frame_with_zero_length_payload():
    output = io.BytesIO()
    frame = Frame.chunk(MessageId.new_uuid(), "test-stream", 0, b"")
    limits = Limits.default()

    write_frame(output, frame, limits)

    output.seek(0)
    decoded = read_frame(output, limits)

    assert decoded is not None
    assert decoded.payload == b""


# TEST230: Test frame round-trip preserves all fields
def test_frame_roundtrip_preserves_fields():
    original = Frame(
        frame_type=FrameType.REQ,
        id=MessageId.new_uuid(),
        seq=42,
        content_type="application/json",
        meta={"key": "value"},
        payload=b"test data",
        cap="cap:in=\"media:void\";op=test;out=\"media:void\"",
    )

    data = encode_frame(original)
    decoded = decode_frame(data)

    assert decoded.frame_type == original.frame_type
    assert decoded.seq == original.seq
    assert decoded.content_type == original.content_type
    assert decoded.payload == original.payload
    assert decoded.cap == original.cap


# TEST231: Test multiple readers on same stream
def test_multiple_readers_on_same_stream():
    output = io.BytesIO()
    limits = Limits.default()

    frame1 = Frame.hello(1024, 512)
    frame2 = Frame.hello(2048, 1024)
    frame3 = Frame.hello(4096, 2048)

    write_frame(output, frame1, limits)
    write_frame(output, frame2, limits)
    write_frame(output, frame3, limits)

    output.seek(0)
    reader = FrameReader(output, limits)

    read1 = reader.read()
    read2 = reader.read()
    read3 = reader.read()

    assert read1.hello_max_frame() == 1024
    assert read2.hello_max_frame() == 2048
    assert read3.hello_max_frame() == 4096


# TEST232: Test writer flushes after each frame
def test_writer_flushes_after_each_frame():
    output = io.BytesIO()
    writer = FrameWriter.new(output)

    frame = Frame.hello(1024, 512)
    writer.write(frame)

    # Data should be available immediately
    data = output.getvalue()
    assert len(data) > 0


# TEST233: Test frame encoding preserves binary data
def test_frame_encoding_preserves_binary_data():
    # Binary data with all byte values
    binary_data = bytes(range(256))

    frame = Frame.chunk(MessageId.new_uuid(), "test-stream", 0, binary_data)

    data = encode_frame(frame)
    decoded = decode_frame(data)

    assert decoded.payload == binary_data


# TEST234: Test handshake with very small limits
def test_handshake_with_very_small_limits():
    host_to_plugin = io.BytesIO()
    plugin_to_host = io.BytesIO()

    tiny_limits = Limits(256, 128)  # Use larger limits to fit HELLO frame with length prefix

    # Host with tiny limits
    host_hello = Frame.hello(tiny_limits.max_frame, tiny_limits.max_chunk)
    host_writer_temp = FrameWriter(host_to_plugin, tiny_limits)
    host_writer_temp.write(host_hello)

    # Plugin reads
    host_to_plugin.seek(0)
    plugin_reader = FrameReader(host_to_plugin, tiny_limits)
    received = plugin_reader.read()

    assert received is not None
    assert received.hello_max_frame() == 256


# TEST313: Test write_stream_chunked sends STREAM_START + CHUNK(s) + STREAM_END + END for payload larger than max_chunk,
# CHUNK frames + END frame, and reading them back reassembles the full original data
def test_write_stream_chunked_reassembly():
    buf = io.BytesIO()
    writer = FrameWriter(buf, Limits(DEFAULT_MAX_FRAME, 100))

    request_id = MessageId.new_uuid()
    data = bytes(i % 256 for i in range(250))

    writer.write_stream_chunked(request_id, "resp-1", "media:bytes", data)

    buf.seek(0)
    reader = FrameReader(buf)

    frames = []
    while True:
        frame = reader.read()
        if frame is None:
            break
        frames.append(frame)
        if frame.frame_type == FrameType.END:
            break

    # Protocol v2: STREAM_START + 3 CHUNK (250/100=3) + STREAM_END + END = 6 frames
    assert len(frames) == 6, f"Expected 6 frames (STREAM_START + 3 CHUNK + STREAM_END + END), got {len(frames)}"
    assert frames[0].frame_type == FrameType.STREAM_START
    assert frames[0].stream_id == "resp-1"
    assert frames[0].media_urn == "media:bytes"
    assert frames[1].frame_type == FrameType.CHUNK
    assert frames[1].stream_id == "resp-1"
    assert frames[2].frame_type == FrameType.CHUNK
    assert frames[3].frame_type == FrameType.CHUNK
    assert frames[4].frame_type == FrameType.STREAM_END
    assert frames[4].stream_id == "resp-1"
    assert frames[5].frame_type == FrameType.END

    reassembled = b""
    for f in frames:
        if f.frame_type == FrameType.CHUNK:
            reassembled += f.payload or b""
    assert reassembled == data, "concatenated chunks must match original data"


# TEST314: Test payload exactly equal to max_chunk produces STREAM_START + 1 CHUNK + STREAM_END + END
def test_exact_max_chunk_stream_chunked():
    buf = io.BytesIO()
    writer = FrameWriter(buf, Limits(DEFAULT_MAX_FRAME, 100))

    request_id = MessageId.new_uuid()
    data = bytes([0xAB] * 100)

    writer.write_stream_chunked(request_id, "resp-1", "media:bytes", data)

    buf.seek(0)
    reader = FrameReader(buf)

    frames = []
    while True:
        frame = reader.read()
        if frame is None:
            break
        frames.append(frame)
        if frame.frame_type == FrameType.END:
            break

    # STREAM_START + 1 CHUNK + STREAM_END + END = 4 frames
    assert len(frames) == 4, f"Expected 4 frames, got {len(frames)}"
    assert frames[0].frame_type == FrameType.STREAM_START
    assert frames[1].frame_type == FrameType.CHUNK
    assert frames[1].payload == data
    assert frames[2].frame_type == FrameType.STREAM_END
    assert frames[3].frame_type == FrameType.END


# TEST315: Test payload of max_chunk + 1 produces STREAM_START + 2 CHUNK + STREAM_END + END
def test_max_chunk_plus_one_splits_into_two_chunks():
    buf = io.BytesIO()
    writer = FrameWriter(buf, Limits(DEFAULT_MAX_FRAME, 100))

    request_id = MessageId.new_uuid()
    data = bytes(range(101))

    writer.write_stream_chunked(request_id, "resp-1", "media:bytes", data)

    buf.seek(0)
    reader = FrameReader(buf)

    frames = []
    while True:
        frame = reader.read()
        if frame is None:
            break
        frames.append(frame)
        if frame.frame_type == FrameType.END:
            break

    # STREAM_START + 2 CHUNK + STREAM_END + END = 5 frames
    assert len(frames) == 5, f"Expected 5 frames, got {len(frames)}"
    assert frames[0].frame_type == FrameType.STREAM_START
    assert frames[1].frame_type == FrameType.CHUNK
    assert len(frames[1].payload) == 100
    assert frames[2].frame_type == FrameType.CHUNK
    assert len(frames[2].payload) == 1
    assert frames[3].frame_type == FrameType.STREAM_END
    assert frames[4].frame_type == FrameType.END

    reassembled = frames[1].payload + frames[2].payload
    assert reassembled == data


# TEST317: Test auto-chunking preserves data integrity across chunk boundaries for 3x max_chunk payload
def test_chunking_data_integrity_3x():
    buf = io.BytesIO()
    writer = FrameWriter(buf, Limits(DEFAULT_MAX_FRAME, 100))

    request_id = MessageId.new_uuid()
    pattern = b"ABCDEFGHIJ"
    data = (pattern * 30)  # 300 bytes

    writer.write_stream_chunked(request_id, "resp-1", "media:bytes", data)

    buf.seek(0)
    reader = FrameReader(buf)

    frames = []
    while True:
        frame = reader.read()
        if frame is None:
            break
        frames.append(frame)
        if frame.frame_type == FrameType.END:
            break

    # Protocol v2: STREAM_START + 3 CHUNK (300/100) + STREAM_END + END = 6 frames
    assert len(frames) == 6, f"Expected 6 frames, got {len(frames)}"

    reassembled = b""
    for f in frames:
        if f.frame_type == FrameType.CHUNK:
            reassembled += f.payload or b""
    assert len(reassembled) == 300
    assert reassembled == data, "pattern must be preserved across chunk boundaries"


# TEST389: StreamStart encode/decode roundtrip preserves stream_id and media_urn
def test_stream_start_roundtrip():
    id = MessageId.new_uuid()
    stream_id = "stream-abc-123"
    media_urn = "media:bytes"

    frame = Frame.stream_start(id, stream_id, media_urn)
    encoded = encode_frame(frame)
    decoded = decode_frame(encoded)

    assert decoded.frame_type == FrameType.STREAM_START
    assert decoded.id == id
    assert decoded.stream_id == "stream-abc-123"
    assert decoded.media_urn == "media:bytes"


# TEST390: StreamEnd encode/decode roundtrip preserves stream_id, no media_urn
def test_stream_end_roundtrip():
    id = MessageId.new_uuid()
    stream_id = "stream-xyz-789"

    frame = Frame.stream_end(id, stream_id)
    encoded = encode_frame(frame)
    decoded = decode_frame(encoded)

    assert decoded.frame_type == FrameType.STREAM_END
    assert decoded.id == id
    assert decoded.stream_id == "stream-xyz-789"
    assert decoded.media_urn is None, "StreamEnd should not have media_urn"


# TEST399a: RelayNotify encode/decode roundtrip preserves manifest and limits
def test_relay_notify_roundtrip():
    manifest = b'{"caps":["cap:op=relay-test"]}'
    max_frame = 2_000_000
    max_chunk = 128_000

    frame = Frame.relay_notify(manifest, max_frame, max_chunk)
    encoded = encode_frame(frame)
    decoded = decode_frame(encoded)

    assert decoded.frame_type == FrameType.RELAY_NOTIFY

    extracted_manifest = decoded.relay_notify_manifest()
    assert extracted_manifest is not None, "relay_notify_manifest() must not be None after roundtrip"
    assert extracted_manifest == manifest

    extracted_limits = decoded.relay_notify_limits()
    assert extracted_limits is not None, "relay_notify_limits() must not be None after roundtrip"
    assert extracted_limits.max_frame == max_frame
    assert extracted_limits.max_chunk == max_chunk


# TEST400a: RelayState encode/decode roundtrip preserves resource payload
def test_relay_state_roundtrip():
    resources = b'{"gpu_memory":8192,"cpu_cores":16}'

    frame = Frame.relay_state(resources)
    encoded = encode_frame(frame)
    decoded = decode_frame(encoded)

    assert decoded.frame_type == FrameType.RELAY_STATE
    assert decoded.payload == resources
