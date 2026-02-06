"""Tests for async_plugin_host module

Tests for AsyncPluginHost, ResponseChunk, PluginResponse, and error types.
"""

import pytest

from capns.async_plugin_host import (
    ResponseChunk,
    PluginResponse,
    AsyncHostError,
    CborErrorWrapper,
    IoError,
    PluginError,
    UnexpectedFrameType,
    ProcessExited,
    Handshake,
    Closed,
    SendError,
    RecvError,
)
from capns.cbor_frame import FrameType


# TEST235: Test ResponseChunk stores payload, seq, offset, len, and eof fields correctly
def test_response_chunk():
    chunk = ResponseChunk(
        payload=b"hello",
        seq=0,
        offset=None,
        len=None,
        is_eof=False,
    )

    assert chunk.payload == b"hello"
    assert chunk.seq == 0
    assert chunk.offset is None
    assert chunk.len is None
    assert not chunk.is_eof


# TEST236: Test ResponseChunk with all fields populated preserves offset, len, and eof
def test_response_chunk_with_all_fields():
    chunk = ResponseChunk(
        payload=b"data",
        seq=5,
        offset=1024,
        len=8192,
        is_eof=True,
    )

    assert chunk.payload == b"data"
    assert chunk.seq == 5
    assert chunk.offset == 1024
    assert chunk.len == 8192
    assert chunk.is_eof


# TEST237: Test PluginResponse::Single final_payload returns the single payload slice
def test_plugin_response_single():
    response = PluginResponse.single(b"result")
    assert response.final_payload() == b"result"
    assert response.concatenated() == b"result"


# TEST238: Test PluginResponse::Single with empty payload returns empty slice and empty vec
def test_plugin_response_single_empty():
    response = PluginResponse.single(b"")
    assert response.final_payload() == b""
    assert response.concatenated() == b""


# TEST239: Test PluginResponse::Streaming concatenated joins all chunk payloads in order
def test_plugin_response_streaming():
    chunks = [
        ResponseChunk(
            payload=b"hello",
            seq=0,
            offset=0,
            len=11,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b" ",
            seq=1,
            offset=5,
            len=11,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b"world",
            seq=2,
            offset=6,
            len=11,
            is_eof=True,
        ),
    ]

    response = PluginResponse.streaming(chunks)

    # Verify concatenated joins all payloads in order
    assert response.concatenated() == b"hello world"

    # Verify final_payload returns last chunk's payload
    assert response.final_payload() == b"world"


# TEST240: Test PluginResponse::Streaming final_payload returns the last chunk's payload
def test_plugin_response_streaming_final_payload():
    chunks = [
        ResponseChunk(
            payload=b"first",
            seq=0,
            offset=0,
            len=16,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b"second",
            seq=1,
            offset=5,
            len=16,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b"last",
            seq=2,
            offset=11,
            len=16,
            is_eof=True,
        ),
    ]

    response = PluginResponse.streaming(chunks)

    # final_payload should return the last chunk's payload
    assert response.final_payload() == b"last"


# TEST241: Test PluginResponse::Streaming with empty chunks vec returns empty concatenation
def test_plugin_response_streaming_empty():
    response = PluginResponse.streaming([])
    assert response.final_payload() is None
    assert response.concatenated() == b""


# TEST242: Test PluginResponse::Streaming concatenated capacity is pre-allocated correctly for large payloads
def test_plugin_response_streaming_large():
    # Create chunks with substantial data
    chunks = [
        ResponseChunk(
            payload=b"x" * 1000,
            seq=0,
            offset=0,
            len=3000,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b"y" * 1000,
            seq=1,
            offset=1000,
            len=3000,
            is_eof=False,
        ),
        ResponseChunk(
            payload=b"z" * 1000,
            seq=2,
            offset=2000,
            len=3000,
            is_eof=True,
        ),
    ]

    response = PluginResponse.streaming(chunks)

    concatenated = response.concatenated()
    assert len(concatenated) == 3000
    assert concatenated[:1000] == b"x" * 1000
    assert concatenated[1000:2000] == b"y" * 1000
    assert concatenated[2000:3000] == b"z" * 1000


# TEST243: Test AsyncHostError variants display correct error messages
def test_async_host_error_variants():
    # Test PluginError
    err = PluginError("CODE", "message")
    assert err.code == "CODE"
    assert err.error_message == "message"
    assert "[CODE]" in str(err)
    assert "message" in str(err)

    # Test UnexpectedFrameType
    err2 = UnexpectedFrameType(FrameType.LOG)
    assert "LOG" in str(err2) or "5" in str(err2)  # Either name or value

    # Test ProcessExited
    err3 = ProcessExited()
    assert "exited" in str(err3).lower()

    # Test Closed
    err4 = Closed()
    assert "closed" in str(err4).lower()

    # Test SendError
    err5 = SendError()
    assert "send" in str(err5).lower() or "channel" in str(err5).lower()

    # Test RecvError
    err6 = RecvError()
    assert "recv" in str(err6).lower() or "channel" in str(err6).lower()


# TEST244: Test AsyncHostError::from converts CborError to Cbor variant
def test_async_host_error_from_cbor():
    # Create a CborError and wrap it
    cbor_msg = "CBOR encoding failed"
    host_err = CborErrorWrapper(cbor_msg)
    assert cbor_msg in str(host_err)


# TEST245: Test AsyncHostError::from converts io::Error to Io variant
def test_async_host_error_from_io():
    io_msg = "pipe broken"
    host_err = IoError(io_msg)
    assert io_msg in str(host_err)


# TEST246: Test AsyncHostError Clone implementation produces equal values
def test_async_host_error_equality():
    # Python doesn't have explicit Clone trait, but we can test equality
    err1 = PluginError("ERR", "msg")
    err2 = PluginError("ERR", "msg")
    # Python exceptions don't have built-in equality, but we can test string representation
    assert str(err1) == str(err2)
    assert err1.code == err2.code
    assert err1.error_message == err2.error_message


# TEST247: Test ResponseChunk Clone produces independent copy with same data
def test_response_chunk_copy():
    chunk = ResponseChunk(
        payload=b"data",
        seq=3,
        offset=100,
        len=500,
        is_eof=True,
    )

    # Python dataclasses support shallow copy via copy module
    import copy
    cloned = copy.copy(chunk)

    # Verify all fields match
    assert cloned.payload == chunk.payload
    assert cloned.seq == chunk.seq
    assert cloned.offset == chunk.offset
    assert cloned.len == chunk.len
    assert cloned.is_eof == chunk.is_eof

    # Verify it's an independent copy (not the same object)
    assert cloned is not chunk
