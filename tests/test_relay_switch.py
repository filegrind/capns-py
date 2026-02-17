"""Tests for RelaySwitch — TEST426-TEST435"""

import json
import socket
import threading
from io import BytesIO

import pytest

from capns.bifaci.frame import Frame, FrameType, Limits, MessageId, compute_checksum
from capns.bifaci.io import FrameReader, FrameWriter
from capns.bifaci.relay_switch import (
    RelaySwitch,
    SocketPair,
    NoHandlerError,
    ProtocolError,
)


def send_notify(writer: FrameWriter, manifest_json: dict, limits: Limits):
    """Helper to send RelayNotify"""
    manifest_bytes = json.dumps(manifest_json).encode("utf-8")
    notify = Frame.relay_notify(manifest_bytes, limits.max_frame, limits.max_chunk)
    writer.write(notify)


# TEST426: Single master REQ/response routing
def test_426_single_master_req_response():
    """Verify basic single-master request/response flow"""
    # Create socket pair for master
    engine_read, slave_write = socket.socketpair()
    slave_read, engine_write = socket.socketpair()

    done = threading.Event()

    # Spawn mock slave that sends RelayNotify then echoes frames
    def slave_thread():
        reader = FrameReader(slave_read.makefile('rb'))
        writer = FrameWriter(slave_write.makefile('wb'))

        manifest = {"capabilities": ['cap:in=media:;out=media:']}
        send_notify(writer, manifest, Limits.default())
        done.set()

        # Read one REQ and send response
        frame = reader.read()
        if frame and frame.frame_type == FrameType.REQ:
            response = Frame.end(frame.id, bytes([42]))
            writer.write(response)

    threading.Thread(target=slave_thread, daemon=True).start()

    # Wait for RelayNotify
    done.wait(timeout=2)

    # Create RelaySwitch
    switch = RelaySwitch([SocketPair(read=engine_read.makefile('rb'), write=engine_write.makefile('wb'))])

    # Send REQ
    req = Frame.req(
        MessageId(1),
        'cap:in=media:;out=media:',
        bytes([1, 2, 3]),
        "text/plain"
    )
    switch.send_to_master(req)

    # Read response
    response = switch.read_from_masters()
    assert response is not None
    assert response.frame_type == FrameType.END
    assert response.id.to_string() == MessageId(1).to_string()
    assert response.payload == bytes([42])


# TEST427: Multi-master cap routing
def test_427_multi_master_cap_routing():
    """Verify routing to correct master based on cap URN"""
    # Create two masters with different caps
    engine_read1, slave_write1 = socket.socketpair()
    slave_read1, engine_write1 = socket.socketpair()
    engine_read2, slave_write2 = socket.socketpair()
    slave_read2, engine_write2 = socket.socketpair()

    done1 = threading.Event()
    done2 = threading.Event()

    # Spawn slave 1 (echo cap)
    def slave1_thread():
        reader = FrameReader(slave_read1.makefile('rb'))
        writer = FrameWriter(slave_write1.makefile('wb'))

        manifest = {"capabilities": ['cap:in=media:;out=media:']}
        send_notify(writer, manifest, Limits.default())
        done1.set()

        while True:
            frame = reader.read()
            if not frame:
                break
            if frame.frame_type == FrameType.REQ:
                response = Frame.end(frame.id, bytes([1]))
                writer.write(response)

    # Spawn slave 2 (double cap)
    def slave2_thread():
        reader = FrameReader(slave_read2.makefile('rb'))
        writer = FrameWriter(slave_write2.makefile('wb'))

        manifest = {"capabilities": ['cap:in="media:void";op=double;out="media:void"']}
        send_notify(writer, manifest, Limits.default())
        done2.set()

        while True:
            frame = reader.read()
            if not frame:
                break
            if frame.frame_type == FrameType.REQ:
                response = Frame.end(frame.id, bytes([2]))
                writer.write(response)

    threading.Thread(target=slave1_thread, daemon=True).start()
    threading.Thread(target=slave2_thread, daemon=True).start()

    done1.wait(timeout=2)
    done2.wait(timeout=2)

    switch = RelaySwitch([
        SocketPair(read=engine_read1.makefile('rb'), write=engine_write1.makefile('wb')),
        SocketPair(read=engine_read2.makefile('rb'), write=engine_write2.makefile('wb')),
    ])

    # Send REQ for echo cap → routes to master 1
    req1 = Frame.req(
        MessageId(1),
        'cap:in=media:;out=media:',
        bytes(),
        "text/plain"
    )
    switch.send_to_master(req1)

    resp1 = switch.read_from_masters()
    assert resp1.payload == bytes([1])

    # Send REQ for double cap → routes to master 2
    req2 = Frame.req(
        MessageId(2),
        'cap:in="media:void";op=double;out="media:void"',
        bytes(),
        "text/plain"
    )
    switch.send_to_master(req2)

    resp2 = switch.read_from_masters()
    assert resp2.payload == bytes([2])


# TEST428: Unknown cap returns error
def test_428_unknown_cap_returns_error():
    """Verify NoHandlerError for unknown cap"""
    engine_read, slave_write = socket.socketpair()
    slave_read, engine_write = socket.socketpair()

    done = threading.Event()

    def slave_thread():
        writer = FrameWriter(slave_write.makefile('wb'))

        manifest = {"capabilities": ['cap:in=media:;out=media:']}
        send_notify(writer, manifest, Limits.default())
        done.set()

    threading.Thread(target=slave_thread, daemon=True).start()

    done.wait(timeout=2)

    switch = RelaySwitch([SocketPair(read=engine_read.makefile('rb'), write=engine_write.makefile('wb'))])

    # Send REQ for unknown cap
    req = Frame.req(
        MessageId(1),
        'cap:in="media:void";op=unknown;out="media:void"',
        bytes(),
        "text/plain"
    )

    with pytest.raises(NoHandlerError):
        switch.send_to_master(req)


# TEST429: Cap routing logic (find_master_for_cap)
def test_429_find_master_for_cap():
    """Verify find_master_for_cap logic with exact and URN matching"""
    # Create two masters with different caps
    engine_read1, slave_write1 = socket.socketpair()
    slave_read1, engine_write1 = socket.socketpair()
    engine_read2, slave_write2 = socket.socketpair()
    slave_read2, engine_write2 = socket.socketpair()

    done1 = threading.Event()
    done2 = threading.Event()

    def slave1_thread():
        writer = FrameWriter(slave_write1.makefile('wb'))
        manifest = {"capabilities": ['cap:in=media:;out=media:']}
        send_notify(writer, manifest, Limits.default())
        done1.set()

    def slave2_thread():
        writer = FrameWriter(slave_write2.makefile('wb'))
        manifest = {"capabilities": ['cap:in="media:void";op=double;out="media:void"']}
        send_notify(writer, manifest, Limits.default())
        done2.set()

    threading.Thread(target=slave1_thread, daemon=True).start()
    threading.Thread(target=slave2_thread, daemon=True).start()

    done1.wait(timeout=2)
    done2.wait(timeout=2)

    switch = RelaySwitch([
        SocketPair(read=engine_read1.makefile('rb'), write=engine_write1.makefile('wb')),
        SocketPair(read=engine_read2.makefile('rb'), write=engine_write2.makefile('wb')),
    ])

    # Verify routing
    assert switch._find_master_for_cap('cap:in=media:;out=media:') == 0
    assert switch._find_master_for_cap('cap:in="media:void";op=double;out="media:void"') == 1
    assert switch._find_master_for_cap('cap:in="media:void";op=unknown;out="media:void"') is None

    # Verify aggregate capabilities
    caps = json.loads(switch.capabilities())
    cap_list = caps["capabilities"]
    assert len(cap_list) == 2


# TEST430: Tie-breaking (same cap on multiple masters - first match wins, routing is consistent)
def test_430_tie_breaking_same_cap_multiple_masters():
    """Verify consistent routing when multiple masters advertise same cap"""
    # Create two masters with the SAME cap
    engine_read1, slave_write1 = socket.socketpair()
    slave_read1, engine_write1 = socket.socketpair()
    engine_read2, slave_write2 = socket.socketpair()
    slave_read2, engine_write2 = socket.socketpair()

    done1 = threading.Event()
    done2 = threading.Event()

    same_cap = 'cap:in=media:;out=media:'

    # Spawn slave 1
    def slave1_thread():
        reader = FrameReader(slave_read1.makefile('rb'))
        writer = FrameWriter(slave_write1.makefile('wb'))
        manifest = {"capabilities": [same_cap]}
        send_notify(writer, manifest, Limits.default())
        done1.set()

        # Echo with marker 1
        while True:
            frame = reader.read()
            if not frame:
                break
            if frame.frame_type == FrameType.REQ:
                response = Frame.end(frame.id, bytes([1]))
                writer.write(response)

    # Spawn slave 2
    def slave2_thread():
        reader = FrameReader(slave_read2.makefile('rb'))
        writer = FrameWriter(slave_write2.makefile('wb'))
        manifest = {"capabilities": [same_cap]}
        send_notify(writer, manifest, Limits.default())
        done2.set()

        # Echo with marker 2 (should never be called if routing is consistent)
        while True:
            frame = reader.read()
            if not frame:
                break
            if frame.frame_type == FrameType.REQ:
                response = Frame.end(frame.id, bytes([2]))
                writer.write(response)

    threading.Thread(target=slave1_thread, daemon=True).start()
    threading.Thread(target=slave2_thread, daemon=True).start()

    done1.wait(timeout=2)
    done2.wait(timeout=2)

    switch = RelaySwitch([
        SocketPair(read=engine_read1.makefile('rb'), write=engine_write1.makefile('wb')),
        SocketPair(read=engine_read2.makefile('rb'), write=engine_write2.makefile('wb')),
    ])

    # Send first request - should go to master 0 (first match)
    req1 = Frame.req(MessageId(1), same_cap, bytes(), "text/plain")
    switch.send_to_master(req1)

    resp1 = switch.read_from_masters()
    assert resp1.payload == bytes([1])  # From master 0

    # Send second request - should ALSO go to master 0 (consistent routing)
    req2 = Frame.req(MessageId(2), same_cap, bytes(), "text/plain")
    switch.send_to_master(req2)

    resp2 = switch.read_from_masters()
    assert resp2.payload == bytes([1])  # Also from master 0


# TEST431: Continuation frame routing (CHUNK, END follow REQ)
def test_431_continuation_frame_routing():
    """Verify continuation frames route to same master as REQ"""
    engine_read, slave_write = socket.socketpair()
    slave_read, engine_write = socket.socketpair()

    done = threading.Event()

    def slave_thread():
        reader = FrameReader(slave_read.makefile('rb'))
        writer = FrameWriter(slave_write.makefile('wb'))

        manifest = {"capabilities": ['cap:in="media:void";op=test;out="media:void"']}
        send_notify(writer, manifest, Limits.default())
        done.set()

        # Read REQ
        req = reader.read()
        assert req.frame_type == FrameType.REQ

        # Read CHUNK continuation
        chunk = reader.read()
        assert chunk.frame_type == FrameType.CHUNK
        assert chunk.id.to_string() == req.id.to_string()

        # Read END continuation
        end = reader.read()
        assert end.frame_type == FrameType.END
        assert end.id.to_string() == req.id.to_string()

        # Send response
        response = Frame.end(req.id, bytes([42]))
        writer.write(response)

    threading.Thread(target=slave_thread, daemon=True).start()

    done.wait(timeout=2)

    switch = RelaySwitch([SocketPair(read=engine_read.makefile('rb'), write=engine_write.makefile('wb'))])

    req_id = MessageId(1)

    # Send REQ
    req = Frame.req(req_id, 'cap:in="media:void";op=test;out="media:void"', bytes(), "text/plain")
    switch.send_to_master(req)

    # Send CHUNK continuation
    chunk_payload = bytes([1, 2, 3])
    chunk = Frame.chunk(req_id, "stream1", 0, chunk_payload, 0, compute_checksum(chunk_payload))
    switch.send_to_master(chunk)

    # Send END continuation
    end = Frame.end(req_id, None)
    switch.send_to_master(end)

    # Read response
    response = switch.read_from_masters()
    assert response.frame_type == FrameType.END
    assert response.payload == bytes([42])


# TEST432: Empty masters list returns error
def test_432_empty_masters_list_error():
    """Verify error when creating RelaySwitch with empty masters list"""
    with pytest.raises(ProtocolError) as exc_info:
        RelaySwitch([])
    assert "at least one master" in str(exc_info.value)


# TEST433: Capability aggregation deduplicates caps
def test_433_capability_aggregation_deduplicates():
    """Verify aggregate capabilities deduplicate overlapping caps"""
    # Create two masters with overlapping caps
    engine_read1, slave_write1 = socket.socketpair()
    slave_read1, engine_write1 = socket.socketpair()
    engine_read2, slave_write2 = socket.socketpair()
    slave_read2, engine_write2 = socket.socketpair()

    done1 = threading.Event()
    done2 = threading.Event()

    def slave1_thread():
        writer = FrameWriter(slave_write1.makefile('wb'))
        manifest = {
            "capabilities": [
                'cap:in=media:;out=media:',
                'cap:in="media:void";op=double;out="media:void"'
            ]
        }
        send_notify(writer, manifest, Limits.default())
        done1.set()

    def slave2_thread():
        writer = FrameWriter(slave_write2.makefile('wb'))
        manifest = {
            "capabilities": [
                'cap:in=media:;out=media:',  # Duplicate
                'cap:in="media:void";op=triple;out="media:void"'
            ]
        }
        send_notify(writer, manifest, Limits.default())
        done2.set()

    threading.Thread(target=slave1_thread, daemon=True).start()
    threading.Thread(target=slave2_thread, daemon=True).start()

    done1.wait(timeout=2)
    done2.wait(timeout=2)

    switch = RelaySwitch([
        SocketPair(read=engine_read1.makefile('rb'), write=engine_write1.makefile('wb')),
        SocketPair(read=engine_read2.makefile('rb'), write=engine_write2.makefile('wb')),
    ])

    caps = json.loads(switch.capabilities())
    cap_list = sorted(caps["capabilities"])

    # Should have 3 unique caps (echo appears twice but deduplicated)
    assert len(cap_list) == 3
    assert 'cap:in="media:void";op=double;out="media:void"' in cap_list
    assert 'cap:in=media:;out=media:' in cap_list
    assert 'cap:in="media:void";op=triple;out="media:void"' in cap_list


# TEST434: Limits negotiation takes minimum
def test_434_limits_negotiation_minimum():
    """Verify negotiated limits take minimum across all masters"""
    engine_read1, slave_write1 = socket.socketpair()
    slave_read1, engine_write1 = socket.socketpair()
    engine_read2, slave_write2 = socket.socketpair()
    slave_read2, engine_write2 = socket.socketpair()

    done1 = threading.Event()
    done2 = threading.Event()

    def slave1_thread():
        writer = FrameWriter(slave_write1.makefile('wb'))
        manifest = {"capabilities": []}
        limits1 = Limits(max_frame=1_000_000, max_chunk=100_000)
        send_notify(writer, manifest, limits1)
        done1.set()

    def slave2_thread():
        writer = FrameWriter(slave_write2.makefile('wb'))
        manifest = {"capabilities": []}
        limits2 = Limits(max_frame=2_000_000, max_chunk=50_000)  # Larger frame, smaller chunk
        send_notify(writer, manifest, limits2)
        done2.set()

    threading.Thread(target=slave1_thread, daemon=True).start()
    threading.Thread(target=slave2_thread, daemon=True).start()

    done1.wait(timeout=2)
    done2.wait(timeout=2)

    switch = RelaySwitch([
        SocketPair(read=engine_read1.makefile('rb'), write=engine_write1.makefile('wb')),
        SocketPair(read=engine_read2.makefile('rb'), write=engine_write2.makefile('wb')),
    ])

    # Should take minimum of each limit
    assert switch.limits().max_frame == 1_000_000  # min(1M, 2M)
    assert switch.limits().max_chunk == 50_000     # min(100K, 50K)


# TEST435: URN matching (exact vs accepts())
def test_435_urn_matching_exact_and_accepts():
    """Verify exact and URN-level matching for cap routing"""
    engine_read, slave_write = socket.socketpair()
    slave_read, engine_write = socket.socketpair()

    done = threading.Event()

    # Master advertises a specific cap
    registered_cap = 'cap:in="media:text;utf8";op=process;out="media:text;utf8"'

    def slave_thread():
        reader = FrameReader(slave_read.makefile('rb'))
        writer = FrameWriter(slave_write.makefile('wb'))
        manifest = {"capabilities": [registered_cap]}
        send_notify(writer, manifest, Limits.default())
        done.set()

        # Respond to request
        while True:
            frame = reader.read()
            if not frame:
                break
            if frame.frame_type == FrameType.REQ:
                response = Frame.end(frame.id, bytes([42]))
                writer.write(response)

    threading.Thread(target=slave_thread, daemon=True).start()

    done.wait(timeout=2)

    switch = RelaySwitch([SocketPair(read=engine_read.makefile('rb'), write=engine_write.makefile('wb'))])

    # Exact match should work
    req1 = Frame.req(MessageId(1), registered_cap, bytes(), "text/plain")
    switch.send_to_master(req1)
    resp1 = switch.read_from_masters()
    assert resp1.payload == bytes([42])

    # More specific request should NOT match less specific registered cap
    # (request is more specific, registered is less specific → no match)
    req2 = Frame.req(
        MessageId(2),
        'cap:in="media:text;utf8;normalized";op=process;out="media:text"',
        bytes(),
        "text/plain"
    )
    with pytest.raises(NoHandlerError):
        switch.send_to_master(req2)
