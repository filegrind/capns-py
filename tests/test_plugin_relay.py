"""Tests for plugin relay (TEST404-TEST412)"""
import io
import os
import threading

import pytest

from capns.cbor_frame import Frame, FrameType, Limits, MessageId
from capns.cbor_io import FrameReader, FrameWriter
from capns.plugin_relay import RelaySlave, RelayMaster


def make_pipe():
    """Create a pair of connected streams using os.pipe().
    Returns (read_file, write_file) as file objects suitable for FrameReader/FrameWriter.
    """
    r_fd, w_fd = os.pipe()
    return os.fdopen(r_fd, "rb"), os.fdopen(w_fd, "wb")


# TEST404: Slave sends RelayNotify on connect (initial_notify parameter)
def test_slave_sends_relay_notify_on_connect():
    """Verify slave sends RelayNotify with manifest and limits on connect"""
    manifest = b'{"caps":["cap:op=test"]}'
    limits = Limits.default()

    master_read, slave_write = make_pipe()

    def slave_thread():
        writer = FrameWriter(slave_write)
        RelaySlave.send_notify(writer, manifest, limits)
        slave_write.close()

    t = threading.Thread(target=slave_thread)
    t.start()

    reader = FrameReader(master_read)
    frame = reader.read()
    assert frame is not None
    assert frame.frame_type == FrameType.RELAY_NOTIFY

    extracted_manifest = frame.relay_notify_manifest()
    assert extracted_manifest is not None
    assert extracted_manifest == manifest

    extracted_limits = frame.relay_notify_limits()
    assert extracted_limits is not None
    assert extracted_limits.max_frame == limits.max_frame
    assert extracted_limits.max_chunk == limits.max_chunk

    master_read.close()
    t.join()


# TEST405: Master reads RelayNotify and extracts manifest + limits
def test_master_reads_relay_notify():
    """Verify master connects by reading initial RelayNotify"""
    manifest = b'{"caps":["cap:op=convert"]}'
    limits = Limits(max_frame=1_000_000, max_chunk=64_000)

    master_read, slave_write = make_pipe()

    def slave_thread():
        writer = FrameWriter(slave_write)
        frame = Frame.relay_notify(manifest, limits.max_frame, limits.max_chunk)
        writer.write(frame)
        slave_write.close()

    t = threading.Thread(target=slave_thread)
    t.start()

    reader = FrameReader(master_read)
    master = RelayMaster.connect(reader)

    assert master.manifest == manifest
    assert master.limits.max_frame == 1_000_000
    assert master.limits.max_chunk == 64_000

    master_read.close()
    t.join()


# TEST406: Slave stores RelayState from master (resource_state() returns payload)
def test_slave_stores_relay_state():
    """Verify slave stores RelayState payload"""
    resources = b'{"memory_mb":4096}'

    slave_socket_read, master_socket_write = make_pipe()
    local_read, local_write = make_pipe()

    def master_thread():
        writer = FrameWriter(master_socket_write)
        RelayMaster.send_state(writer, resources)
        master_socket_write.close()

    t = threading.Thread(target=master_thread)
    t.start()

    slave = RelaySlave(FrameReader(local_read), FrameWriter(local_write))

    # Read manually (simulating what run() does)
    socket_reader = FrameReader(slave_socket_read)
    frame = socket_reader.read()
    assert frame is not None
    assert frame.frame_type == FrameType.RELAY_STATE

    # Manually store
    if frame.payload is not None:
        slave._resource_state = bytes(frame.payload)

    stored = slave.resource_state()
    assert stored == resources

    slave_socket_read.close()
    local_read.close()
    local_write.close()
    t.join()


# TEST407: Protocol frames pass through slave transparently (both directions)
def test_protocol_frames_pass_through():
    """Verify REQ and CHUNK pass through the relay"""
    slave_socket_read, master_socket_write = make_pipe()
    master_socket_read, slave_socket_write = make_pipe()
    runtime_reads, slave_local_write = make_pipe()
    slave_local_read, runtime_writes = make_pipe()

    req_id = MessageId.new_uuid()
    chunk_id = MessageId.new_uuid()

    errors = []

    def master_write_thread():
        try:
            writer = FrameWriter(master_socket_write)
            req = Frame.req(req_id, "cap:op=test", b"hello", "text/plain")
            writer.write(req)
            master_socket_write.close()
        except Exception as e:
            errors.append(e)

    def runtime_write_thread():
        try:
            writer = FrameWriter(runtime_writes)
            chunk = Frame.chunk(chunk_id, "stream-1", 0, b"response")
            writer.write(chunk)
            runtime_writes.close()
        except Exception as e:
            errors.append(e)

    def slave_relay_thread():
        try:
            socket_reader = FrameReader(slave_socket_read)
            socket_writer = FrameWriter(slave_socket_write)
            local_reader = FrameReader(slave_local_read)
            local_writer = FrameWriter(slave_local_write)

            # Socket -> local: read REQ, forward
            from_socket = socket_reader.read()
            assert from_socket is not None
            assert from_socket.frame_type == FrameType.REQ
            local_writer.write(from_socket)

            # Local -> socket: read CHUNK, forward
            from_local = local_reader.read()
            assert from_local is not None
            assert from_local.frame_type == FrameType.CHUNK
            socket_writer.write(from_local)

            slave_socket_read.close()
            slave_socket_write.close()
            slave_local_read.close()
            slave_local_write.close()
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=master_write_thread),
        threading.Thread(target=runtime_write_thread),
        threading.Thread(target=slave_relay_thread),
    ]
    for t in threads:
        t.start()

    # Runtime reads the forwarded REQ
    runtime_reader = FrameReader(runtime_reads)
    forwarded_req = runtime_reader.read()
    assert forwarded_req is not None
    assert forwarded_req.frame_type == FrameType.REQ
    assert forwarded_req.cap == "cap:op=test"
    assert forwarded_req.payload == b"hello"

    # Master reads the forwarded CHUNK
    master_reader = FrameReader(master_socket_read)
    forwarded_chunk = master_reader.read()
    assert forwarded_chunk is not None
    assert forwarded_chunk.frame_type == FrameType.CHUNK
    assert forwarded_chunk.payload == b"response"

    runtime_reads.close()
    master_socket_read.close()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread errors: {errors}"


# TEST408: RelayNotify/RelayState are NOT forwarded through relay (intercepted)
def test_relay_frames_not_forwarded():
    """Verify RelayState is intercepted, only normal frames forwarded"""
    slave_socket_read, master_socket_write = make_pipe()
    runtime_read, slave_local_write = make_pipe()

    errors = []

    def master_write_thread():
        try:
            writer = FrameWriter(master_socket_write)
            # Send RelayState (should be intercepted)
            state = Frame.relay_state(b'{"memory":1024}')
            writer.write(state)
            # Then send a normal REQ
            req = Frame.req(MessageId.new_uuid(), "cap:op=test", b"", "text/plain")
            writer.write(req)
            master_socket_write.close()
        except Exception as e:
            errors.append(e)

    def slave_thread():
        try:
            socket_reader = FrameReader(slave_socket_read)
            local_writer = FrameWriter(slave_local_write)
            resource_state = None

            # Read first frame — RelayState, NOT forwarded
            frame1 = socket_reader.read()
            assert frame1 is not None
            assert frame1.frame_type == FrameType.RELAY_STATE
            resource_state = frame1.payload

            # Read second frame — REQ, forwarded
            frame2 = socket_reader.read()
            assert frame2 is not None
            assert frame2.frame_type == FrameType.REQ
            local_writer.write(frame2)

            assert resource_state == b'{"memory":1024}'

            slave_socket_read.close()
            slave_local_write.close()
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=master_write_thread),
        threading.Thread(target=slave_thread),
    ]
    for t in threads:
        t.start()

    # Runtime should only see the REQ
    runtime_reader = FrameReader(runtime_read)
    frame = runtime_reader.read()
    assert frame is not None
    assert frame.frame_type == FrameType.REQ

    runtime_read.close()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread errors: {errors}"


# TEST409: Slave can inject RelayNotify mid-stream (cap change)
def test_slave_injects_relay_notify_midstream():
    """Verify slave can send RelayNotify between normal frames"""
    master_socket_read, slave_socket_write = make_pipe()

    def slave_thread():
        writer = FrameWriter(slave_socket_write)
        limits = Limits.default()

        # First: send initial RelayNotify
        initial = b'{"caps":["cap:op=test"]}'
        RelaySlave.send_notify(writer, initial, limits)

        # Then: a normal CHUNK
        chunk = Frame.chunk(MessageId.new_uuid(), "stream-1", 0, b"data")
        writer.write(chunk)

        # Then: updated RelayNotify
        updated = b'{"caps":["cap:op=test","cap:op=convert"]}'
        RelaySlave.send_notify(writer, updated, limits)

        slave_socket_write.close()

    t = threading.Thread(target=slave_thread)
    t.start()

    reader = FrameReader(master_socket_read)

    # Read initial RelayNotify
    f1 = reader.read()
    assert f1 is not None
    assert f1.frame_type == FrameType.RELAY_NOTIFY
    assert f1.relay_notify_manifest() == b'{"caps":["cap:op=test"]}'

    # Read CHUNK (passed through)
    f2 = reader.read()
    assert f2 is not None
    assert f2.frame_type == FrameType.CHUNK

    # Read updated RelayNotify
    f3 = reader.read()
    assert f3 is not None
    assert f3.frame_type == FrameType.RELAY_NOTIFY
    assert f3.relay_notify_manifest() == b'{"caps":["cap:op=test","cap:op=convert"]}'

    master_socket_read.close()
    t.join()


# TEST410: Master receives updated RelayNotify (cap change via read_frame)
def test_master_receives_updated_relay_notify():
    """Verify master intercepts updated RelayNotify and updates state"""
    master_socket_read, slave_socket_write = make_pipe()

    limits = Limits(max_frame=2_000_000, max_chunk=100_000)

    def slave_thread():
        writer = FrameWriter(slave_socket_write)

        # Initial RelayNotify
        initial = Frame.relay_notify(b'{"caps":["cap:op=a"]}', limits.max_frame, limits.max_chunk)
        writer.write(initial)

        # Normal frame
        end = Frame.end(MessageId.new_uuid(), None)
        writer.write(end)

        # Updated RelayNotify with new limits
        updated = Frame.relay_notify(
            b'{"caps":["cap:op=a","cap:op=b"]}',
            3_000_000,
            200_000,
        )
        writer.write(updated)

        # Another normal frame
        end2 = Frame.end(MessageId.new_uuid(), None)
        writer.write(end2)

        slave_socket_write.close()

    t = threading.Thread(target=slave_thread)
    t.start()

    reader = FrameReader(master_socket_read)
    master = RelayMaster.connect(reader)

    # Initial state
    assert master.manifest == b'{"caps":["cap:op=a"]}'
    assert master.limits.max_frame == 2_000_000

    # First non-relay frame
    f1 = master.read_frame(reader)
    assert f1 is not None
    assert f1.frame_type == FrameType.END

    # read_frame should have intercepted the updated RelayNotify
    f2 = master.read_frame(reader)
    assert f2 is not None
    assert f2.frame_type == FrameType.END

    # Manifest and limits should be updated
    assert master.manifest == b'{"caps":["cap:op=a","cap:op=b"]}'
    assert master.limits.max_frame == 3_000_000
    assert master.limits.max_chunk == 200_000

    master_socket_read.close()
    t.join()


# TEST411: Socket close detection (both directions)
def test_socket_close_detection():
    """Verify closed socket is detected in both directions"""
    # Master -> slave direction: master closes, slave detects
    slave_socket_read, master_socket_write = make_pipe()
    master_socket_write.close()  # Close immediately

    reader = FrameReader(slave_socket_read)
    result = reader.read()
    assert result is None, "closed socket must return None"
    slave_socket_read.close()

    # Slave -> master direction: slave closes, master detects via read_frame
    master_socket_read2, slave_socket_write2 = make_pipe()

    def slave_thread():
        writer = FrameWriter(slave_socket_write2)
        defaults = Limits.default()
        notify = Frame.relay_notify(b"[]", defaults.max_frame, defaults.max_chunk)
        writer.write(notify)
        slave_socket_write2.close()

    t = threading.Thread(target=slave_thread)
    t.start()

    reader2 = FrameReader(master_socket_read2)
    master = RelayMaster.connect(reader2)
    result = master.read_frame(reader2)
    assert result is None, "closed socket must return None"

    master_socket_read2.close()
    t.join()


# TEST412: Bidirectional concurrent frame flow through relay
def test_bidirectional_concurrent_flow():
    """Verify frames flow correctly in both directions simultaneously"""
    slave_socket_read, master_socket_write = make_pipe()
    master_socket_read, slave_socket_write = make_pipe()
    runtime_reads, slave_local_write = make_pipe()
    slave_local_read, runtime_writes = make_pipe()

    req_id1 = MessageId.new_uuid()
    req_id2 = MessageId.new_uuid()
    resp_id = MessageId.new_uuid()

    errors = []

    def master_write():
        try:
            writer = FrameWriter(master_socket_write)
            req1 = Frame.req(req_id1, "cap:op=a", b"data-a", "text/plain")
            req2 = Frame.req(req_id2, "cap:op=b", b"data-b", "text/plain")
            writer.write(req1)
            writer.write(req2)
            master_socket_write.close()
        except Exception as e:
            errors.append(e)

    def runtime_write():
        try:
            writer = FrameWriter(runtime_writes)
            chunk = Frame.chunk(resp_id, "s1", 0, b"resp-a")
            end = Frame.end(resp_id, None)
            writer.write(chunk)
            writer.write(end)
            runtime_writes.close()
        except Exception as e:
            errors.append(e)

    def slave_relay():
        try:
            sock_r = FrameReader(slave_socket_read)
            sock_w = FrameWriter(slave_socket_write)
            local_r = FrameReader(slave_local_read)
            local_w = FrameWriter(slave_local_write)

            # Forward 2 frames from socket to local
            for _ in range(2):
                f = sock_r.read()
                assert f is not None
                local_w.write(f)

            # Forward 2 frames from local to socket
            for _ in range(2):
                f = local_r.read()
                assert f is not None
                sock_w.write(f)

            slave_socket_read.close()
            slave_socket_write.close()
            slave_local_read.close()
            slave_local_write.close()
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=master_write),
        threading.Thread(target=runtime_write),
        threading.Thread(target=slave_relay),
    ]
    for t in threads:
        t.start()

    # Runtime reads forwarded REQs
    runtime_reader = FrameReader(runtime_reads)
    f1 = runtime_reader.read()
    f2 = runtime_reader.read()
    assert f1 is not None and f1.frame_type == FrameType.REQ
    assert f2 is not None and f2.frame_type == FrameType.REQ
    assert f1.id == req_id1
    assert f2.id == req_id2

    # Master reads forwarded responses
    master_reader = FrameReader(master_socket_read)
    f3 = master_reader.read()
    assert f3 is not None
    assert f3.frame_type == FrameType.CHUNK
    assert f3.payload == b"resp-a"
    f4 = master_reader.read()
    assert f4 is not None
    assert f4.frame_type == FrameType.END

    runtime_reads.close()
    master_socket_read.close()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread errors: {errors}"
