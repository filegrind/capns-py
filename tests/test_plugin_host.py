"""Tests for PluginHost — multi-plugin relay-based host.

Tests TEST413-TEST425 mirror the Go plugin_host_multi_test.go tests.
Uses socket pairs (os.pipe) and threads to simulate plugins.
"""

import json
import os
import threading
import time

import pytest

from capns.async_plugin_host import PluginHost
from capns.cbor_frame import Frame, FrameType, Limits, MessageId
from capns.cbor_io import (
    FrameReader,
    FrameWriter,
    handshake_accept,
)


def make_pipe_pair():
    """Create a bidirectional pipe pair for simulating plugin connections.

    Returns (host_read, host_write, plugin_read, plugin_write) as file objects.
    host_read/host_write are what the host sees (plugin's stdout/stdin).
    plugin_read/plugin_write are what the plugin side uses.
    """
    # Plugin stdout → Host reads
    plugin_stdout_r, plugin_stdout_w = os.pipe()
    # Host writes → Plugin stdin
    plugin_stdin_r, plugin_stdin_w = os.pipe()

    host_read = os.fdopen(plugin_stdout_r, "rb")
    plugin_write = os.fdopen(plugin_stdout_w, "wb")
    plugin_read = os.fdopen(plugin_stdin_r, "rb")
    host_write = os.fdopen(plugin_stdin_w, "wb")

    return host_read, host_write, plugin_read, plugin_write


def simulate_plugin(plugin_read, plugin_write, manifest_str, handler=None):
    """Run a simulated plugin: handshake + optional handler.

    Args:
        plugin_read: Plugin reads from this (host's writes)
        plugin_write: Plugin writes to this (host reads)
        manifest_str: JSON manifest string
        handler: Optional function(reader, writer) called after handshake
    """
    reader = FrameReader(plugin_read)
    writer = FrameWriter(plugin_write)

    limits = handshake_accept(reader, writer, manifest_str.encode("utf-8"))
    reader.set_limits(limits)
    writer.set_limits(limits)

    if handler is not None:
        handler(reader, writer)


# TEST413: RegisterPlugin adds entries to capTable
def test_register_plugin_adds_cap_table():
    host = PluginHost()
    host.register_plugin("/path/to/converter", ["cap:op=convert", "cap:op=analyze"])

    with host._lock:
        assert len(host._cap_table) == 2, "must have 2 cap table entries"
        assert host._cap_table[0].cap_urn == "cap:op=convert"
        assert host._cap_table[0].plugin_idx == 0
        assert host._cap_table[1].cap_urn == "cap:op=analyze"
        assert host._cap_table[1].plugin_idx == 0

        assert len(host._plugins) == 1
        assert not host._plugins[0].running, "registered plugin must not be running"


# TEST414: Capabilities() returns None when no plugins are running
def test_capabilities_empty_initially():
    # Case 1: No plugins at all
    host = PluginHost()
    assert host.capabilities() is None, "no plugins → None capabilities"

    # Case 2: Plugin registered but not running
    host.register_plugin("/path/to/plugin", ["cap:op=test"])
    assert host.capabilities() is None, "registered but not running → None capabilities"


# TEST415: REQ for known cap triggers spawn (expect error for non-existent binary)
def test_req_triggers_spawn():
    host = PluginHost()
    host.register_plugin("/nonexistent/plugin/binary", ["cap:op=test"])

    # Set up relay pipes
    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    err_frame = [None]

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        req_id = MessageId.new_uuid()
        req = Frame.req(req_id, "cap:op=test", b"hello", "text/plain")
        writer.write(req)

        # Read ERR response
        frame = reader.read()
        if frame is not None:
            err_frame[0] = frame

        # Close relay to end Run()
        engine_w.close()
        engine_r.close()

    t = threading.Thread(target=engine_thread)
    t.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    t.join()

    assert err_frame[0] is not None, "must receive ERR frame"
    assert err_frame[0].frame_type == FrameType.ERR
    assert err_frame[0].error_code() == "SPAWN_FAILED", "spawn of nonexistent binary must fail"


# TEST416: AttachPlugin performs HELLO handshake, extracts manifest, updates capabilities
def test_attach_plugin_handshake():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=echo"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    done = threading.Event()

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest)
        plugin_read.close()
        plugin_write.close()
        done.set()

    t = threading.Thread(target=plugin_thread)
    t.start()

    host = PluginHost()
    idx = host.attach_plugin(host_read, host_write)

    assert idx == 0, "first attached plugin is index 0"

    with host._lock:
        assert host._plugins[0].running, "attached plugin must be running"
        assert host._plugins[0].caps == ["cap:op=echo"]

    caps = host.capabilities()
    assert caps is not None, "running plugin must produce capabilities"
    assert b"cap:op=echo" in caps

    # Clean up
    host_read.close()
    host_write.close()
    done.wait(timeout=5)
    t.join(timeout=5)


# TEST417: Route REQ to correct plugin by cap_urn (two plugins)
def test_route_req_by_cap_urn():
    manifest_a = '{"name":"PluginA","version":"1.0","caps":[{"urn":"cap:op=convert"}]}'
    manifest_b = '{"name":"PluginB","version":"1.0","caps":[{"urn":"cap:op=analyze"}]}'

    # Plugin A pipes
    host_read_a, host_write_a, plugin_read_a, plugin_write_a = make_pipe_pair()
    # Plugin B pipes
    host_read_b, host_write_b, plugin_read_b, plugin_write_b = make_pipe_pair()

    barrier = threading.Barrier(3)  # 2 plugins + engine

    # Plugin A: reads REQ+END, responds with "converted"
    def plugin_a_thread():
        def handler(r, w):
            # Read REQ
            frame = r.read()
            assert frame is not None
            assert frame.frame_type == FrameType.REQ
            req_id = frame.id

            # Read until END
            while True:
                f = r.read()
                if f is None or f.frame_type == FrameType.END:
                    break

            # Respond
            w.write(Frame.end(req_id, b"converted"))

        simulate_plugin(plugin_read_a, plugin_write_a, manifest_a, handler)
        plugin_read_a.close()
        plugin_write_a.close()

    # Plugin B: handshake only, expects no REQs
    def plugin_b_thread():
        def handler(r, w):
            # Should get EOF (no frames sent to B)
            frame = r.read()
            # frame is None on EOF or error

        simulate_plugin(plugin_read_b, plugin_write_b, manifest_b, handler)
        plugin_read_b.close()
        plugin_write_b.close()

    t_a = threading.Thread(target=plugin_a_thread)
    t_b = threading.Thread(target=plugin_b_thread)
    t_a.start()
    t_b.start()

    host = PluginHost()
    host.attach_plugin(host_read_a, host_write_a)
    host.attach_plugin(host_read_b, host_write_b)

    # Relay pipes
    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    response_payload = [None]

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        req_id = MessageId.new_uuid()
        writer.write(Frame.req(req_id, "cap:op=convert", b"", "text/plain"))
        writer.write(Frame.end(req_id))

        # Read response
        frame = reader.read()
        if frame is not None and frame.frame_type == FrameType.END:
            response_payload[0] = frame.payload

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()

    # Close host connections to unblock plugin B
    host_read_b.close()
    host_write_b.close()
    host_read_a.close()
    host_write_a.close()

    t_eng.join(timeout=10)
    t_a.join(timeout=10)
    t_b.join(timeout=10)

    assert response_payload[0] == b"converted"


# TEST418: Route STREAM_START/CHUNK/STREAM_END/END by req_id
def test_route_continuation_by_req_id():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=cont"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_handler(r, w):
        # Read REQ
        req = r.read()
        assert req is not None
        assert req.frame_type == FrameType.REQ
        req_id = req.id

        # Read STREAM_START
        ss = r.read()
        assert ss is not None
        assert ss.frame_type == FrameType.STREAM_START
        assert ss.id.to_string() == req_id.to_string()

        # Read CHUNK
        chunk = r.read()
        assert chunk is not None
        assert chunk.frame_type == FrameType.CHUNK
        assert chunk.id.to_string() == req_id.to_string()
        assert chunk.payload == b"payload-data"

        # Read STREAM_END
        se = r.read()
        assert se is not None
        assert se.frame_type == FrameType.STREAM_END

        # Read END
        end = r.read()
        assert end is not None
        assert end.frame_type == FrameType.END

        # Respond
        w.write(Frame.end(req_id, b"ok"))

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest, plugin_handler)
        plugin_read.close()
        plugin_write.close()

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    response_payload = [None]

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        req_id = MessageId.new_uuid()
        writer.write(Frame.req(req_id, "cap:op=cont", b"", "text/plain"))
        writer.write(Frame.stream_start(req_id, "arg-0", "media:bytes"))
        writer.write(Frame.chunk(req_id, "arg-0", 0, b"payload-data"))
        writer.write(Frame.stream_end(req_id, "arg-0"))
        writer.write(Frame.end(req_id))

        # Read response
        frame = reader.read()
        if frame is not None and frame.frame_type == FrameType.END:
            response_payload[0] = frame.payload

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()

    t_eng.join(timeout=10)
    t_p.join(timeout=10)

    assert response_payload[0] == b"ok"


# TEST419: Plugin HEARTBEAT handled locally (not forwarded to relay)
def test_heartbeat_local_handling():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=hb"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_handler(r, w):
        # Send heartbeat
        hb_id = MessageId.new_uuid()
        w.write(Frame.heartbeat(hb_id))

        # Read heartbeat response from host
        resp = r.read()
        assert resp is not None
        assert resp.frame_type == FrameType.HEARTBEAT
        assert resp.id.to_string() == hb_id.to_string()

        # Now send a LOG to give engine something to read
        log_id = MessageId.new_uuid()
        w.write(Frame.log(log_id, "info", "heartbeat was answered"))

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest, plugin_handler)
        plugin_read.close()
        plugin_write.close()

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    received_types = []

    def engine_thread():
        reader = FrameReader(engine_r)
        while True:
            frame = reader.read()
            if frame is None:
                break
            received_types.append(frame.frame_type)

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    # Let the host run briefly then close
    def close_relay():
        time.sleep(1.0)
        engine_w.close()
        engine_r.close()

    t_close = threading.Thread(target=close_relay)
    t_close.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()

    t_eng.join(timeout=10)
    t_p.join(timeout=10)
    t_close.join(timeout=10)

    # HEARTBEAT must NOT appear in relay
    for ft in received_types:
        assert ft != FrameType.HEARTBEAT, "heartbeat must not be forwarded to relay"

    # LOG must appear (proving relay received forwarded frames)
    assert FrameType.LOG in received_types, "LOG must be forwarded to relay"


# TEST420: Plugin non-HELLO/non-HB frames forwarded to relay
def test_plugin_frames_forwarded_to_relay():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=fwd"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_handler(r, w):
        # Read REQ from host
        req = r.read()
        if req is None:
            return
        req_id = req.id

        # Read END
        r.read()

        # Send diverse frame types
        w.write(Frame.log(req_id, "info", "processing"))
        w.write(Frame.stream_start(req_id, "output", "media:bytes"))
        w.write(Frame.chunk(req_id, "output", 0, b"data"))
        w.write(Frame.stream_end(req_id, "output"))
        w.write(Frame.end(req_id))

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest, plugin_handler)
        plugin_read.close()
        plugin_write.close()

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    received_types = []

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        # Send REQ + END
        req_id = MessageId.new_uuid()
        writer.write(Frame.req(req_id, "cap:op=fwd", b"", "text/plain"))
        writer.write(Frame.end(req_id))

        # Read all forwarded frames
        while True:
            frame = reader.read()
            if frame is None:
                break
            received_types.append(frame.frame_type)
            if frame.frame_type == FrameType.END:
                break

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()

    t_eng.join(timeout=10)
    t_p.join(timeout=10)

    # Verify forwarded types
    type_set = set(received_types)
    assert FrameType.LOG in type_set, "LOG must be forwarded"
    assert FrameType.STREAM_START in type_set, "STREAM_START must be forwarded"
    assert FrameType.CHUNK in type_set, "CHUNK must be forwarded"
    assert FrameType.END in type_set, "END must be forwarded"


# TEST421: Plugin death updates capability list (removes dead plugin's caps)
def test_plugin_death_updates_caps():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=die"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_thread():
        # Handshake then die immediately
        simulate_plugin(plugin_read, plugin_write, manifest)
        plugin_read.close()
        plugin_write.close()

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    # Before death: caps must be present
    caps = host.capabilities()
    assert caps is not None
    assert b"cap:op=die" in caps

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    # Let host process death event briefly
    def close_relay():
        time.sleep(1.0)
        engine_w.close()
        engine_r.close()

    t_close = threading.Thread(target=close_relay)
    t_close.start()

    host.run(relay_r, relay_w)

    # After death: caps must be gone
    caps_after = host.capabilities()
    if caps_after is not None:
        parsed = json.loads(caps_after)
        assert len(parsed.get("caps", [])) == 0, "dead plugin caps must be removed"

    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()
    t_p.join(timeout=5)
    t_close.join(timeout=5)


# TEST422: Plugin death sends ERR for all pending requests
def test_plugin_death_sends_err():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=die"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_handler(r, w):
        # Read REQ
        r.read()
        # Die without responding
        plugin_read.close()
        plugin_write.close()

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest, plugin_handler)

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    err_frame = [None]

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        # Send REQ + END
        req_id = MessageId.new_uuid()
        writer.write(Frame.req(req_id, "cap:op=die", b"hello", "text/plain"))
        writer.write(Frame.end(req_id))

        # Wait for ERR
        while True:
            frame = reader.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.ERR:
                err_frame[0] = frame
                break

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()

    t_eng.join(timeout=10)
    t_p.join(timeout=10)

    assert err_frame[0] is not None, "must receive ERR when plugin dies with pending request"
    assert err_frame[0].error_code() == "PLUGIN_DIED"


# TEST423: Multiple plugins with distinct caps route independently
def test_multi_plugin_distinct_caps():
    manifest_a = '{"name":"PluginA","version":"1.0","caps":[{"urn":"cap:op=alpha"}]}'
    manifest_b = '{"name":"PluginB","version":"1.0","caps":[{"urn":"cap:op=beta"}]}'

    host_read_a, host_write_a, plugin_read_a, plugin_write_a = make_pipe_pair()
    host_read_b, host_write_b, plugin_read_b, plugin_write_b = make_pipe_pair()

    def plugin_a_handler(r, w):
        req = r.read()
        if req is None:
            return
        # Read until END
        while True:
            f = r.read()
            if f is None or f.frame_type == FrameType.END:
                break
        w.write(Frame.end(req.id, b"from-A"))

    def plugin_b_handler(r, w):
        req = r.read()
        if req is None:
            return
        while True:
            f = r.read()
            if f is None or f.frame_type == FrameType.END:
                break
        w.write(Frame.end(req.id, b"from-B"))

    def plugin_a_thread():
        simulate_plugin(plugin_read_a, plugin_write_a, manifest_a, plugin_a_handler)
        plugin_read_a.close()
        plugin_write_a.close()

    def plugin_b_thread():
        simulate_plugin(plugin_read_b, plugin_write_b, manifest_b, plugin_b_handler)
        plugin_read_b.close()
        plugin_write_b.close()

    t_a = threading.Thread(target=plugin_a_thread)
    t_b = threading.Thread(target=plugin_b_thread)
    t_a.start()
    t_b.start()

    host = PluginHost()
    host.attach_plugin(host_read_a, host_write_a)
    host.attach_plugin(host_read_b, host_write_b)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    responses = {}
    lock = threading.Lock()

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        alpha_id = MessageId.new_uuid()
        writer.write(Frame.req(alpha_id, "cap:op=alpha", b"", "text/plain"))
        writer.write(Frame.end(alpha_id))

        beta_id = MessageId.new_uuid()
        writer.write(Frame.req(beta_id, "cap:op=beta", b"", "text/plain"))
        writer.write(Frame.end(beta_id))

        # Read 2 responses
        for _ in range(2):
            frame = reader.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.END:
                id_str = frame.id.to_string()
                with lock:
                    if id_str == alpha_id.to_string():
                        responses["alpha"] = frame.payload
                    elif id_str == beta_id.to_string():
                        responses["beta"] = frame.payload

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read_a.close()
    host_write_a.close()
    host_read_b.close()
    host_write_b.close()

    t_eng.join(timeout=10)
    t_a.join(timeout=10)
    t_b.join(timeout=10)

    with lock:
        assert responses.get("alpha") == b"from-A"
        assert responses.get("beta") == b"from-B"


# TEST424: Concurrent requests to same plugin handled independently
def test_concurrent_requests_same_plugin():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=conc"}]}'

    host_read, host_write, plugin_read, plugin_write = make_pipe_pair()

    def plugin_handler(r, w):
        # Read both REQs and ENDs, respond to each
        req_ids = []

        # Read REQ 0
        req0 = r.read()
        if req0 is None:
            return
        req_ids.append(req0.id)

        # Read END for req 0
        r.read()

        # Read REQ 1
        req1 = r.read()
        if req1 is None:
            return
        req_ids.append(req1.id)

        # Read END for req 1
        r.read()

        # Respond to each
        w.write(Frame.end(req_ids[0], b"response-0"))
        w.write(Frame.end(req_ids[1], b"response-1"))

    def plugin_thread():
        simulate_plugin(plugin_read, plugin_write, manifest, plugin_handler)
        plugin_read.close()
        plugin_write.close()

    t_p = threading.Thread(target=plugin_thread)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(host_read, host_write)

    relay_r, relay_w, engine_r, engine_w = make_pipe_pair()

    responses = {}
    lock = threading.Lock()

    def engine_thread():
        writer = FrameWriter(engine_w)
        reader = FrameReader(engine_r)

        id0 = MessageId.new_uuid()
        id1 = MessageId.new_uuid()

        writer.write(Frame.req(id0, "cap:op=conc", b"", "text/plain"))
        writer.write(Frame.end(id0))

        writer.write(Frame.req(id1, "cap:op=conc", b"", "text/plain"))
        writer.write(Frame.end(id1))

        # Read both responses
        for _ in range(2):
            frame = reader.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.END:
                id_str = frame.id.to_string()
                with lock:
                    if id_str == id0.to_string():
                        responses["0"] = frame.payload
                    elif id_str == id1.to_string():
                        responses["1"] = frame.payload

        engine_w.close()
        engine_r.close()

    t_eng = threading.Thread(target=engine_thread)
    t_eng.start()

    host.run(relay_r, relay_w)
    relay_r.close()
    relay_w.close()
    host_read.close()
    host_write.close()

    t_eng.join(timeout=10)
    t_p.join(timeout=10)

    with lock:
        assert responses.get("0") == b"response-0"
        assert responses.get("1") == b"response-1"


# TEST425: FindPluginForCap returns None for unknown cap
def test_find_plugin_for_cap_unknown():
    host = PluginHost()
    host.register_plugin("/path/to/plugin", ["cap:op=known"])

    idx = host.find_plugin_for_cap("cap:op=known")
    assert idx is not None, "known cap must be found"
    assert idx == 0

    idx2 = host.find_plugin_for_cap("cap:op=unknown")
    assert idx2 is None, "unknown cap must not be found"
