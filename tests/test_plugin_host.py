"""Tests for PluginHost — multi-plugin relay-based host.

Tests TEST413-TEST425 mirror the Go plugin_host_multi_test.go tests.
Uses socket pairs and threads to simulate plugins.

Socket lifecycle rules:
- Plugin threads NEVER close host-side sockets (doing so discards unread data)
- For clean exit: plugin handler returns, main thread closes all sockets after host.run
- For death simulation: plugin closes only its own write end (plugin_socks)
"""

import json
import socket
import threading
import time

import pytest

from capns.bifaci.host_runtime import PluginHost
from capns.bifaci.frame import Frame, FrameType, Limits, MessageId
from capns.bifaci.io import (
    FrameReader,
    FrameWriter,
    handshake_accept,
)


def make_conn():
    """Create a bidirectional connection using socket pairs.

    Returns (host_read, host_write, plugin_read, plugin_write, host_socks, plugin_socks).
    - host_socks: [s1a, s2a] — close these to clean up from host side
    - plugin_socks: [s1b, s2b] — close these to simulate plugin death
    """
    # Channel 1: plugin writes (s1b) → host reads (s1a)
    s1a, s1b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    # Channel 2: host writes (s2a) → plugin reads (s2b)
    s2a, s2b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    host_read = s1a.makefile("rb")
    plugin_write = s1b.makefile("wb")
    plugin_read = s2b.makefile("rb")
    host_write = s2a.makefile("wb")

    return host_read, host_write, plugin_read, plugin_write, [s1a, s2a], [s1b, s2b]


def close_socks(socks):
    """Shutdown and close a list of sockets."""
    for s in socks:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass


def cleanup(*sock_lists):
    """Close all socket lists."""
    for socks in sock_lists:
        close_socks(socks)


def simulate_plugin(plugin_read, plugin_write, manifest_str, handler=None):
    """Run a simulated plugin: handshake + optional handler."""
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
    host = PluginHost()
    assert host.capabilities() is None, "no plugins → None capabilities"
    host.register_plugin("/path/to/plugin", ["cap:op=test"])
    assert host.capabilities() is None, "registered but not running → None capabilities"


# TEST415: REQ for known cap triggers spawn (expect error for non-existent binary)
def test_req_triggers_spawn():
    host = PluginHost()
    host.register_plugin("/nonexistent/plugin/binary", ["cap:op=test"])

    hr, hw, pr, pw, hs, ps = make_conn()
    err_frame = [None]

    def engine():
        w = FrameWriter(pw)
        r = FrameReader(pr)
        req_id = MessageId.new_uuid()
        w.write(Frame.req(req_id, "cap:op=test", b"hello", "text/plain"))
        frame = r.read()
        if frame is not None:
            err_frame[0] = frame
        close_socks(ps)

    t = threading.Thread(target=engine, daemon=True)
    t.start()

    host.run(hr, hw)
    cleanup(hs, ps)
    t.join(timeout=5)

    assert err_frame[0] is not None, "must receive ERR frame"
    assert err_frame[0].frame_type == FrameType.ERR
    assert err_frame[0].error_code() == "SPAWN_FAILED"


# TEST416: AttachPlugin performs HELLO handshake, extracts manifest, updates capabilities
def test_attach_plugin_handshake():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:in=media:;out=media:"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin():
        simulate_plugin(pr, pw, manifest)
        # Don't close sockets — main thread handles cleanup

    t = threading.Thread(target=plugin, daemon=True)
    t.start()

    host = PluginHost()
    idx = host.attach_plugin(hr, hw)

    assert idx == 0
    with host._lock:
        assert host._plugins[0].running
        assert host._plugins[0].caps == ["cap:in=media:;out=media:"]

    caps = host.capabilities()
    assert caps is not None
    assert b"cap:in=media:;out=media:" in caps
    cleanup(hs, ps)
    t.join(timeout=5)


# TEST417: Route REQ to correct plugin by cap_urn (two plugins)
def test_route_req_by_cap_urn():
    manifest_a = '{"name":"A","version":"1.0","caps":[{"urn":"cap:op=convert"}]}'
    manifest_b = '{"name":"B","version":"1.0","caps":[{"urn":"cap:op=analyze"}]}'

    hr_a, hw_a, pr_a, pw_a, hs_a, ps_a = make_conn()
    hr_b, hw_b, pr_b, pw_b, hs_b, ps_b = make_conn()

    def plugin_a():
        def handler(r, w):
            frame = r.read()
            if frame is None:
                return
            req_id = frame.id
            while True:
                f = r.read()
                if f is None or f.frame_type == FrameType.END:
                    break
            w.write(Frame.end(req_id, b"converted"))
        simulate_plugin(pr_a, pw_a, manifest_a, handler)

    def plugin_b():
        def handler(r, w):
            r.read()  # waits for EOF
        simulate_plugin(pr_b, pw_b, manifest_b, handler)

    t_a = threading.Thread(target=plugin_a, daemon=True)
    t_b = threading.Thread(target=plugin_b, daemon=True)
    t_a.start()
    t_b.start()

    host = PluginHost()
    host.attach_plugin(hr_a, hw_a)
    host.attach_plugin(hr_b, hw_b)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    response_payload = [None]

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        req_id = MessageId.new_uuid()
        w.write(Frame.req(req_id, "cap:op=convert", b"", "text/plain"))
        w.write(Frame.end(req_id))
        frame = r.read()
        if frame is not None and frame.frame_type == FrameType.END:
            response_payload[0] = frame.payload
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs_a, ps_a, hs_b, ps_b, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert response_payload[0] == b"converted"


# TEST418: Route STREAM_START/CHUNK/STREAM_END/END by req_id
def test_route_continuation_by_req_id():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=cont"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin_thread():
        def handler(r, w):
            req = r.read()
            if req is None:
                return
            assert req.frame_type == FrameType.REQ
            req_id = req.id
            ss = r.read()
            assert ss.frame_type == FrameType.STREAM_START
            assert ss.id.to_string() == req_id.to_string()
            chunk = r.read()
            assert chunk.frame_type == FrameType.CHUNK
            assert chunk.payload == b"payload-data"
            se = r.read()
            assert se.frame_type == FrameType.STREAM_END
            end = r.read()
            assert end.frame_type == FrameType.END
            w.write(Frame.end(req_id, b"ok"))
        simulate_plugin(pr, pw, manifest, handler)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    response = [None]

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        req_id = MessageId.new_uuid()
        w.write(Frame.req(req_id, "cap:op=cont", b"", "text/plain"))
        w.write(Frame.stream_start(req_id, "arg-0", "media:bytes"))
        w.write(Frame.chunk(req_id, "arg-0", 0, b"payload-data"))
        w.write(Frame.stream_end(req_id, "arg-0"))
        w.write(Frame.end(req_id))
        frame = r.read()
        if frame is not None and frame.frame_type == FrameType.END:
            response[0] = frame.payload
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs, ps, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_p.join(timeout=5)

    assert response[0] == b"ok"


# TEST419: Plugin HEARTBEAT handled locally (not forwarded to relay)
def test_heartbeat_local_handling():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=hb"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    plugin_done = threading.Event()

    def plugin_thread():
        def handler(r, w):
            hb_id = MessageId.new_uuid()
            w.write(Frame.heartbeat(hb_id))
            resp = r.read()
            assert resp is not None
            assert resp.frame_type == FrameType.HEARTBEAT
            assert resp.id.to_string() == hb_id.to_string()
            log_id = MessageId.new_uuid()
            w.write(Frame.log(log_id, "info", "heartbeat was answered"))
            plugin_done.set()
        simulate_plugin(pr, pw, manifest, handler)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    received_types = []

    def engine():
        r = FrameReader(r_pr)
        while True:
            frame = r.read()
            if frame is None:
                break
            received_types.append(frame.frame_type)
            if frame.frame_type == FrameType.LOG:
                break  # Got what we expected

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    def close_relay():
        # Wait for plugin to send LOG, then give host time to forward it
        plugin_done.wait(timeout=5.0)
        time.sleep(0.1)  # Small delay for host to forward
        close_socks(r_ps)

    t_close = threading.Thread(target=close_relay, daemon=True)
    t_close.start()

    host.run(r_hr, r_hw)
    cleanup(hs, ps, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_p.join(timeout=5)
    t_close.join(timeout=5)

    for ft in received_types:
        assert ft != FrameType.HEARTBEAT, "heartbeat must not be forwarded to relay"
    assert FrameType.LOG in received_types, "LOG must be forwarded to relay"


# TEST420: Plugin non-HELLO/non-HB frames forwarded to relay
def test_plugin_frames_forwarded_to_relay():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=fwd"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin_thread():
        def handler(r, w):
            req = r.read()
            if req is None:
                return
            req_id = req.id
            r.read()  # END
            w.write(Frame.log(req_id, "info", "processing"))
            w.write(Frame.stream_start(req_id, "output", "media:bytes"))
            w.write(Frame.chunk(req_id, "output", 0, b"data"))
            w.write(Frame.stream_end(req_id, "output"))
            w.write(Frame.end(req_id))
        simulate_plugin(pr, pw, manifest, handler)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    received_types = []

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        req_id = MessageId.new_uuid()
        w.write(Frame.req(req_id, "cap:op=fwd", b"", "text/plain"))
        w.write(Frame.end(req_id))
        while True:
            frame = r.read()
            if frame is None:
                break
            received_types.append(frame.frame_type)
            if frame.frame_type == FrameType.END:
                break
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs, ps, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_p.join(timeout=5)

    type_set = set(received_types)
    assert FrameType.LOG in type_set, "LOG must be forwarded"
    assert FrameType.STREAM_START in type_set, "STREAM_START must be forwarded"
    assert FrameType.CHUNK in type_set, "CHUNK must be forwarded"
    assert FrameType.END in type_set, "END must be forwarded"


# TEST421: Plugin death updates capability list (removes dead plugin's caps)
def test_plugin_death_updates_caps():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=die"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin_thread():
        simulate_plugin(pr, pw, manifest)
        # Die by closing plugin-side sockets → host sees EOF
        close_socks(ps)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    caps = host.capabilities()
    assert caps is not None
    assert b"cap:op=die" in caps

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()

    def close_relay():
        time.sleep(1.0)
        close_socks(r_ps)

    t_close = threading.Thread(target=close_relay, daemon=True)
    t_close.start()

    host.run(r_hr, r_hw)

    caps_after = host.capabilities()
    if caps_after is not None:
        parsed = json.loads(caps_after)
        assert len(parsed.get("caps", [])) == 0, "dead plugin caps must be removed"

    cleanup(hs, ps, r_hs, r_ps)
    t_p.join(timeout=5)
    t_close.join(timeout=5)


# TEST422: Plugin death sends ERR for all pending requests
def test_plugin_death_sends_err():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=die"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin_thread():
        def handler(r, w):
            r.read()  # Read REQ
            # Die by closing plugin-side sockets
            close_socks(ps)
        simulate_plugin(pr, pw, manifest, handler)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    err_frame = [None]

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        req_id = MessageId.new_uuid()
        w.write(Frame.req(req_id, "cap:op=die", b"hello", "text/plain"))
        w.write(Frame.end(req_id))
        while True:
            frame = r.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.ERR:
                err_frame[0] = frame
                break
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs, ps, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_p.join(timeout=5)

    assert err_frame[0] is not None, "must receive ERR when plugin dies with pending request"
    assert err_frame[0].error_code() == "PLUGIN_DIED"


# TEST423: Multiple plugins with distinct caps route independently
def test_multi_plugin_distinct_caps():
    manifest_a = '{"name":"A","version":"1.0","caps":[{"urn":"cap:op=alpha"}]}'
    manifest_b = '{"name":"B","version":"1.0","caps":[{"urn":"cap:op=beta"}]}'

    hr_a, hw_a, pr_a, pw_a, hs_a, ps_a = make_conn()
    hr_b, hw_b, pr_b, pw_b, hs_b, ps_b = make_conn()

    def plugin_a():
        def handler(r, w):
            req = r.read()
            if req is None:
                return
            while True:
                f = r.read()
                if f is None or f.frame_type == FrameType.END:
                    break
            w.write(Frame.end(req.id, b"from-A"))
        simulate_plugin(pr_a, pw_a, manifest_a, handler)

    def plugin_b():
        def handler(r, w):
            req = r.read()
            if req is None:
                return
            while True:
                f = r.read()
                if f is None or f.frame_type == FrameType.END:
                    break
            w.write(Frame.end(req.id, b"from-B"))
        simulate_plugin(pr_b, pw_b, manifest_b, handler)

    t_a = threading.Thread(target=plugin_a, daemon=True)
    t_b = threading.Thread(target=plugin_b, daemon=True)
    t_a.start()
    t_b.start()

    host = PluginHost()
    host.attach_plugin(hr_a, hw_a)
    host.attach_plugin(hr_b, hw_b)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    responses = {}
    lock = threading.Lock()

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        alpha_id = MessageId.new_uuid()
        w.write(Frame.req(alpha_id, "cap:op=alpha", b"", "text/plain"))
        w.write(Frame.end(alpha_id))
        beta_id = MessageId.new_uuid()
        w.write(Frame.req(beta_id, "cap:op=beta", b"", "text/plain"))
        w.write(Frame.end(beta_id))
        for _ in range(2):
            frame = r.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.END:
                id_str = frame.id.to_string()
                with lock:
                    if id_str == alpha_id.to_string():
                        responses["alpha"] = frame.payload
                    elif id_str == beta_id.to_string():
                        responses["beta"] = frame.payload
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs_a, ps_a, hs_b, ps_b, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    with lock:
        assert responses.get("alpha") == b"from-A"
        assert responses.get("beta") == b"from-B"


# TEST424: Concurrent requests to same plugin handled independently
def test_concurrent_requests_same_plugin():
    manifest = '{"name":"Test","version":"1.0","caps":[{"urn":"cap:op=conc"}]}'
    hr, hw, pr, pw, hs, ps = make_conn()

    def plugin_thread():
        def handler(r, w):
            req_ids = []
            req0 = r.read()
            if req0 is None:
                return
            req_ids.append(req0.id)
            r.read()  # END 0
            req1 = r.read()
            if req1 is None:
                return
            req_ids.append(req1.id)
            r.read()  # END 1
            w.write(Frame.end(req_ids[0], b"response-0"))
            w.write(Frame.end(req_ids[1], b"response-1"))
        simulate_plugin(pr, pw, manifest, handler)

    t_p = threading.Thread(target=plugin_thread, daemon=True)
    t_p.start()

    host = PluginHost()
    host.attach_plugin(hr, hw)

    r_hr, r_hw, r_pr, r_pw, r_hs, r_ps = make_conn()
    responses = {}
    lock = threading.Lock()

    def engine():
        w = FrameWriter(r_pw)
        r = FrameReader(r_pr)
        id0 = MessageId.new_uuid()
        id1 = MessageId.new_uuid()
        w.write(Frame.req(id0, "cap:op=conc", b"", "text/plain"))
        w.write(Frame.end(id0))
        w.write(Frame.req(id1, "cap:op=conc", b"", "text/plain"))
        w.write(Frame.end(id1))
        for _ in range(2):
            frame = r.read()
            if frame is None:
                break
            if frame.frame_type == FrameType.END:
                id_str = frame.id.to_string()
                with lock:
                    if id_str == id0.to_string():
                        responses["0"] = frame.payload
                    elif id_str == id1.to_string():
                        responses["1"] = frame.payload
        close_socks(r_ps)

    t_eng = threading.Thread(target=engine, daemon=True)
    t_eng.start()

    host.run(r_hr, r_hw)
    cleanup(hs, ps, r_hs, r_ps)
    t_eng.join(timeout=5)
    t_p.join(timeout=5)

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
