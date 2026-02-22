"""Tests for plugin_runtime module"""

import pytest
import json
import cbor2
import sys
import queue
import io
from capns.bifaci.plugin_runtime import (
    PluginRuntime,
    NoPeerInvoker,
    CliStreamEmitter,
    PeerRequestError,
    DeserializeError,
    CapUrnError,
    extract_effective_payload,
    collect_args_by_media_urn,
    collect_peer_response,
    RuntimeError as PluginRuntimeError,
    NoHandlerError,
    MissingArgumentError,
    UnknownSubcommandError,
    ManifestError,
    PeerResponseError,
    PendingStream,
    Request,
    WET_KEY_REQUEST,
    dispatch_op,
    OpFactory,
)
from ops import Op, OpMetadata, DryContext, WetContext, ExecutionFailedError
from capns.cap.caller import CapArgumentValue
from capns.bifaci.manifest import CapManifest
from capns.bifaci.frame import DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK, Frame, FrameType, MessageId

# Test manifest JSON with a single cap for basic tests.
# Note: cap URN uses "cap:op=test" which lacks in/out tags, so CapManifest deserialization
# may fail because Cap requires in/out specs. For tests that only need raw manifest bytes
# (CBOR mode handshake), this is fine. For tests that need parsed CapManifest, use
# VALID_MANIFEST instead.
TEST_MANIFEST = '{"name":"TestPlugin","version":"1.0.0","description":"Test plugin","caps":[{"urn":"cap:op=test","title":"Test","command":"test"}]}'

# Valid manifest with proper in/out specs for tests that need parsed CapManifest
VALID_MANIFEST = '{"name":"TestPlugin","version":"1.0.0","description":"Test plugin","caps":[{"urn":"cap:in=\\"media:void\\";op=test;out=\\"media:void\\"","title":"Test","command":"test"}]}'


# =============================================================================
# Test helpers
# =============================================================================

def make_test_frames(media_urn: str, data: bytes) -> queue.Queue:
    """Create a queue.Queue of frames for testing a single-stream input."""
    from capns.bifaci.frame import compute_checksum
    request_id = MessageId(0)
    frames = queue.Queue()
    frames.put(Frame.stream_start(request_id, "arg-0", media_urn))
    encoded = cbor2.dumps(data)
    frames.put(Frame.chunk(request_id, "arg-0", 0, encoded, 0, compute_checksum(encoded)))
    frames.put(Frame.stream_end(request_id, "arg-0", 1))
    frames.put(Frame.end(request_id, None))
    frames.put(None)
    return frames


def invoke_op(factory: OpFactory, frames: queue.Queue, emitter) -> None:
    """Helper: invoke a factory-produced Op with test input/output."""
    op = factory()
    peer = NoPeerInvoker()
    dispatch_op(op, frames, emitter, peer)


# TEST248: Test register_op and find_handler by exact cap URN
def test_248_register_and_find_handler():
    class EmitBytesOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            _ = req.take_frames()
            req.emitter().emit_cbor(b"result")
        def metadata(self): return OpMetadata.builder("EmitBytesOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:in=*;op=test;out=*", EmitBytesOp)
    assert runtime.find_handler("cap:in=*;op=test;out=*") is not None


# TEST249: Test register_op handler echoes bytes directly
def test_249_raw_handler():
    received = []

    class EchoOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames = req.take_frames()
            chunks = []
            for frame in iter(frames.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload:
                    chunks.append(cbor2.loads(frame.payload))
                elif frame.frame_type == FrameType.END:
                    break
            data = b''.join(chunks)
            received.append(data)
            req.emitter().emit_cbor(data)
        def metadata(self): return OpMetadata.builder("EchoOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:op=raw", EchoOp)

    factory = runtime.find_handler("cap:op=raw")
    assert factory is not None

    frames = make_test_frames("media:", b"echo this")
    emitter = CliStreamEmitter()
    invoke_op(factory, frames, emitter)
    assert received[0] == b"echo this", "Op handler must echo payload"


# TEST250: Test Op handler collects input and processes it
def test_250_typed_handler_deserialization():
    received = []

    class JsonKeyOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames = req.take_frames()
            chunks = []
            for frame in iter(frames.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload:
                    chunks.append(cbor2.loads(frame.payload))
                elif frame.frame_type == FrameType.END:
                    break
            all_bytes = b''.join(chunks)
            data = json.loads(all_bytes)
            value = data.get("key", "missing").encode('utf-8')
            received.append(value)
            req.emitter().emit_cbor(value)
        def metadata(self): return OpMetadata.builder("JsonKeyOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:op=test", JsonKeyOp)

    factory = runtime.find_handler("cap:op=test")
    assert factory is not None

    frames = make_test_frames("media:", b'{"key":"hello"}')
    emitter = CliStreamEmitter()
    invoke_op(factory, frames, emitter)
    assert received[0] == b"hello"


# TEST251: Test Op handler propagates errors through HandlerError
def test_251_typed_handler_rejects_invalid_json():
    class JsonParseOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames = req.take_frames()
            chunks = []
            for frame in iter(frames.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload:
                    chunks.append(cbor2.loads(frame.payload))
                elif frame.frame_type == FrameType.END:
                    break
            all_bytes = b''.join(chunks)
            data = json.loads(all_bytes)  # raises on bad JSON
            _ = data
        def metadata(self): return OpMetadata.builder("JsonParseOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:op=test", JsonParseOp)

    factory = runtime.find_handler("cap:op=test")
    frames = make_test_frames("media:", b"not json {{{{")
    emitter = CliStreamEmitter()

    with pytest.raises(Exception) as exc_info:
        invoke_op(factory, frames, emitter)

    assert exc_info.value is not None, "Invalid input must produce an error"


# TEST252: Test find_handler returns None for unregistered cap URNs
def test_252_find_handler_unknown_cap():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    assert runtime.find_handler("cap:op=nonexistent") is None


# TEST253: Test OpFactory can be used across threads (Send + Sync equivalent)
def test_253_handler_is_send_sync():
    import threading

    received = []

    class EmitAndRecordOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            _ = req.take_frames()
            req.emitter().emit_cbor(b"done")
            received.append(b"done")
        def metadata(self): return OpMetadata.builder("EmitAndRecordOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:op=threaded", EmitAndRecordOp)

    factory = runtime.find_handler("cap:op=threaded")
    assert factory is not None

    def thread_func():
        frames = make_test_frames("media:", b"{}")
        emitter = CliStreamEmitter()
        invoke_op(factory, frames, emitter)

    thread = threading.Thread(target=thread_func)
    thread.start()
    thread.join()
    assert received == [b"done"]


# TEST254: Test NoPeerInvoker always returns PeerRequest error regardless of arguments
def test_254_no_peer_invoker():
    no_peer = NoPeerInvoker()

    with pytest.raises(PeerRequestError) as exc_info:
        no_peer.invoke("cap:op=test", [])

    assert "not supported" in str(exc_info.value).lower()


# TEST255: Test NoPeerInvoker returns error even with valid arguments
def test_255_no_peer_invoker_with_arguments():
    no_peer = NoPeerInvoker()
    args = [CapArgumentValue.from_str("media:test", "value")]

    with pytest.raises(PeerRequestError):
        no_peer.invoke("cap:op=test", args)


# TEST256: Test PluginRuntime::with_manifest_json stores manifest data and parses when valid
def test_256_with_manifest_json():
    runtime_basic = PluginRuntime.with_manifest_json(TEST_MANIFEST)
    assert len(runtime_basic.manifest_data) > 0

    # VALID_MANIFEST has proper in/out specs
    runtime_valid = PluginRuntime.with_manifest_json(VALID_MANIFEST)
    assert len(runtime_valid.manifest_data) > 0
    assert runtime_valid.manifest is not None, "VALID_MANIFEST must parse into CapManifest"


# TEST257: Test PluginRuntime::new with invalid JSON still creates runtime (manifest is None)
def test_257_new_with_invalid_json():
    runtime = PluginRuntime(b"not json")
    assert len(runtime.manifest_data) > 0
    assert runtime.manifest is None, "invalid JSON should leave manifest as None"


# TEST258: Test PluginRuntime::with_manifest creates runtime with valid manifest data
def test_258_with_manifest_struct():
    manifest_dict = json.loads(VALID_MANIFEST)
    manifest = CapManifest.from_dict(manifest_dict)
    runtime = PluginRuntime.with_manifest(manifest)
    assert len(runtime.manifest_data) > 0
    assert runtime.manifest is not None


# TEST259: Test extract_effective_payload with single stream matching cap in_spec
def test_259_extract_effective_payload_non_cbor():
    # Single stream with data matching the cap's input spec
    streams = [
        ("stream-0", PendingStream(media_urn="media:", chunks=[b"raw data"], complete=True))
    ]
    result = extract_effective_payload(streams, "cap:in=media:;op=test;out=*")
    assert result == b"raw data", "Should extract matching stream"


# TEST260: Test extract_effective_payload with wildcard in_spec accepts any stream
def test_260_extract_effective_payload_no_content_type():
    streams = [
        ("stream-0", PendingStream(media_urn="media:", chunks=[b"raw data"], complete=True))
    ]
    result = extract_effective_payload(streams, "cap:in=*;op=test;out=*")
    assert result == b"raw data", "Wildcard should accept any stream"


# TEST261: Test extract_effective_payload extracts matching stream by media URN
def test_261_extract_effective_payload_cbor_match():
    # Stream with media URN that matches cap's input spec
    streams = [
        ("stream-0", PendingStream(
            media_urn="media:string;textable;form=scalar",
            chunks=[b"hello"],
            complete=True
        ))
    ]
    result = extract_effective_payload(
        streams,
        "cap:in=media:string;textable;form=scalar;op=test;out=*"
    )
    assert result == b"hello"


# TEST262: Test extract_effective_payload fails when no stream matches expected input
def test_262_extract_effective_payload_cbor_no_match():
    # Multiple streams, none match cap's specific input spec
    streams = [
        ("stream-0", PendingStream(
            media_urn="media:other-type",
            chunks=[b"wrong1"],
            complete=True
        )),
        ("stream-1", PendingStream(
            media_urn="media:different-type",
            chunks=[b"wrong2"],
            complete=True
        ))
    ]

    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            streams,
            "cap:in=media:string;textable;form=scalar;op=test;out=*"
        )

    assert "No stream found matching" in str(exc_info.value)


# TEST263: Test extract_effective_payload with empty streams returns error
def test_263_extract_effective_payload_invalid_cbor():
    # No streams provided
    streams = []
    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            streams,
            "cap:in=media:;op=test;out=*"
        )
    assert "No stream found matching" in str(exc_info.value)


# TEST264: Test extract_effective_payload with incomplete stream skips it
def test_264_extract_effective_payload_cbor_not_array():
    # Stream that's not complete
    streams = [
        ("stream-0", PendingStream(media_urn="media:", chunks=[b"data"], complete=False))
    ]

    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            streams,
            "cap:in=media:;op=test;out=*"
        )

    assert "No stream found matching" in str(exc_info.value)


# TEST265: Test extract_effective_payload with invalid cap URN returns CapUrn error
def test_265_extract_effective_payload_invalid_cap_urn():
    streams = []

    with pytest.raises(CapUrnError):
        extract_effective_payload(
            streams,
            "not-a-cap-urn"
        )


# TEST266: Test CliStreamEmitter writes to stdout and stderr correctly (basic construction)
def test_266_cli_stream_emitter_construction():
    emitter = CliStreamEmitter()
    assert emitter.ndjson, "default CLI emitter must use NDJSON"

    emitter2 = CliStreamEmitter.without_ndjson()
    assert not emitter2.ndjson


# TEST268: Test RuntimeError variants display correct messages
def test_268_runtime_error_display():
    err = NoHandlerError("cap:op=missing")
    assert "cap:op=missing" in str(err)

    err2 = MissingArgumentError("model")
    assert "model" in str(err2)

    err3 = UnknownSubcommandError("badcmd")
    assert "badcmd" in str(err3)

    err4 = ManifestError("parse failed")
    assert "parse failed" in str(err4)

    err5 = PeerRequestError("denied")
    assert "denied" in str(err5)

    err6 = PeerResponseError("timeout")
    assert "timeout" in str(err6)


# TEST270: Test registering multiple Op handlers for different caps and finding each independently
def test_270_multiple_handlers():
    class EchoTagOp(Op):
        def __init__(self, tag: bytes):
            self.tag = tag
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            _ = req.take_frames()
            req.emitter().emit_cbor(self.tag)
        def metadata(self): return OpMetadata.builder("EchoTagOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op("cap:op=alpha", lambda: EchoTagOp(b"a"))
    runtime.register_op("cap:op=beta", lambda: EchoTagOp(b"b"))
    runtime.register_op("cap:op=gamma", lambda: EchoTagOp(b"g"))

    emitter = CliStreamEmitter()
    f_alpha = runtime.find_handler("cap:op=alpha")
    invoke_op(f_alpha, make_test_frames("media:", b""), emitter)

    f_beta = runtime.find_handler("cap:op=beta")
    invoke_op(f_beta, make_test_frames("media:", b""), emitter)

    f_gamma = runtime.find_handler("cap:op=gamma")
    invoke_op(f_gamma, make_test_frames("media:", b""), emitter)


# TEST271: Test Op handler replacing an existing registration for the same cap URN
def test_271_handler_replacement():
    result2 = []

    class FirstOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            _ = req.take_frames()
            req.emitter().emit_cbor(b"first")
        def metadata(self): return OpMetadata.builder("FirstOp").build()

    class SecondOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            _ = req.take_frames()
            req.emitter().emit_cbor(b"second")
            result2.append(b"second")
        def metadata(self): return OpMetadata.builder("SecondOp").build()

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    runtime.register_op_type("cap:op=test", FirstOp)
    runtime.register_op_type("cap:op=test", SecondOp)

    factory = runtime.find_handler("cap:op=test")
    assert factory is not None

    emitter = CliStreamEmitter()
    invoke_op(factory, make_test_frames("media:", b""), emitter)
    assert result2 == [b"second"], "later registration must replace earlier"


# TEST272: Test extract_effective_payload with multiple streams selects the correct one
def test_272_extract_effective_payload_multiple_args():
    # Multiple streams, only one matches the cap's input spec
    streams = [
        ("stream-0", PendingStream(
            media_urn="media:other-type;textable",
            chunks=[b"wrong"],
            complete=True
        )),
        ("stream-1", PendingStream(
            media_urn="media:model-spec;textable;form=scalar",
            chunks=[b"correct"],
            complete=True
        ))
    ]

    result = extract_effective_payload(
        streams,
        "cap:in=media:model-spec;textable;form=scalar;op=infer;out=*"
    )
    assert result == b"correct"


# TEST273: Test extract_effective_payload with binary data in stream (not just text)
def test_273_extract_effective_payload_binary_value():
    binary_data = bytes(range(256))
    streams = [
        ("stream-0", PendingStream(
            media_urn="media:pdf",
            chunks=[binary_data],
            complete=True
        ))
    ]

    result = extract_effective_payload(
        streams,
        "cap:in=media:pdf;op=process;out=*"
    )
    assert result == binary_data, "binary values must roundtrip through stream extraction"


# =============================================================================
# File-path to bytes conversion tests (TEST336-TEST360)
# =============================================================================

def create_test_cap(urn_str: str, title: str, command: str, args: list) -> 'Cap':
    """Helper function to create a Cap for tests"""
    from capns.urn.cap_urn import CapUrn
    from capns.cap.definition import Cap
    urn = CapUrn.from_string(urn_str)
    cap = Cap(urn, title, command)
    cap.args = args
    return cap


def create_test_manifest(name: str, version: str, description: str, caps: list) -> CapManifest:
    """Helper function to create a CapManifest for tests"""
    return CapManifest(
        name=name,
        version=version,
        description=description,
        caps=caps
    )


# TEST336: Single file-path arg with stdin source reads file and passes bytes to handler
def test_336_file_path_reads_file_passes_bytes(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.frame import compute_checksum

    test_file = tmp_path / "test336_input.pdf"
    test_file.write_bytes(b"PDF binary content 336")

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process PDF",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    received_payload = []

    class CollectBytesOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames_q = req.take_frames()
            chunks = []
            for frame in iter(frames_q.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload:
                    chunks.append(cbor2.loads(frame.payload))
                elif frame.frame_type == FrameType.END:
                    break
            received_payload.append(b''.join(chunks))
        def metadata(self): return OpMetadata.builder("CollectBytesOp").build()

    runtime.register_op('cap:in="media:pdf";op=process;out="media:void"', CollectBytesOp)

    # Simulate CLI invocation: plugin process /path/to/file.pdf
    cli_args = [str(test_file)]
    cap = runtime.find_cap_by_command(runtime.manifest, 'process')
    assert cap is not None, "Process cap not found in manifest"
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Build frame queue like run_cli_mode does
    request_id = MessageId(0)
    frames = queue.Queue()
    for i, arg in enumerate(arguments):
        stream_id = f"arg-{i}"
        frames.put(Frame.stream_start(request_id, stream_id, arg.media_urn))
        encoded = cbor2.dumps(arg.value)
        frames.put(Frame.chunk(request_id, stream_id, 0, encoded, 0, compute_checksum(encoded)))
        frames.put(Frame.stream_end(request_id, stream_id, 1))
    frames.put(Frame.end(request_id, None))
    frames.put(None)

    factory = runtime.find_handler(cap.urn_string())
    emitter = CliStreamEmitter()
    invoke_op(factory, frames, emitter)

    # Verify handler received file bytes, not file path
    assert received_payload[0] == b"PDF binary content 336", "Handler should receive file bytes"


# TEST337: file-path arg without stdin source passes path as string (no conversion)
def test_337_file_path_without_stdin_passes_string(tmp_path):
    from capns.cap.definition import CapArg, PositionSource

    test_file = tmp_path / "test337_input.txt"
    test_file.write_bytes(b"content")

    cap = create_test_cap(
        'cap:in="media:void";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[PositionSource(0)]  # NO stdin source!
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Should get file PATH as string, not file CONTENTS
    value_str = result.decode('utf-8')
    assert "test337_input.txt" in value_str, "Should receive file path string when no stdin source"


# TEST338: file-path arg reads file via --file CLI flag
def test_338_file_path_via_cli_flag(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, CliFlagSource

    test_file = tmp_path / "test338.pdf"
    test_file.write_bytes(b"PDF via flag 338")

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                CliFlagSource("--file"),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["--file", str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"PDF via flag 338", "Should read file from --file flag"


# TEST339: file-path-array reads multiple files with glob pattern
def test_339_file_path_array_glob_expansion(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test339"
    test_dir.mkdir()

    file1 = test_dir / "doc1.txt"
    file2 = test_dir / "doc2.txt"
    file1.write_bytes(b"content1")
    file2.write_bytes(b"content2")

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Batch",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Pass glob pattern as JSON array
    pattern = f"{test_dir}/*.txt"
    paths_json = json.dumps([pattern])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 2, "Should find 2 files"

    # Verify contents (order may vary, so sort)
    bytes_vec = sorted(files_array)
    assert bytes_vec == [b"content1", b"content2"]


# TEST340: File not found error provides clear message
def test_340_file_not_found_clear_error():
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.plugin_runtime import IoRuntimeError

    cap = create_test_cap(
        'cap:in="media:pdf";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["/nonexistent/file.pdf"]
    # cap is already defined above with correct URN and args

    with pytest.raises(IoRuntimeError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err_msg = str(exc_info.value)
    assert "/nonexistent/file.pdf" in err_msg, "Error should mention file path"
    assert "Failed to read file" in err_msg, "Error should be clear"


# TEST341: stdin takes precedence over file-path in source order
def test_341_stdin_precedence_over_file_path(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test341_input.txt"
    test_file.write_bytes(b"file content")

    # Stdin source comes BEFORE position source
    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),  # First
                PositionSource(0),            # Second
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    stdin_data = b"stdin content 341"
    # cap is already defined above with correct URN and args

    result = runtime._extract_arg_value(cap.args[0], cli_args, stdin_data)

    # Should get stdin data, not file content (stdin source tried first)
    assert result == b"stdin content 341", "stdin source should take precedence"


# TEST342: file-path with position 0 reads first positional arg as file
def test_342_file_path_position_zero_reads_first_arg(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test342.dat"
    test_file.write_bytes(b"binary data 342")

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # CLI: plugin test /path/to/file (position 0 after subcommand)
    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"binary data 342", "Should read file at position 0"


# TEST343: Non-file-path args are not affected by file reading
def test_343_non_file_path_args_unaffected():
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    # Arg with different media type should NOT trigger file reading
    cap = create_test_cap(
        'cap:in="media:void";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:model-spec;textable;form=scalar",  # NOT file-path
            required=True,
            sources=[
                StdinSource("media:model-spec;textable;form=scalar"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["mlx-community/Llama-3.2-3B-Instruct-4bit"]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Should get the string value, not attempt file read
    value_str = result.decode('utf-8')
    assert value_str == "mlx-community/Llama-3.2-3B-Instruct-4bit"


# TEST344: file-path-array with invalid JSON fails clearly
def test_344_file_path_array_invalid_json_fails():
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.plugin_runtime import CliError

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Pass invalid JSON (not an array)
    cli_args = ["not a json array"]
    # cap is already defined above with correct URN and args

    with pytest.raises(CliError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "Failed to parse file-path-array" in err, "Error should mention file-path-array"
    assert "expected JSON array" in err, "Error should explain expected format"


# TEST345: file-path-array with one file failing stops and reports error
def test_345_file_path_array_one_file_missing_fails_hard(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.plugin_runtime import IoRuntimeError

    file1 = tmp_path / "test345_exists.txt"
    file1.write_bytes(b"exists")
    file2_path = tmp_path / "test345_missing.txt"

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Explicitly list both files (one exists, one doesn't)
    paths_json = json.dumps([
        str(file1),
        str(file2_path),  # Doesn't exist!
    ])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args

    with pytest.raises(IoRuntimeError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "test345_missing.txt" in err, "Error should mention the missing file"
    assert "Failed to read file" in err, "Error should be clear about read failure"


# TEST346: Large file (1MB) reads successfully
def test_346_large_file_reads_successfully(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test346_large.bin"

    # Create 1MB file
    large_data = bytes([42] * 1_000_000)
    test_file.write_bytes(large_data)

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert len(result) == 1_000_000, "Should read entire 1MB file"
    assert result == large_data, "Content should match exactly"


# TEST347: Empty file reads as empty bytes
def test_347_empty_file_reads_as_empty_bytes(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test347_empty.txt"
    test_file.write_bytes(b"")

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"", "Empty file should produce empty bytes"


# TEST348: file-path conversion respects source order
def test_348_file_path_conversion_respects_source_order(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test348.txt"
    test_file.write_bytes(b"file content 348")

    # Position source BEFORE stdin source
    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                PositionSource(0),            # First
                StdinSource("media:"),  # Second
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    stdin_data = b"stdin content 348"
    # cap is already defined above with correct URN and args

    result = runtime._extract_arg_value(cap.args[0], cli_args, stdin_data)

    # Position source tried first, so file is read
    assert result == b"file content 348", "Position source tried first, file read"


# TEST349: file-path arg with multiple sources tries all in order
def test_349_file_path_multiple_sources_fallback(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource, CliFlagSource

    test_file = tmp_path / "test349.txt"
    test_file.write_bytes(b"content 349")

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                CliFlagSource("--file"),     # First (not provided)
                PositionSource(0),            # Second (provided)
                StdinSource("media:"),  # Third (not used)
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Only provide position arg, no --file flag
    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"content 349", "Should fall back to position source and read file"


# TEST350: Integration test - full CLI mode invocation with file-path
def test_350_full_cli_mode_with_file_path_integration(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.frame import compute_checksum

    test_file = tmp_path / "test350_input.pdf"
    test_content = b"PDF file content for integration test"
    test_file.write_bytes(test_content)

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:result;textable"',
        "Process PDF",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    received_payload = []

    class CollectBytesOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames_q = req.take_frames()
            chunks = []
            for frame in iter(frames_q.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload:
                    chunks.append(cbor2.loads(frame.payload))
                elif frame.frame_type == FrameType.END:
                    break
            received_payload.append(b''.join(chunks))
        def metadata(self): return OpMetadata.builder("CollectBytesOp").build()

    runtime.register_op(
        'cap:in="media:pdf";op=process;out="media:result;textable"',
        CollectBytesOp,
    )

    # Simulate full CLI invocation
    cli_args = [str(test_file)]
    cap = runtime.find_cap_by_command(runtime.manifest, 'process')
    assert cap is not None, "Process cap not found in manifest"
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Build frame queue like run_cli_mode does
    request_id = MessageId(0)
    frames = queue.Queue()
    for i, arg in enumerate(arguments):
        stream_id = f"arg-{i}"
        frames.put(Frame.stream_start(request_id, stream_id, arg.media_urn))
        encoded = cbor2.dumps(arg.value)
        frames.put(Frame.chunk(request_id, stream_id, 0, encoded, 0, compute_checksum(encoded)))
        frames.put(Frame.stream_end(request_id, stream_id, 1))
    frames.put(Frame.end(request_id, None))
    frames.put(None)

    factory = runtime.find_handler(cap.urn_string())
    emitter = CliStreamEmitter()
    invoke_op(factory, frames, emitter)

    # Verify handler received file bytes
    assert received_payload[0] == test_content, "Handler should receive file bytes, not path"


# TEST351: file-path-array with empty array succeeds
def test_351_file_path_array_empty_array():
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=False,  # Not required
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["[]"]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 0, "Empty array should produce empty result"


# TEST352: file permission denied error is clear (Unix-specific)
@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions only")
def test_352_file_permission_denied_clear_error(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.plugin_runtime import IoRuntimeError
    import os

    test_file = tmp_path / "test352_noperm.txt"
    test_file.write_bytes(b"content")

    # Remove read permissions
    os.chmod(test_file, 0o000)

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args

    try:
        with pytest.raises(IoRuntimeError) as exc_info:
            runtime._extract_arg_value(cap.args[0], cli_args, None)

        err = str(exc_info.value)
        assert "test352_noperm.txt" in err, "Error should mention the file"
    finally:
        # Cleanup: restore permissions then delete
        os.chmod(test_file, 0o644)


# TEST353: CBOR payload format matches between CLI and CBOR mode
def test_353_cbor_payload_format_consistency():
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    cap = create_test_cap(
        'cap:in="media:text;textable";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:text;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:text;textable"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["test value"]
    # cap is already defined above with correct URN and args
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Verify structure of CapArgumentValue list
    assert len(arguments) == 1, "Should have 1 argument"

    # Check the CapArgumentValue object
    arg = arguments[0]
    assert arg.media_urn == "media:text;textable;form=scalar"
    assert arg.value == b"test value"


# TEST354: Glob pattern with no matches produces empty array
def test_354_glob_pattern_no_matches_empty_array(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Glob pattern that matches nothing
    pattern = f"{tmp_path}/nonexistent_*.xyz"
    paths_json = json.dumps([pattern])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 0, "No matches should produce empty array"


# TEST355: Glob pattern skips directories
def test_355_glob_pattern_skips_directories(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test355"
    test_dir.mkdir()

    subdir = test_dir / "subdir"
    subdir.mkdir()

    file1 = test_dir / "file1.txt"
    file1.write_bytes(b"content1")

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Glob that matches both file and directory
    pattern = f"{test_dir}/*"
    paths_json = json.dumps([pattern])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    # Should only include the file, not the directory
    assert len(files_array) == 1, "Should only include files, not directories"
    assert files_array[0] == b"content1"


# TEST356: Multiple glob patterns combined
def test_356_multiple_glob_patterns_combined(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test356"
    test_dir.mkdir()

    file1 = test_dir / "doc.txt"
    file2 = test_dir / "data.json"
    file1.write_bytes(b"text")
    file2.write_bytes(b"json")

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Multiple patterns
    pattern1 = f"{test_dir}/*.txt"
    pattern2 = f"{test_dir}/*.json"
    paths_json = json.dumps([pattern1, pattern2])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 2, "Should find both files from different patterns"

    # Collect contents (order may vary)
    contents = sorted(files_array)
    assert contents == [b"json", b"text"]


# TEST357: Symlinks are followed when reading files
@pytest.mark.skipif(sys.platform == "win32", reason="Unix symlinks only")
def test_357_symlinks_followed(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    import os

    test_dir = tmp_path / "test357"
    test_dir.mkdir()

    real_file = test_dir / "real.txt"
    link_file = test_dir / "link.txt"
    real_file.write_bytes(b"real content")
    os.symlink(real_file, link_file)

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(link_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"real content", "Should follow symlink and read real file"


# TEST358: Binary file with non-UTF8 data reads correctly
def test_358_binary_file_non_utf8(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test358.bin"

    # Binary data that's not valid UTF-8
    binary_data = bytes([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x7F, 0xAB, 0xCD])
    test_file.write_bytes(binary_data)

    cap = create_test_cap(
        'cap:in="media:";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == binary_data, "Binary data should read correctly"


# TEST359: Invalid glob pattern fails with clear error
def test_359_invalid_glob_pattern_fails():
    from capns.cap.definition import CapArg, StdinSource, PositionSource
    from capns.bifaci.plugin_runtime import CliError

    cap = create_test_cap(
        'cap:in="media:";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Invalid glob pattern (unclosed bracket)
    pattern = "[invalid"
    paths_json = json.dumps([pattern])

    cli_args = [paths_json]
    # cap is already defined above with correct URN and args

    with pytest.raises(CliError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "Invalid glob pattern" in err, "Error should mention invalid glob"


# TEST360: Extract effective payload handles file-path data correctly
def test_360_extract_effective_payload_with_file_data(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test360.pdf"
    pdf_content = b"PDF content for extraction test"
    test_file.write_bytes(pdf_content)

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    # cap is already defined above with correct URN and args

    # Build arguments (what build_arguments_from_cli does)
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Extract effective payload (what run_cli_mode does)
    streams = [
        (f"arg-{i}", PendingStream(media_urn=arg.media_urn, chunks=[arg.value], complete=True))
        for i, arg in enumerate(arguments)
    ]
    effective = extract_effective_payload(streams, cap.urn_string())

    # The effective payload should be the raw PDF bytes
    assert effective == pdf_content, "extract_effective_payload should extract file bytes"


# TEST361: CLI mode with file path - pass file path as command-line argument
def test_361_cli_mode_file_path(tmp_path):
    from capns.cap.definition import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test361.pdf"
    pdf_content = b"PDF content for CLI file path test"
    test_file.write_bytes(pdf_content)

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # CLI mode: pass file path as positional argument
    cli_args = [str(test_file)]
    cap = runtime.find_cap_by_command(runtime.manifest, cap.command)
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Verify arguments contain file-path URN (before conversion)
    assert len(arguments) == 1
    # The argument should have the stdin source URN (after conversion)
    assert arguments[0].media_urn == "media:pdf"
    assert arguments[0].value == pdf_content


# TEST362: CLI mode with binary piped in - pipe binary data via stdin
#
# This test simulates real-world conditions:
# - Pure binary data piped to stdin (NOT CBOR)
# - CLI mode detected (command arg present)
# - Cap accepts stdin source
# - Binary is chunked on-the-fly and accumulated
# - Handler receives complete CBOR payload
def test_362_cli_mode_piped_binary():
    from capns.cap.definition import CapArg, StdinSource
    import io

    # Simulate large binary being piped (1MB PDF)
    pdf_content = bytes([0xAB] * 1_000_000)

    # Create cap that accepts stdin
    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:pdf",
            required=True,
            sources=[
                StdinSource("media:pdf"),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Mock stdin with BytesIO (simulates piped binary)
    mock_stdin = io.BytesIO(pdf_content)

    # Build payload from streaming reader (what CLI piped mode does)
    from capns.bifaci.frame import DEFAULT_MAX_CHUNK
    payload = runtime._build_payload_from_streaming_reader(cap, mock_stdin, DEFAULT_MAX_CHUNK)

    # Verify payload is CBOR array with correct structure
    cbor_val = cbor2.loads(payload)
    assert isinstance(cbor_val, list), "Expected CBOR array"
    assert len(cbor_val) == 1, "CBOR array should have one argument"

    arg_map = cbor_val[0]
    assert isinstance(arg_map, dict), "Expected Map in CBOR array"

    media_urn = arg_map.get("media_urn")
    value = arg_map.get("value")

    assert media_urn == "media:pdf", "Media URN should match cap in_spec"
    assert value == pdf_content, "Binary content should be preserved exactly"


# TEST363: CBOR mode with chunked content - send file content streaming as chunks
def test_363_cbor_mode_chunked_content():
    from capns.cap.definition import CapArg, StdinSource

    pdf_content = bytes([0xAA] * 10000)  # 10KB of data
    received_data = []

    class StreamingOp(Op):
        async def perform(self, dry, wet):
            req = wet.get_required(WET_KEY_REQUEST)
            frames_q = req.take_frames()
            total = bytearray()
            for frame in iter(frames_q.get, None):
                if frame.frame_type == FrameType.CHUNK and frame.payload is not None:
                    total.extend(frame.payload)
                elif frame.frame_type == FrameType.END:
                    break
            cbor_val = cbor2.loads(bytes(total))
            if isinstance(cbor_val, list) and len(cbor_val) > 0:
                arg_map = cbor_val[0]
                if isinstance(arg_map, dict) and "value" in arg_map:
                    received_data.append(arg_map["value"])
        def metadata(self): return OpMetadata.builder("StreamingOp").build()

    cap = create_test_cap(
        'cap:in="media:pdf";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:pdf",
            required=True,
            sources=[
                StdinSource("media:pdf"),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)
    runtime.register_op(cap.urn_string(), StreamingOp)

    # Build CBOR payload
    from capns.cap.caller import CapArgumentValue
    args = [CapArgumentValue(media_urn="media:pdf", value=pdf_content)]
    payload_bytes = cbor2.dumps([
        {
            "media_urn": arg.media_urn,
            "value": arg.value,
        }
        for arg in args
    ])

    from capns.bifaci.frame import compute_checksum
    factory = runtime.find_handler(cap.urn_string())
    assert factory is not None, "Handler not found"

    emitter = CliStreamEmitter()
    frames = queue.Queue()
    max_chunk = 262144
    request_id = MessageId(0)
    stream_id = "test-stream"

    # Send STREAM_START
    frames.put(Frame.stream_start(request_id, stream_id, "media:"))

    # Send CHUNK frames (raw payload bytes, not CBOR-re-encoded)
    offset = 0
    seq = 0
    while offset < len(payload_bytes):
        chunk_size = min(len(payload_bytes) - offset, max_chunk)
        chunk = payload_bytes[offset:offset + chunk_size]
        frames.put(Frame.chunk(request_id, stream_id, seq, chunk, seq, compute_checksum(chunk)))
        offset += chunk_size
        seq += 1

    # Send STREAM_END and END
    frames.put(Frame.stream_end(request_id, stream_id, seq))
    frames.put(Frame.end(request_id, None))
    frames.put(None)

    invoke_op(factory, frames, emitter)

    assert len(received_data) == 1, "Should receive data"
    assert received_data[0] == pdf_content, "Handler should receive chunked content"


# TEST364: CBOR mode with file path - send file path in CBOR arguments (auto-conversion)
def test_364_cbor_mode_file_path(tmp_path):
    test_file = tmp_path / "test364.pdf"
    pdf_content = b"PDF content for CBOR file path test"
    test_file.write_bytes(pdf_content)

    # Build CBOR arguments with file-path URN
    from capns.cap.caller import CapArgumentValue
    args = [CapArgumentValue(
        media_urn="media:file-path;textable;form=scalar",
        value=str(test_file).encode('utf-8'),
    )]
    payload = cbor2.dumps([
        {
            "media_urn": arg.media_urn,
            "value": arg.value,
        }
        for arg in args
    ])

    # Verify the CBOR structure is correct
    decoded = cbor2.loads(payload)
    assert isinstance(decoded, list), "Expected CBOR array"
    assert len(decoded) == 1, "Expected 1 argument"

    arg_map = decoded[0]
    assert isinstance(arg_map, dict), "Expected map"

    media_urn = arg_map.get("media_urn")
    value = arg_map.get("value")

    assert media_urn == "media:file-path;textable;form=scalar", "Expected media:file-path URN"
    assert value == str(test_file).encode('utf-8'), "Expected file path as value"


# TEST395: Small payload (< max_chunk) produces correct CBOR arguments
def test_395_build_payload_small():
    cap = create_test_cap(
        'cap:in="media:";op=process;out="media:void"',
        "Process",
        "process",
        [],
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    data = b"small payload"
    reader = io.BytesIO(data)

    from capns.bifaci.frame import DEFAULT_MAX_CHUNK
    payload = runtime._build_payload_from_streaming_reader(cap, reader, DEFAULT_MAX_CHUNK)

    # Verify CBOR structure
    cbor_val = cbor2.loads(payload)
    assert isinstance(cbor_val, list), f"Expected list, got: {type(cbor_val)}"
    assert len(cbor_val) == 1, f"Should have one argument, got: {len(cbor_val)}"

    arg_map = cbor_val[0]
    assert isinstance(arg_map, dict), f"Expected dict, got: {type(arg_map)}"
    assert "value" in arg_map, "Argument should have 'value' field"

    value_bytes = arg_map["value"]
    assert isinstance(value_bytes, bytes), f"Expected bytes, got: {type(value_bytes)}"
    assert value_bytes == data, f"Payload bytes should match, expected: {data}, got: {value_bytes}"


# TEST396: Large payload (> max_chunk) accumulates across chunks correctly
def test_396_build_payload_large():
    cap = create_test_cap(
        'cap:in="media:";op=process;out="media:void"',
        "Process",
        "process",
        [],
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Use small max_chunk to force multi-chunk
    data = bytes(i % 256 for i in range(1000))
    reader = io.BytesIO(data)

    payload = runtime._build_payload_from_streaming_reader(cap, reader, 100)

    cbor_val = cbor2.loads(payload)
    arr = cbor_val
    arg_map = arr[0]
    value_bytes = arg_map["value"]

    assert len(value_bytes) == 1000, f"All bytes should be accumulated, expected: 1000, got: {len(value_bytes)}"
    assert value_bytes == data, "Data should match exactly"


# TEST397: Empty reader produces valid empty CBOR arguments
def test_397_build_payload_empty():
    cap = create_test_cap(
        'cap:in="media:";op=process;out="media:void"',
        "Process",
        "process",
        [],
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    reader = io.BytesIO(b"")

    from capns.bifaci.frame import DEFAULT_MAX_CHUNK
    payload = runtime._build_payload_from_streaming_reader(cap, reader, DEFAULT_MAX_CHUNK)

    cbor_val = cbor2.loads(payload)
    arr = cbor_val
    arg_map = arr[0]
    value_bytes = arg_map["value"]

    assert len(value_bytes) == 0, f"Empty reader should produce empty bytes, got: {len(value_bytes)} bytes"


# ErrorReader that simulates an IO error
class ErrorReader:
    def read(self, size=-1):
        raise IOError("simulated read error")


# TEST398: IO error from reader propagates as error
def test_398_build_payload_io_error():
    cap = create_test_cap(
        'cap:in="media:";op=process;out="media:void"',
        "Process",
        "process",
        [],
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    reader = ErrorReader()

    from capns.bifaci.frame import DEFAULT_MAX_CHUNK
    with pytest.raises(IOError) as exc_info:
        runtime._build_payload_from_streaming_reader(cap, reader, DEFAULT_MAX_CHUNK)

    assert "simulated read error" in str(exc_info.value), f"Expected 'simulated read error', got: {exc_info.value}"


# TEST479: Custom identity Op overrides auto-registered default
def test_479_custom_identity_overrides_default():
    from capns.standard.caps import CAP_IDENTITY

    class FailOp(Op):
        async def perform(self, dry, wet):
            raise ExecutionFailedError("custom identity")
        def metadata(self): return OpMetadata.builder("FailOp").build()

    runtime = PluginRuntime.with_manifest_json(VALID_MANIFEST)

    # Auto-registered identity handler must exist
    assert runtime.find_handler(CAP_IDENTITY) is not None, "Auto-registered identity must exist"

    # Count handlers before override
    handlers_before = len(runtime.handlers)

    # Override identity with a custom Op
    runtime.register_op_type(CAP_IDENTITY, FailOp)

    # Handler count must not change (dict insert replaces, doesn't add)
    assert len(runtime.handlers) == handlers_before, \
        "Replacing identity must not increase handler count"

    # Custom Op must be invoked (not the default)
    factory = runtime.find_handler(CAP_IDENTITY)
    assert factory is not None
    frames = make_test_frames("media:", b"test")
    emitter = CliStreamEmitter()
    with pytest.raises(Exception) as exc_info:
        invoke_op(factory, frames, emitter)
    assert "custom identity" in str(exc_info.value), \
        f"Custom identity Op must be called: {exc_info.value}"
