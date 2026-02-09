"""Tests for plugin_runtime module"""

import pytest
import json
import cbor2
import sys
from capns.plugin_runtime import (
    PluginRuntime,
    NoPeerInvoker,
    CliStreamEmitter,
    PeerRequestError,
    DeserializeError,
    CapUrnError,
    extract_effective_payload,
    RuntimeError as PluginRuntimeError,
    NoHandlerError,
    MissingArgumentError,
    UnknownSubcommandError,
    ManifestError,
    PeerResponseError,
    PendingStream,
)
from capns.caller import CapArgumentValue
from capns.manifest import CapManifest
from capns.cbor_frame import DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK

# Test manifest JSON with a single cap for basic tests.
# Note: cap URN uses "cap:op=test" which lacks in/out tags, so CapManifest deserialization
# may fail because Cap requires in/out specs. For tests that only need raw manifest bytes
# (CBOR mode handshake), this is fine. For tests that need parsed CapManifest, use
# VALID_MANIFEST instead.
TEST_MANIFEST = '{"name":"TestPlugin","version":"1.0.0","description":"Test plugin","caps":[{"urn":"cap:op=test","title":"Test","command":"test"}]}'

# Valid manifest with proper in/out specs for tests that need parsed CapManifest
VALID_MANIFEST = '{"name":"TestPlugin","version":"1.0.0","description":"Test plugin","caps":[{"urn":"cap:in=\\"media:void\\";op=test;out=\\"media:void\\"","title":"Test","command":"test"}]}'


# TEST248: Test register handler by exact cap URN and find it by the same URN
def test_register_and_find_handler():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    def handler(request, emitter, peer):
        return b"result"

    runtime.register("cap:in=*;op=test;out=*", handler)

    assert runtime.find_handler("cap:in=*;op=test;out=*") is not None


# TEST249: Test register_raw handler works with bytes directly without deserialization
def test_raw_handler():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    def raw_handler(payload, emitter, peer):
        return payload

    runtime.register_raw("cap:op=raw", raw_handler)

    handler = runtime.find_handler("cap:op=raw")
    assert handler is not None

    no_peer = NoPeerInvoker()
    emitter = CliStreamEmitter()
    result = handler(b"echo this", emitter, no_peer)
    assert result == b"echo this", "raw handler must echo payload"


# TEST250: Test register typed handler deserializes JSON and executes correctly
def test_typed_handler_deserialization():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    def handler(req, emitter, peer):
        value = req.get("key", "missing")
        return value.encode('utf-8')

    runtime.register("cap:op=test", handler)

    handler_fn = runtime.find_handler("cap:op=test")
    assert handler_fn is not None

    no_peer = NoPeerInvoker()
    emitter = CliStreamEmitter()
    result = handler_fn(b'{"key":"hello"}', emitter, no_peer)
    assert result == b"hello"


# TEST251: Test typed handler returns RuntimeError::Deserialize for invalid JSON input
def test_typed_handler_rejects_invalid_json():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    def handler(req, emitter, peer):
        return b""

    runtime.register("cap:op=test", handler)

    handler_fn = runtime.find_handler("cap:op=test")
    assert handler_fn is not None

    no_peer = NoPeerInvoker()
    emitter = CliStreamEmitter()

    with pytest.raises(DeserializeError) as exc_info:
        handler_fn(b"not json {{{{", emitter, no_peer)

    assert "Failed to parse request" in str(exc_info.value)


# TEST252: Test find_handler returns None for unregistered cap URNs
def test_find_handler_unknown_cap():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    assert runtime.find_handler("cap:op=nonexistent") is None


# TEST253: Test handler function can be cloned via Arc and sent across threads (Send + Sync)
def test_handler_is_send_sync():
    import threading

    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    def handler(req, emitter, peer):
        return b"done"

    runtime.register("cap:op=threaded", handler)

    handler_fn = runtime.find_handler("cap:op=threaded")
    assert handler_fn is not None

    result_holder = []

    def thread_func():
        no_peer = NoPeerInvoker()
        emitter = CliStreamEmitter()
        result = handler_fn(b"{}", emitter, no_peer)
        result_holder.append(result)

    thread = threading.Thread(target=thread_func)
    thread.start()
    thread.join()

    assert result_holder[0] == b"done"


# TEST254: Test NoPeerInvoker always returns PeerRequest error regardless of arguments
def test_no_peer_invoker():
    no_peer = NoPeerInvoker()

    with pytest.raises(PeerRequestError) as exc_info:
        no_peer.invoke("cap:op=test", [])

    assert "not supported" in str(exc_info.value).lower()


# TEST255: Test NoPeerInvoker returns error even with valid arguments
def test_no_peer_invoker_with_arguments():
    no_peer = NoPeerInvoker()
    args = [CapArgumentValue.from_str("media:test", "value")]

    with pytest.raises(PeerRequestError):
        no_peer.invoke("cap:op=test", args)


# TEST256: Test PluginRuntime::with_manifest_json stores manifest data and parses when valid
def test_with_manifest_json():
    # TEST_MANIFEST has "cap:op=test" which lacks in/out, so CapManifest parsing fails
    runtime_basic = PluginRuntime.with_manifest_json(TEST_MANIFEST)
    assert len(runtime_basic.manifest_data) > 0
    # The cap URN "cap:op=test" is invalid for CapManifest (missing in/out)
    # so manifest parse is expected to fail - this is correct behavior
    assert runtime_basic.manifest is None, "cap:op=test lacks in/out, parse must fail"

    # VALID_MANIFEST has proper in/out specs
    runtime_valid = PluginRuntime.with_manifest_json(VALID_MANIFEST)
    assert len(runtime_valid.manifest_data) > 0
    assert runtime_valid.manifest is not None, "VALID_MANIFEST must parse into CapManifest"


# TEST257: Test PluginRuntime::new with invalid JSON still creates runtime (manifest is None)
def test_new_with_invalid_json():
    runtime = PluginRuntime(b"not json")
    assert len(runtime.manifest_data) > 0
    assert runtime.manifest is None, "invalid JSON should leave manifest as None"


# TEST258: Test PluginRuntime::with_manifest creates runtime with valid manifest data
def test_with_manifest_struct():
    manifest_dict = json.loads(VALID_MANIFEST)
    manifest = CapManifest.from_dict(manifest_dict)
    runtime = PluginRuntime.with_manifest(manifest)
    assert len(runtime.manifest_data) > 0
    assert runtime.manifest is not None


# TEST259: Test extract_effective_payload with single stream matching cap in_spec
def test_extract_effective_payload_non_cbor():
    # Single stream with data matching the cap's input spec
    streams = [
        ("stream-0", PendingStream(media_urn="media:bytes", chunks=[b"raw data"], complete=True))
    ]
    result = extract_effective_payload(streams, "cap:in=media:bytes;op=test;out=*")
    assert result == b"raw data", "Should extract matching stream"


# TEST260: Test extract_effective_payload with wildcard in_spec accepts any stream
def test_extract_effective_payload_no_content_type():
    streams = [
        ("stream-0", PendingStream(media_urn="media:bytes", chunks=[b"raw data"], complete=True))
    ]
    result = extract_effective_payload(streams, "cap:in=*;op=test;out=*")
    assert result == b"raw data", "Wildcard should accept any stream"


# TEST261: Test extract_effective_payload extracts matching stream by media URN
def test_extract_effective_payload_cbor_match():
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
def test_extract_effective_payload_cbor_no_match():
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
def test_extract_effective_payload_invalid_cbor():
    # No streams provided
    streams = []
    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            streams,
            "cap:in=media:bytes;op=test;out=*"
        )
    assert "No stream found matching" in str(exc_info.value)


# TEST264: Test extract_effective_payload with incomplete stream skips it
def test_extract_effective_payload_cbor_not_array():
    # Stream that's not complete
    streams = [
        ("stream-0", PendingStream(media_urn="media:bytes", chunks=[b"data"], complete=False))
    ]

    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            streams,
            "cap:in=media:bytes;op=test;out=*"
        )

    assert "No stream found matching" in str(exc_info.value)


# TEST265: Test extract_effective_payload with invalid cap URN returns CapUrn error
def test_extract_effective_payload_invalid_cap_urn():
    streams = []

    with pytest.raises(CapUrnError):
        extract_effective_payload(
            streams,
            "not-a-cap-urn"
        )


# TEST266: Test CliStreamEmitter writes to stdout and stderr correctly (basic construction)
def test_cli_stream_emitter_construction():
    emitter = CliStreamEmitter()
    assert emitter.ndjson, "default CLI emitter must use NDJSON"

    emitter2 = CliStreamEmitter.without_ndjson()
    assert not emitter2.ndjson


# TEST267: Test CliStreamEmitter::default creates NDJSON emitter
def test_cli_stream_emitter_default():
    emitter = CliStreamEmitter()
    assert emitter.ndjson


# TEST268: Test RuntimeError variants display correct messages
def test_runtime_error_display():
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


# TEST269: Test PluginRuntime limits returns default protocol limits
def test_runtime_limits_default():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))
    limits = runtime.get_limits()
    assert limits.max_frame == DEFAULT_MAX_FRAME
    assert limits.max_chunk == DEFAULT_MAX_CHUNK


# TEST270: Test registering multiple handlers for different caps and finding each independently
def test_multiple_handlers():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    runtime.register_raw("cap:op=alpha", lambda p, e, pr: b"a")
    runtime.register_raw("cap:op=beta", lambda p, e, pr: b"b")
    runtime.register_raw("cap:op=gamma", lambda p, e, pr: b"g")

    no_peer = NoPeerInvoker()
    emitter = CliStreamEmitter()

    h_alpha = runtime.find_handler("cap:op=alpha")
    assert h_alpha(b"", emitter, no_peer) == b"a"

    h_beta = runtime.find_handler("cap:op=beta")
    assert h_beta(b"", emitter, no_peer) == b"b"

    h_gamma = runtime.find_handler("cap:op=gamma")
    assert h_gamma(b"", emitter, no_peer) == b"g"


# TEST271: Test handler replacing an existing registration for the same cap URN
def test_handler_replacement():
    runtime = PluginRuntime(TEST_MANIFEST.encode('utf-8'))

    runtime.register_raw("cap:op=test", lambda p, e, pr: b"first")
    runtime.register_raw("cap:op=test", lambda p, e, pr: b"second")

    handler = runtime.find_handler("cap:op=test")
    assert handler is not None

    no_peer = NoPeerInvoker()
    emitter = CliStreamEmitter()
    result = handler(b"", emitter, no_peer)
    assert result == b"second", "later registration must replace earlier"


# TEST272: Test extract_effective_payload with multiple streams selects the correct one
def test_extract_effective_payload_multiple_args():
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
def test_extract_effective_payload_binary_value():
    binary_data = bytes(range(256))
    streams = [
        ("stream-0", PendingStream(
            media_urn="media:pdf;bytes",
            chunks=[binary_data],
            complete=True
        ))
    ]

    result = extract_effective_payload(
        streams,
        "cap:in=media:pdf;bytes;op=process;out=*"
    )
    assert result == binary_data, "binary values must roundtrip through stream extraction"


# =============================================================================
# File-path to bytes conversion tests (TEST336-TEST360)
# =============================================================================

def create_test_cap(urn_str: str, title: str, command: str, args: list) -> 'Cap':
    """Helper function to create a Cap for tests"""
    from capns.cap_urn import CapUrn
    from capns.cap import Cap
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
    from capns.cap import CapArg, StdinSource, PositionSource
    import threading

    test_file = tmp_path / "test336_input.pdf"
    test_file.write_bytes(b"PDF binary content 336")

    cap = create_test_cap(
        'cap:in="media:pdf;bytes";op=process;out="media:void"',
        "Process PDF",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf;bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Track what handler receives
    received_payload = []

    def handler(payload, emitter, peer):
        received_payload.append(payload)
        return b"processed"

    runtime.register_raw(
        'cap:in="media:pdf;bytes";op=process;out="media:void"',
        handler
    )

    # Simulate CLI invocation: plugin process /path/to/file.pdf
    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Extract effective payload (simulates what run_cli_mode does)
    streams = [
        (f"arg-{i}", PendingStream(media_urn=arg.media_urn, chunks=[arg.value], complete=True))
        for i, arg in enumerate(arguments)
    ]
    payload = extract_effective_payload(streams, cap.urn_string())

    handler_fn = runtime.find_handler(cap.urn_string())
    emitter = CliStreamEmitter()
    peer = NoPeerInvoker()
    result = handler_fn(payload, emitter, peer)

    # Verify handler received file bytes, not file path
    assert received_payload[0] == b"PDF binary content 336", "Handler should receive file bytes"
    assert result == b"processed"


# TEST337: file-path arg without stdin source passes path as string (no conversion)
def test_337_file_path_without_stdin_passes_string(tmp_path):
    from capns.cap import CapArg, PositionSource

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
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Should get file PATH as string, not file CONTENTS
    value_str = result.decode('utf-8')
    assert "test337_input.txt" in value_str, "Should receive file path string when no stdin source"


# TEST338: file-path arg reads file via --file CLI flag
def test_338_file_path_via_cli_flag(tmp_path):
    from capns.cap import CapArg, StdinSource, CliFlagSource

    test_file = tmp_path / "test338.pdf"
    test_file.write_bytes(b"PDF via flag 338")

    cap = create_test_cap(
        'cap:in="media:pdf;bytes";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf;bytes"),
                CliFlagSource("--file"),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["--file", str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"PDF via flag 338", "Should read file from --file flag"


# TEST339: file-path-array reads multiple files with glob pattern
def test_339_file_path_array_glob_expansion(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test339"
    test_dir.mkdir()

    file1 = test_dir / "doc1.txt"
    file2 = test_dir / "doc2.txt"
    file1.write_bytes(b"content1")
    file2.write_bytes(b"content2")

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Batch",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 2, "Should find 2 files"

    # Verify contents (order may vary, so sort)
    bytes_vec = sorted(files_array)
    assert bytes_vec == [b"content1", b"content2"]


# TEST340: File not found error provides clear message
def test_340_file_not_found_clear_error():
    from capns.cap import CapArg, StdinSource, PositionSource
    from capns.plugin_runtime import IoRuntimeError

    cap = create_test_cap(
        'cap:in="media:pdf;bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf;bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["/nonexistent/file.pdf"]
    cap = runtime.manifest.caps[0]

    with pytest.raises(IoRuntimeError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err_msg = str(exc_info.value)
    assert "/nonexistent/file.pdf" in err_msg, "Error should mention file path"
    assert "Failed to read file" in err_msg, "Error should be clear"


# TEST341: stdin takes precedence over file-path in source order
def test_341_stdin_precedence_over_file_path(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test341_input.txt"
    test_file.write_bytes(b"file content")

    # Stdin source comes BEFORE position source
    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),  # First
                PositionSource(0),            # Second
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    stdin_data = b"stdin content 341"
    cap = runtime.manifest.caps[0]

    result = runtime._extract_arg_value(cap.args[0], cli_args, stdin_data)

    # Should get stdin data, not file content (stdin source tried first)
    assert result == b"stdin content 341", "stdin source should take precedence"


# TEST342: file-path with position 0 reads first positional arg as file
def test_342_file_path_position_zero_reads_first_arg(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test342.dat"
    test_file.write_bytes(b"binary data 342")

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # CLI: plugin test /path/to/file (position 0 after subcommand)
    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"binary data 342", "Should read file at position 0"


# TEST343: Non-file-path args are not affected by file reading
def test_343_non_file_path_args_unaffected():
    from capns.cap import CapArg, StdinSource, PositionSource

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
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Should get the string value, not attempt file read
    value_str = result.decode('utf-8')
    assert value_str == "mlx-community/Llama-3.2-3B-Instruct-4bit"


# TEST344: file-path-array with invalid JSON fails clearly
def test_344_file_path_array_invalid_json_fails():
    from capns.cap import CapArg, StdinSource, PositionSource
    from capns.plugin_runtime import CliError

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Pass invalid JSON (not an array)
    cli_args = ["not a json array"]
    cap = runtime.manifest.caps[0]

    with pytest.raises(CliError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "Failed to parse file-path-array" in err, "Error should mention file-path-array"
    assert "expected JSON array" in err, "Error should explain expected format"


# TEST345: file-path-array with one file failing stops and reports error
def test_345_file_path_array_one_file_missing_fails_hard(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource
    from capns.plugin_runtime import IoRuntimeError

    file1 = tmp_path / "test345_exists.txt"
    file1.write_bytes(b"exists")
    file2_path = tmp_path / "test345_missing.txt"

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]

    with pytest.raises(IoRuntimeError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "test345_missing.txt" in err, "Error should mention the missing file"
    assert "Failed to read file" in err, "Error should be clear about read failure"


# TEST346: Large file (1MB) reads successfully
def test_346_large_file_reads_successfully(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test346_large.bin"

    # Create 1MB file
    large_data = bytes([42] * 1_000_000)
    test_file.write_bytes(large_data)

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert len(result) == 1_000_000, "Should read entire 1MB file"
    assert result == large_data, "Content should match exactly"


# TEST347: Empty file reads as empty bytes
def test_347_empty_file_reads_as_empty_bytes(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test347_empty.txt"
    test_file.write_bytes(b"")

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"", "Empty file should produce empty bytes"


# TEST348: file-path conversion respects source order
def test_348_file_path_conversion_respects_source_order(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test348.txt"
    test_file.write_bytes(b"file content 348")

    # Position source BEFORE stdin source
    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                PositionSource(0),            # First
                StdinSource("media:bytes"),  # Second
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    stdin_data = b"stdin content 348"
    cap = runtime.manifest.caps[0]

    result = runtime._extract_arg_value(cap.args[0], cli_args, stdin_data)

    # Position source tried first, so file is read
    assert result == b"file content 348", "Position source tried first, file read"


# TEST349: file-path arg with multiple sources tries all in order
def test_349_file_path_multiple_sources_fallback(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource, CliFlagSource

    test_file = tmp_path / "test349.txt"
    test_file.write_bytes(b"content 349")

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                CliFlagSource("--file"),     # First (not provided)
                PositionSource(0),            # Second (provided)
                StdinSource("media:bytes"),  # Third (not used)
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Only provide position arg, no --file flag
    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"content 349", "Should fall back to position source and read file"


# TEST350: Integration test - full CLI mode invocation with file-path
def test_350_full_cli_mode_with_file_path_integration(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test350_input.pdf"
    test_content = b"PDF file content for integration test"
    test_file.write_bytes(test_content)

    cap = create_test_cap(
        'cap:in="media:pdf;bytes";op=process;out="media:result;textable"',
        "Process PDF",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf;bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    # Track what the handler receives
    received_payload = []

    def handler(payload, emitter, peer):
        received_payload.append(payload)
        return b"processed"

    runtime.register_raw(
        'cap:in="media:pdf;bytes";op=process;out="media:result;textable"',
        handler
    )

    # Simulate full CLI invocation
    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Extract effective payload (what run_cli_mode does)
    streams = [
        (f"arg-{i}", PendingStream(media_urn=arg.media_urn, chunks=[arg.value], complete=True))
        for i, arg in enumerate(arguments)
    ]
    payload = extract_effective_payload(streams, cap.urn_string())

    handler_fn = runtime.find_handler(cap.urn_string())
    emitter = CliStreamEmitter()
    peer = NoPeerInvoker()
    result = handler_fn(payload, emitter, peer)

    # Verify handler received file bytes
    assert received_payload[0] == test_content, "Handler should receive file bytes, not path"
    assert result == b"processed"


# TEST351: file-path-array with empty array succeeds
def test_351_file_path_array_empty_array():
    from capns.cap import CapArg, StdinSource, PositionSource

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=False,  # Not required
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = ["[]"]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 0, "Empty array should produce empty result"


# TEST352: file permission denied error is clear (Unix-specific)
@pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions only")
def test_352_file_permission_denied_clear_error(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource
    from capns.plugin_runtime import IoRuntimeError
    import os

    test_file = tmp_path / "test352_noperm.txt"
    test_file.write_bytes(b"content")

    # Remove read permissions
    os.chmod(test_file, 0o000)

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]

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
    from capns.cap import CapArg, StdinSource, PositionSource

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
    cap = runtime.manifest.caps[0]
    arguments = runtime.build_arguments_from_cli(cap, cli_args)

    # Verify structure of CapArgumentValue list
    assert len(arguments) == 1, "Should have 1 argument"

    # Check the CapArgumentValue object
    arg = arguments[0]
    assert arg.media_urn == "media:text;textable;form=scalar"
    assert arg.value == b"test value"


# TEST354: Glob pattern with no matches produces empty array
def test_354_glob_pattern_no_matches_empty_array(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    assert len(files_array) == 0, "No matches should produce empty array"


# TEST355: Glob pattern skips directories
def test_355_glob_pattern_skips_directories(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test355"
    test_dir.mkdir()

    subdir = test_dir / "subdir"
    subdir.mkdir()

    file1 = test_dir / "file1.txt"
    file1.write_bytes(b"content1")

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    # Decode CBOR array
    files_array = cbor2.loads(result)

    # Should only include the file, not the directory
    assert len(files_array) == 1, "Should only include files, not directories"
    assert files_array[0] == b"content1"


# TEST356: Multiple glob patterns combined
def test_356_multiple_glob_patterns_combined(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_dir = tmp_path / "test356"
    test_dir.mkdir()

    file1 = test_dir / "doc.txt"
    file2 = test_dir / "data.json"
    file1.write_bytes(b"text")
    file2.write_bytes(b"json")

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]
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
    from capns.cap import CapArg, StdinSource, PositionSource
    import os

    test_dir = tmp_path / "test357"
    test_dir.mkdir()

    real_file = test_dir / "real.txt"
    link_file = test_dir / "link.txt"
    real_file.write_bytes(b"real content")
    os.symlink(real_file, link_file)

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(link_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == b"real content", "Should follow symlink and read real file"


# TEST358: Binary file with non-UTF8 data reads correctly
def test_358_binary_file_non_utf8(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test358.bin"

    # Binary data that's not valid UTF-8
    binary_data = bytes([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x7F, 0xAB, 0xCD])
    test_file.write_bytes(binary_data)

    cap = create_test_cap(
        'cap:in="media:bytes";op=test;out="media:void"',
        "Test",
        "test",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]
    result = runtime._extract_arg_value(cap.args[0], cli_args, None)

    assert result == binary_data, "Binary data should read correctly"


# TEST359: Invalid glob pattern fails with clear error
def test_359_invalid_glob_pattern_fails():
    from capns.cap import CapArg, StdinSource, PositionSource
    from capns.plugin_runtime import CliError

    cap = create_test_cap(
        'cap:in="media:bytes";op=batch;out="media:void"',
        "Test",
        "batch",
        [CapArg(
            media_urn="media:file-path;textable;form=list",
            required=True,
            sources=[
                StdinSource("media:bytes"),
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
    cap = runtime.manifest.caps[0]

    with pytest.raises(CliError) as exc_info:
        runtime._extract_arg_value(cap.args[0], cli_args, None)

    err = str(exc_info.value)
    assert "Invalid glob pattern" in err, "Error should mention invalid glob"


# TEST360: Extract effective payload handles file-path data correctly
def test_360_extract_effective_payload_with_file_data(tmp_path):
    from capns.cap import CapArg, StdinSource, PositionSource

    test_file = tmp_path / "test360.pdf"
    pdf_content = b"PDF content for extraction test"
    test_file.write_bytes(pdf_content)

    cap = create_test_cap(
        'cap:in="media:pdf;bytes";op=process;out="media:void"',
        "Process",
        "process",
        [CapArg(
            media_urn="media:file-path;textable;form=scalar",
            required=True,
            sources=[
                StdinSource("media:pdf;bytes"),
                PositionSource(0),
            ]
        )]
    )

    manifest = create_test_manifest("TestPlugin", "1.0.0", "Test", [cap])
    runtime = PluginRuntime.with_manifest(manifest)

    cli_args = [str(test_file)]
    cap = runtime.manifest.caps[0]

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
