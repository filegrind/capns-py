"""Tests for plugin_runtime module"""

import pytest
import json
import cbor2
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


# TEST259: Test extract_effective_payload with non-CBOR content_type returns raw payload unchanged
def test_extract_effective_payload_non_cbor():
    payload = b"raw data"
    result = extract_effective_payload(payload, "application/json", "cap:op=test")
    assert result == payload, "non-CBOR must return raw payload"


# TEST260: Test extract_effective_payload with None content_type returns raw payload unchanged
def test_extract_effective_payload_no_content_type():
    payload = b"raw data"
    result = extract_effective_payload(payload, None, "cap:op=test")
    assert result == payload


# TEST261: Test extract_effective_payload with CBOR content extracts matching argument value
def test_extract_effective_payload_cbor_match():
    # Build CBOR arguments: [{media_urn: "media:string;textable;form=scalar", value: bytes("hello")}]
    args = [
        {
            "media_urn": "media:string;textable;form=scalar",
            "value": b"hello"
        }
    ]
    payload = cbor2.dumps(args)

    # The cap URN has in=media:string;textable;form=scalar
    result = extract_effective_payload(
        payload,
        "application/cbor",
        "cap:in=media:string;textable;form=scalar;op=test;out=*"
    )
    assert result == b"hello"


# TEST262: Test extract_effective_payload with CBOR content fails when no argument matches expected input
def test_extract_effective_payload_cbor_no_match():
    args = [
        {
            "media_urn": "media:other-type",
            "value": b"data"
        }
    ]
    payload = cbor2.dumps(args)

    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            payload,
            "application/cbor",
            "cap:in=media:string;textable;form=scalar;op=test;out=*"
        )

    assert "No argument found matching" in str(exc_info.value)


# TEST263: Test extract_effective_payload with invalid CBOR bytes returns deserialization error
def test_extract_effective_payload_invalid_cbor():
    with pytest.raises(DeserializeError):
        extract_effective_payload(
            b"not cbor",
            "application/cbor",
            "cap:in=*;op=test;out=*"
        )


# TEST264: Test extract_effective_payload with CBOR non-array (e.g. map) returns error
def test_extract_effective_payload_cbor_not_array():
    value = {}
    payload = cbor2.dumps(value)

    with pytest.raises(DeserializeError) as exc_info:
        extract_effective_payload(
            payload,
            "application/cbor",
            "cap:in=*;op=test;out=*"
        )

    assert "must be an array" in str(exc_info.value)


# TEST265: Test extract_effective_payload with invalid cap URN returns CapUrn error
def test_extract_effective_payload_invalid_cap_urn():
    args = []
    payload = cbor2.dumps(args)

    with pytest.raises(CapUrnError):
        extract_effective_payload(
            payload,
            "application/cbor",
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


# TEST272: Test extract_effective_payload CBOR with multiple arguments selects the correct one
def test_extract_effective_payload_multiple_args():
    args = [
        {
            "media_urn": "media:other-type;textable",
            "value": b"wrong"
        },
        {
            "media_urn": "media:model-spec;textable;form=scalar",
            "value": b"correct"
        }
    ]
    payload = cbor2.dumps(args)

    result = extract_effective_payload(
        payload,
        "application/cbor",
        "cap:in=media:model-spec;textable;form=scalar;op=infer;out=*"
    )
    assert result == b"correct"


# TEST273: Test extract_effective_payload with binary data in CBOR value (not just text)
def test_extract_effective_payload_binary_value():
    binary_data = bytes(range(256))
    args = [
        {
            "media_urn": "media:pdf;bytes",
            "value": binary_data
        }
    ]
    payload = cbor2.dumps(args)

    result = extract_effective_payload(
        payload,
        "application/cbor",
        "cap:in=media:pdf;bytes;op=process;out=*"
    )
    assert result == binary_data, "binary values must roundtrip through CBOR extraction"
