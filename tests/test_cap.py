"""Tests for Cap - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import json
from capns import CapUrn
from capns.cap import Cap, CapArg, CapOutput, StdinSource, PositionSource, CliFlagSource
from capns.media_urn import MEDIA_STRING, MEDIA_INTEGER, MEDIA_VOID, MEDIA_OBJECT


def _test_urn(tags: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags}'


# TEST108: Test Cap creation with URN, title, and command
def test_cap_creation():
    urn = CapUrn.from_string(_test_urn("op=extract;target=metadata"))
    cap = Cap(urn, "Extract Metadata", "extract-metadata")

    assert cap.urn == urn
    assert cap.title == "Extract Metadata"
    assert cap.command == "extract-metadata"
    assert cap.urn_string() == urn.to_string()


# TEST109: Test Cap with args stores and retrieves arguments correctly
def test_cap_with_args():
    urn = CapUrn.from_string(_test_urn("op=process"))
    cap = Cap(urn, "Process Data", "process-data")

    # Add positional argument
    arg = CapArg(
        media_urn=MEDIA_STRING,
        required=True,
        sources=[PositionSource(0)],
    )
    cap.add_arg(arg)

    args = cap.get_args()
    assert len(args) == 1
    assert args[0].media_urn == MEDIA_STRING
    assert args[0].required is True


# TEST110: Test Cap with stdin source stores stdin media URN correctly
def test_cap_with_stdin():
    urn = CapUrn.from_string(_test_urn("op=convert"))
    cap = Cap(urn, "Convert", "convert")

    # Add stdin argument
    stdin_arg = CapArg(
        media_urn="media:pdf;bytes",
        required=True,
        sources=[StdinSource("media:pdf;bytes")],
    )
    cap.add_arg(stdin_arg)

    assert cap.get_stdin_media_urn() == "media:pdf;bytes"


# TEST111: Test Cap with no stdin returns None for get_stdin_media_urn
def test_cap_without_stdin():
    urn = CapUrn.from_string(_test_urn("op=process"))
    cap = Cap(urn, "Process", "process")

    # Add non-stdin argument
    arg = CapArg(
        media_urn=MEDIA_STRING,
        required=True,
        sources=[PositionSource(0)],
    )
    cap.add_arg(arg)

    assert cap.get_stdin_media_urn() is None


# TEST112: Test Cap with output stores output definition correctly
def test_cap_with_output():
    urn = CapUrn.from_string(_test_urn("op=generate"))
    cap = Cap(urn, "Generate", "generate")

    output = CapOutput(
        media_urn=MEDIA_OBJECT,
        output_description="Generated output",
    )
    cap.set_output(output)

    assert cap.output is not None
    assert cap.output.media_urn == MEDIA_OBJECT
    assert cap.output.output_description == "Generated output"


# TEST113: Test Cap with metadata stores and retrieves metadata correctly
def test_cap_with_metadata():
    urn = CapUrn.from_string(_test_urn("op=test"))
    metadata = {"supports_streaming": "true", "version": "2.0"}
    cap = Cap.with_metadata(urn, "Test Cap", "test-cap", metadata)

    assert cap.has_metadata("supports_streaming")
    assert cap.get_metadata("supports_streaming") == "true"
    assert cap.has_metadata("version")
    assert cap.get_metadata("version") == "2.0"
    assert not cap.has_metadata("nonexistent")


# TEST114: Test Cap JSON serialization includes all fields
def test_cap_json_serialization():
    urn = CapUrn.from_string(_test_urn("op=process"))
    cap = Cap(urn, "Process", "process-cmd")
    cap.set_description("A processing capability")

    arg = CapArg(
        media_urn=MEDIA_STRING,
        required=True,
        sources=[PositionSource(0)],
        arg_description="Input file",
    )
    cap.add_arg(arg)

    output = CapOutput(
        media_urn=MEDIA_OBJECT,
        output_description="Processed output",
    )
    cap.set_output(output)

    cap_dict = cap.to_dict()

    assert "urn" in cap_dict
    assert "title" in cap_dict
    assert cap_dict["title"] == "Process"
    assert "command" in cap_dict
    assert cap_dict["command"] == "process-cmd"
    assert "cap_description" in cap_dict
    assert "args" in cap_dict
    assert len(cap_dict["args"]) == 1
    assert "output" in cap_dict


# TEST115: Test Cap JSON deserialization roundtrip preserves all data
def test_cap_json_roundtrip():
    urn = CapUrn.from_string(_test_urn("op=convert"))
    cap = Cap(urn, "Convert", "convert-cmd")

    stdin_arg = CapArg(
        media_urn="media:pdf;bytes",
        required=True,
        sources=[StdinSource("media:pdf;bytes")],
    )
    cap.add_arg(stdin_arg)

    # Serialize and deserialize
    cap_dict = cap.to_dict()
    json_str = json.dumps(cap_dict)
    parsed_dict = json.loads(json_str)
    restored_cap = Cap.from_dict(parsed_dict)

    assert restored_cap.title == cap.title
    assert restored_cap.command == cap.command
    assert restored_cap.urn_string() == cap.urn_string()
    assert len(restored_cap.get_args()) == len(cap.get_args())
    assert restored_cap.get_stdin_media_urn() == cap.get_stdin_media_urn()


# TEST116: Test CapArg with multiple sources stores all source types
def test_cap_arg_multiple_sources():
    sources = [
        StdinSource("media:bytes"),
        PositionSource(0),
        CliFlagSource("--input"),
    ]

    arg = CapArg(
        media_urn=MEDIA_STRING,
        required=True,
        sources=sources,
    )

    assert len(arg.sources) == 3
    assert isinstance(arg.sources[0], StdinSource)
    assert isinstance(arg.sources[1], PositionSource)
    assert isinstance(arg.sources[2], CliFlagSource)

    # Test serialization
    arg_dict = arg.to_dict()
    assert len(arg_dict["sources"]) == 3
    assert "stdin" in arg_dict["sources"][0]
    assert "position" in arg_dict["sources"][1]
    assert "cli_flag" in arg_dict["sources"][2]
