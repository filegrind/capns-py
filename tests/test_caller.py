"""Tests for caller - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns.caller import (
    StdinSourceData,
    StdinSourceFileReference,
    CapArgumentValue,
    CapCaller,
    CapSet,
)
from capns import Cap, CapUrn, CapArg
from capns.cap import PositionSource
from capns.media_urn import MEDIA_STRING, MEDIA_VOID, MEDIA_OBJECT


def _test_urn(tags: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags}'


# ============================================================================
# StdinSource Tests (TEST156-162)
# ============================================================================


# TEST156: Test creating StdinSource Data variant with byte vector
def test_stdin_source_data_creation():
    data = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])  # "Hello"
    source = StdinSourceData(data)

    assert source.data == data
    assert len(source.data) == 5


# TEST157: Test creating StdinSource FileReference variant with all required fields
def test_stdin_source_file_reference_creation():
    tracked_file_id = "tracked-file-123"
    original_path = "/path/to/original.pdf"
    security_bookmark = bytes([0x62, 0x6F, 0x6F, 0x6B])  # "book"
    media_urn = "media:pdf;bytes"

    source = StdinSourceFileReference(
        tracked_file_id=tracked_file_id,
        original_path=original_path,
        security_bookmark=security_bookmark,
        media_urn=media_urn,
    )

    assert source.tracked_file_id == tracked_file_id
    assert source.original_path == original_path
    assert source.security_bookmark == security_bookmark
    assert source.media_urn == media_urn


# TEST158: Test StdinSource Data with empty vector stores and retrieves correctly
def test_stdin_source_data_empty():
    source = StdinSourceData(b"")
    assert source.data == b""
    assert len(source.data) == 0


# TEST159: Test StdinSource Data with binary content like PNG header bytes
def test_stdin_source_data_binary():
    # PNG header bytes
    png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    source = StdinSourceData(png_header)

    assert source.data == png_header
    assert source.data[0] == 0x89
    assert source.data[1] == 0x50  # 'P'


# TEST160: Test StdinSource Data clone creates independent copy with same data
def test_stdin_source_data_clone():
    original_data = bytes([1, 2, 3, 4, 5])
    source1 = StdinSourceData(original_data)

    # Create a copy
    source2 = StdinSourceData(bytes(source1.data))

    # Verify they have the same data
    assert source1.data == source2.data

    # Verify they are independent (modifying one doesn't affect the other)
    # Since bytes are immutable in Python, create new instance
    source2 = StdinSourceData(source2.data + b"\x06")
    assert len(source2.data) == 6
    assert len(source1.data) == 5


# TEST161: Test StdinSource FileReference clone creates independent copy with same fields
def test_stdin_source_file_reference_clone():
    source1 = StdinSourceFileReference(
        tracked_file_id="file-123",
        original_path="/path/to/file.pdf",
        security_bookmark=b"bookmark",
        media_urn="media:pdf;bytes",
    )

    # Create a copy
    import copy
    source2 = copy.deepcopy(source1)

    # Verify they have the same fields
    assert source1.tracked_file_id == source2.tracked_file_id
    assert source1.original_path == source2.original_path
    assert source1.security_bookmark == source2.security_bookmark
    assert source1.media_urn == source2.media_urn


# TEST162: Test StdinSource Debug format displays variant type and relevant fields
def test_stdin_source_debug_format():
    # Data variant
    data_source = StdinSourceData(b"test data")
    data_repr = repr(data_source)
    assert "StdinSource::Data" in data_repr
    assert "9 bytes" in data_repr

    # FileReference variant
    file_source = StdinSourceFileReference(
        tracked_file_id="file-123",
        original_path="/path/file.pdf",
        security_bookmark=b"bookmark",
        media_urn="media:pdf;bytes",
    )
    file_repr = repr(file_source)
    assert "StdinSource::FileReference" in file_repr
    assert "file-123" in file_repr
    assert "/path/file.pdf" in file_repr
    assert "media:pdf;bytes" in file_repr


# ============================================================================
# CapArgumentValue Tests (TEST274-283)
# ============================================================================


# TEST274: Test CapArgumentValue::new stores media_urn and raw byte value
def test_cap_argument_value_new():
    media_urn = "media:model-spec;textable;form=scalar"
    value = b"gpt-4o"

    arg = CapArgumentValue(media_urn, value)

    assert arg.media_urn == media_urn
    assert arg.value == value


# TEST275: Test CapArgumentValue::from_str converts string to UTF-8 bytes
def test_cap_argument_value_from_str():
    media_urn = MEDIA_STRING
    value_str = "Hello, World!"

    arg = CapArgumentValue.from_str(media_urn, value_str)

    assert arg.media_urn == media_urn
    assert arg.value == value_str.encode('utf-8')
    assert arg.value_as_str() == value_str


# TEST276: Test CapArgumentValue::value_as_str succeeds for UTF-8 data
def test_cap_argument_value_as_str_success():
    arg = CapArgumentValue(MEDIA_STRING, "test string".encode('utf-8'))
    assert arg.value_as_str() == "test string"


# TEST277: Test CapArgumentValue::value_as_str fails for non-UTF-8 binary data
def test_cap_argument_value_as_str_fails_binary():
    # Binary data that's not valid UTF-8
    binary_data = bytes([0xFF, 0xFE, 0xFD, 0xFC])
    arg = CapArgumentValue("media:bytes", binary_data)

    with pytest.raises(UnicodeDecodeError):
        arg.value_as_str()


# TEST278: Test CapArgumentValue::new with empty value stores empty vec
def test_cap_argument_value_empty():
    arg = CapArgumentValue(MEDIA_STRING, b"")
    assert arg.value == b""
    assert len(arg.value) == 0
    assert arg.value_as_str() == ""


# TEST279: Test CapArgumentValue Clone produces independent copy with same data
def test_cap_argument_value_clone():
    original = CapArgumentValue.from_str(MEDIA_STRING, "original value")
    cloned = original.clone()

    # Same data
    assert cloned.media_urn == original.media_urn
    assert cloned.value == original.value

    # Independent copies (different objects)
    assert cloned is not original
    # Note: bytes are immutable in Python, so value identity doesn't matter for correctness
    assert cloned.value == original.value


# TEST280: Test CapArgumentValue Debug format includes media_urn and value
def test_cap_argument_value_debug():
    # Text value
    text_arg = CapArgumentValue.from_str(MEDIA_STRING, "test value")
    text_repr = repr(text_arg)
    assert "CapArgumentValue" in text_repr
    assert MEDIA_STRING in text_repr
    assert "test value" in text_repr

    # Binary value
    binary_arg = CapArgumentValue("media:bytes", bytes([0x01, 0x02, 0x03]))
    binary_repr = repr(binary_arg)
    assert "CapArgumentValue" in binary_repr
    assert "media:bytes" in binary_repr
    assert "bytes" in binary_repr


# TEST281: Test CapArgumentValue::new accepts Into<String> for media_urn (String and &str)
def test_cap_argument_value_media_urn_types():
    value = b"test"

    # String
    arg1 = CapArgumentValue("media:string".to_string() if hasattr("", "to_string") else "media:string", value)
    assert arg1.media_urn == "media:string"

    # &str
    arg2 = CapArgumentValue("media:string", value)
    assert arg2.media_urn == "media:string"


# TEST282: Test CapArgumentValue::from_str with Unicode string preserves all characters
def test_cap_argument_value_unicode():
    unicode_str = "Hello 世界 🌍"
    arg = CapArgumentValue.from_str(MEDIA_STRING, unicode_str)

    assert arg.value_as_str() == unicode_str
    # Verify UTF-8 encoding
    assert arg.value == unicode_str.encode('utf-8')


# TEST283: Test CapArgumentValue with large binary payload preserves all bytes
def test_cap_argument_value_large_binary():
    # Create a large binary payload (10KB)
    large_data = bytes(range(256)) * 40  # 10,240 bytes
    arg = CapArgumentValue("media:bytes", large_data)

    assert len(arg.value) == 10240
    assert arg.value == large_data
    # Verify all bytes are preserved
    for i in range(10240):
        assert arg.value[i] == large_data[i]


# ============================================================================
# CapCaller Tests
# ============================================================================


class MockCapSet(CapSet):
    """Mock CapSet for testing"""

    def __init__(self, response_binary=None, response_text=None):
        self.response_binary = response_binary
        self.response_text = response_text
        self.last_cap_urn = None
        self.last_arguments = None

    async def execute_cap(self, cap_urn, arguments):
        self.last_cap_urn = cap_urn
        self.last_arguments = arguments
        return (self.response_binary, self.response_text)


def test_cap_caller_validate_arguments_success():
    """Test CapCaller validates arguments correctly"""
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    # Add required argument
    arg_def = CapArg(MEDIA_STRING, required=True, sources=[PositionSource(0)])
    cap.add_arg(arg_def)

    cap_set = MockCapSet(response_text='{"result": "success"}')
    caller = CapCaller("cap:in=\"media:void\";op=test;out=\"media:form=map;textable\"", cap_set, cap)

    # Valid arguments
    arguments = [CapArgumentValue.from_str(MEDIA_STRING, "test value")]
    caller.validate_arguments(arguments)  # Should not raise


def test_cap_caller_validate_arguments_missing_required():
    """Test CapCaller rejects missing required arguments"""
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    # Add required argument
    arg_def = CapArg(MEDIA_STRING, required=True, sources=[PositionSource(0)])
    cap.add_arg(arg_def)

    cap_set = MockCapSet()
    caller = CapCaller("cap:in=\"media:void\";op=test;out=\"media:form=map;textable\"", cap_set, cap)

    # Missing required argument
    with pytest.raises(ValueError, match="Missing required argument"):
        caller.validate_arguments([])


def test_cap_caller_validate_arguments_unknown():
    """Test CapCaller rejects unknown arguments"""
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    # Add one known argument
    arg_def = CapArg(MEDIA_STRING, required=False, sources=[PositionSource(0)])
    cap.add_arg(arg_def)

    cap_set = MockCapSet()
    caller = CapCaller("cap:in=\"media:void\";op=test;out=\"media:form=map;textable\"", cap_set, cap)

    # Unknown argument
    unknown_arg = CapArgumentValue.from_str("media:unknown", "value")
    with pytest.raises(ValueError, match="Unknown argument"):
        caller.validate_arguments([unknown_arg])


def test_cap_caller_get_positional_arg_positions():
    """Test CapCaller returns correct positional argument positions"""
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    # Add positional arguments
    arg1 = CapArg("media:arg1", required=True, sources=[PositionSource(0)])
    arg2 = CapArg("media:arg2", required=True, sources=[PositionSource(1)])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    cap_set = MockCapSet()
    caller = CapCaller("cap:in=\"media:void\";op=test;out=\"media:form=map;textable\"", cap_set, cap)

    positions = caller.get_positional_arg_positions()
    assert positions == {
        "media:arg1": 0,
        "media:arg2": 1,
    }
