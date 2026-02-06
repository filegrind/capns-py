"""Tests for validation - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns import CapUrn, Cap, CapArg
from capns.cap import PositionSource, CliFlagSource, StdinSource
from capns.validation import (
    validate_cap_args,
    validate_positional_arguments,
    MissingRequiredArgumentError,
    InvalidCapSchemaError,
    TooManyArgumentsError,
    RESERVED_CLI_FLAGS,
)
from capns.media_urn import MEDIA_STRING, MEDIA_INTEGER, MEDIA_VOID, MEDIA_OBJECT


def _test_urn(tags: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags}'


# TEST051: Test input validation succeeds with valid positional argument
def test_input_validation_success():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    arg = CapArg(MEDIA_STRING, True, [PositionSource(0)])
    cap.add_arg(arg)

    input_args = ["/path/to/file.txt"]

    # Should succeed without raising
    validate_positional_arguments(cap, input_args)


# TEST052: Test input validation fails with MissingRequiredArgument when required arg missing
def test_input_validation_missing_required():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    arg = CapArg(MEDIA_STRING, True, [PositionSource(0)])
    cap.add_arg(arg)

    input_args = []  # Missing required argument

    with pytest.raises(MissingRequiredArgumentError) as exc_info:
        validate_positional_arguments(cap, input_args)

    assert exc_info.value.argument_name == MEDIA_STRING
    assert exc_info.value.cap_urn == cap.urn_string()


# TEST053: Test validation accepts optional argument when not provided
def test_input_validation_optional_arg():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Optional argument (required=False)
    arg = CapArg(MEDIA_STRING, False, [PositionSource(0)])
    cap.add_arg(arg)

    input_args = []  # Not providing optional argument

    # Should succeed - optional arg can be omitted
    validate_positional_arguments(cap, input_args)


# TEST054: Test validation rejects too many arguments with TooManyArguments error
def test_input_validation_too_many_args():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Cap expects 1 argument
    arg = CapArg(MEDIA_STRING, True, [PositionSource(0)])
    cap.add_arg(arg)

    input_args = ["arg1", "arg2", "arg3"]  # Too many

    with pytest.raises(TooManyArgumentsError) as exc_info:
        validate_positional_arguments(cap, input_args)

    assert exc_info.value.max_expected == 1
    assert exc_info.value.actual_count == 3


# TEST055: Test RULE1 - duplicate media_urns rejected
def test_rule1_duplicate_media_urns():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Add two args with same media_urn
    arg1 = CapArg(MEDIA_STRING, True, [PositionSource(0)])
    arg2 = CapArg(MEDIA_STRING, True, [PositionSource(1)])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE1" in exc_info.value.issue
    assert "Duplicate media_urn" in exc_info.value.issue


# TEST056: Test RULE2 - empty sources rejected
def test_rule2_empty_sources():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Create arg with empty sources list
    arg = CapArg(MEDIA_STRING, True, [])
    cap.add_arg(arg)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE2" in exc_info.value.issue
    assert "empty sources" in exc_info.value.issue


# Additional comprehensive validation tests


# TEST: RULE3 - multiple stdin sources must have identical media_urns
def test_rule3_stdin_media_urns_must_match():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Two args with stdin sources but different media_urns
    arg1 = CapArg("media:input1", True, [StdinSource("media:input1")])
    arg2 = CapArg("media:input2", True, [StdinSource("media:input2")])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE3" in exc_info.value.issue


# TEST: RULE4 - no duplicate source types in same arg
def test_rule4_no_duplicate_source_types():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Arg with two position sources
    arg = CapArg(MEDIA_STRING, True, [PositionSource(0), PositionSource(1)])
    cap.add_arg(arg)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE4" in exc_info.value.issue


# TEST: RULE5 - no duplicate positions across args
def test_rule5_no_duplicate_positions():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Two args with same position
    arg1 = CapArg("media:arg1", True, [PositionSource(0)])
    arg2 = CapArg("media:arg2", True, [PositionSource(0)])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE5" in exc_info.value.issue


# TEST: RULE6 - positions must be sequential (no gaps)
def test_rule6_positions_sequential():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Positions 0 and 2 (missing 1)
    arg1 = CapArg("media:arg1", True, [PositionSource(0)])
    arg2 = CapArg("media:arg2", True, [PositionSource(2)])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE6" in exc_info.value.issue
    assert "gap" in exc_info.value.issue.lower()


# TEST: RULE7 - no arg may have both position and cli_flag
def test_rule7_no_position_and_cli_flag():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Arg with both position and cli_flag
    arg = CapArg(MEDIA_STRING, True, [PositionSource(0), CliFlagSource("--input")])
    cap.add_arg(arg)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE7" in exc_info.value.issue


# TEST: RULE9 - no duplicate cli_flags
def test_rule9_no_duplicate_cli_flags():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Two args with same cli_flag
    arg1 = CapArg("media:arg1", True, [CliFlagSource("--input")])
    arg2 = CapArg("media:arg2", True, [CliFlagSource("--input")])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    with pytest.raises(InvalidCapSchemaError) as exc_info:
        validate_cap_args(cap)

    assert "RULE9" in exc_info.value.issue


# TEST: RULE10 - reserved cli_flags rejected
def test_rule10_reserved_cli_flags():
    for reserved_flag in RESERVED_CLI_FLAGS:
        urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
        cap = Cap(urn, "Test Capability", "test-command")

        arg = CapArg(MEDIA_STRING, True, [CliFlagSource(reserved_flag)])
        cap.add_arg(arg)

        with pytest.raises(InvalidCapSchemaError) as exc_info:
            validate_cap_args(cap)

        assert "RULE10" in exc_info.value.issue
        assert reserved_flag in exc_info.value.issue


# TEST: Valid cap with all rules satisfied
def test_valid_cap_passes_all_rules():
    urn = CapUrn.from_string(_test_urn("type=test;op=cap"))
    cap = Cap(urn, "Test Capability", "test-command")

    # Valid args - sequential positions, no duplicates
    arg1 = CapArg("media:arg1", True, [PositionSource(0)])
    arg2 = CapArg("media:arg2", True, [PositionSource(1)])
    arg3 = CapArg("media:arg3", False, [CliFlagSource("--optional")])
    cap.add_arg(arg1)
    cap.add_arg(arg2)
    cap.add_arg(arg3)

    # Should succeed
    validate_cap_args(cap)
