"""Tests for schema_validation - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import json
from capns import CapUrn, Cap, CapArg, CapOutput
from capns.cap import PositionSource, MediaSpecDef
from capns.schema_validation import (
    SchemaValidator,
    ArgumentValidationError,
    OutputValidationError,
    SchemaCompilationError,
)
from capns.media_urn import MEDIA_STRING, MEDIA_VOID, MEDIA_OBJECT


def _test_urn(tags: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags}'


# TEST163: Test argument schema validation succeeds with valid JSON matching schema
def test_argument_schema_validation_success():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer", "minimum": 0}
        },
        "required": ["name"]
    }

    # Create cap with media_specs containing the schema
    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:user-data",
        media_type="application/json",
        title="User Data",
        profile_uri="https://example.com/schema/user-data",
        schema=schema,
    ))

    arg = CapArg("media:user-data", True, [PositionSource(0)])

    valid_value = {"name": "John", "age": 30}
    # Should succeed without raising
    validator.validate_argument(cap, arg, valid_value)


# TEST164: Test argument schema validation fails with JSON missing required fields
def test_argument_schema_validation_failure():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"}
        },
        "required": ["name"]
    }

    # Create cap with media_specs containing the schema
    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:user-data",
        media_type="application/json",
        title="User Data",
        profile_uri="https://example.com/schema/user-data",
        schema=schema,
    ))

    arg = CapArg("media:user-data", True, [PositionSource(0)])

    invalid_value = {"age": 30}  # Missing required "name"

    with pytest.raises(ArgumentValidationError) as exc_info:
        validator.validate_argument(cap, arg, invalid_value)

    assert "name" in exc_info.value.details.lower() or "required" in exc_info.value.details.lower()


# TEST165: Test output schema validation succeeds with valid JSON matching schema
def test_output_schema_validation_success():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "result": {"type": "string"},
            "timestamp": {"type": "string", "format": "date-time"}
        },
        "required": ["result"]
    }

    # Create cap with media_specs containing the schema
    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:query-result",
        media_type="application/json",
        title="Query Result",
        profile_uri="https://example.com/schema/query-result",
        schema=schema,
    ))

    output = CapOutput("media:query-result", "Query result")

    valid_value = {"result": "success", "timestamp": "2023-01-01T00:00:00Z"}
    # Should succeed without raising
    validator.validate_output(cap, output, valid_value)


# TEST166: Test validation skipped when resolved media spec has no schema
def test_skip_validation_without_schema():
    validator = SchemaValidator()

    # Create cap without media_specs
    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")

    # Argument using media URN with no schema in media_specs
    arg = CapArg(MEDIA_STRING, True, [PositionSource(0)])

    value = "any string value"
    # Should succeed - no schema means validation is skipped
    validator.validate_argument(cap, arg, value)


# TEST167: Test validation with unresolved media URN skips validation gracefully
def test_unresolved_media_urn_skips_validation():
    validator = SchemaValidator()

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")

    # Argument with unknown media URN - not in media_specs
    arg = CapArg("media:completely-unknown-urn", True, [PositionSource(0)])

    value = "test"
    # Should succeed - no schema found means validation is skipped
    validator.validate_argument(cap, arg, value)


# Additional comprehensive schema validation tests


# TEST: Schema validation with nested object schemas
def test_nested_object_schema_validation():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string", "format": "email"}
                },
                "required": ["name", "email"]
            },
            "timestamp": {"type": "integer"}
        },
        "required": ["user"]
    }

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:user-event",
        media_type="application/json",
        title="User Event",
        schema=schema,
    ))

    arg = CapArg("media:user-event", True, [PositionSource(0)])

    # Valid nested object
    valid_value = {
        "user": {
            "name": "Alice",
            "email": "alice@example.com"
        },
        "timestamp": 1234567890
    }
    validator.validate_argument(cap, arg, valid_value)

    # Invalid nested object (missing email)
    invalid_value = {
        "user": {
            "name": "Alice"
        },
        "timestamp": 1234567890
    }

    with pytest.raises(ArgumentValidationError):
        validator.validate_argument(cap, arg, invalid_value)


# TEST: Schema validation with array schemas
def test_array_schema_validation():
    validator = SchemaValidator()

    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "required": ["id"]
        },
        "minItems": 1
    }

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:item-list",
        media_type="application/json",
        title="Item List",
        schema=schema,
    ))

    arg = CapArg("media:item-list", True, [PositionSource(0)])

    # Valid array
    valid_value = [
        {"id": 1, "name": "Item 1"},
        {"id": 2, "name": "Item 2"}
    ]
    validator.validate_argument(cap, arg, valid_value)

    # Invalid array (empty - violates minItems)
    with pytest.raises(ArgumentValidationError):
        validator.validate_argument(cap, arg, [])

    # Invalid array (item missing required id)
    with pytest.raises(ArgumentValidationError):
        validator.validate_argument(cap, arg, [{"name": "Item 1"}])


# TEST: Schema validation with type constraints
def test_type_constraint_validation():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "price": {"type": "number"},
            "active": {"type": "boolean"}
        },
        "required": ["count"]
    }

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:product",
        media_type="application/json",
        title="Product",
        schema=schema,
    ))

    arg = CapArg("media:product", True, [PositionSource(0)])

    # Valid types
    valid_value = {"count": 5, "price": 9.99, "active": True}
    validator.validate_argument(cap, arg, valid_value)

    # Invalid type (count is string instead of integer)
    invalid_value = {"count": "five"}
    with pytest.raises(ArgumentValidationError):
        validator.validate_argument(cap, arg, invalid_value)


# TEST: Schema validation with multiple arguments
def test_validate_multiple_arguments():
    validator = SchemaValidator()

    schema1 = {
        "type": "string",
        "minLength": 1
    }

    schema2 = {
        "type": "integer",
        "minimum": 0,
        "maximum": 100
    }

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:name",
        media_type="text/plain",
        title="Name",
        schema=schema1,
    ))
    cap.add_media_spec(MediaSpecDef(
        urn="media:score",
        media_type="application/json",
        title="Score",
        schema=schema2,
    ))

    # Add arguments
    arg1 = CapArg("media:name", True, [PositionSource(0)])
    arg2 = CapArg("media:score", True, [PositionSource(1)])
    cap.add_arg(arg1)
    cap.add_arg(arg2)

    # Valid arguments
    arguments = ["John", 85]
    validator.validate_arguments(cap, arguments)

    # Invalid first argument
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(cap, ["", 85])  # Empty string

    # Invalid second argument
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(cap, ["John", 150])  # Exceeds maximum


# TEST: Output validation with error details
def test_output_validation_with_details():
    validator = SchemaValidator()

    schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["success", "failure"]},
            "data": {"type": "object"}
        },
        "required": ["status"]
    }

    urn = CapUrn.from_string(_test_urn("type=test;op=validate"))
    cap = Cap(urn, "Test", "test")
    cap.add_media_spec(MediaSpecDef(
        urn="media:response",
        media_type="application/json",
        title="Response",
        schema=schema,
    ))

    output = CapOutput("media:response", "Response")

    # Invalid output (wrong enum value)
    invalid_value = {"status": "pending"}

    with pytest.raises(OutputValidationError) as exc_info:
        validator.validate_output(cap, output, invalid_value)

    # Error should contain validation details
    assert exc_info.value.details
