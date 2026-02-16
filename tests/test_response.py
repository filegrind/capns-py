"""Tests for ResponseWrapper - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import json
from dataclasses import dataclass
from capns.cap.response import ResponseWrapper


@dataclass
class SampleStruct:
    """Sample structure for JSON deserialization testing"""
    name: str
    value: int


# TEST168: Test ResponseWrapper from JSON deserializes to correct structured type
def test_json_response():
    test_data = SampleStruct(name="test", value=42)
    json_str = json.dumps({"name": "test", "value": 42})
    response = ResponseWrapper.from_json(json_str.encode('utf-8'))

    parsed = response.as_type(SampleStruct)
    assert parsed.name == test_data.name
    assert parsed.value == test_data.value


# TEST169: Test ResponseWrapper converts to primitive types integer, float, boolean, string
def test_primitive_types():
    # Test integer
    response = ResponseWrapper.from_text(b"42")
    assert response.as_int() == 42

    # Test float
    response = ResponseWrapper.from_text(b"3.14")
    assert response.as_float() == 3.14

    # Test boolean
    response = ResponseWrapper.from_text(b"true")
    assert response.as_bool() is True

    # Test string
    response = ResponseWrapper.from_text(b"hello world")
    assert response.as_string() == "hello world"


# TEST170: Test ResponseWrapper from binary stores and retrieves raw bytes correctly
def test_binary_response():
    binary_data = bytes([0x89, 0x50, 0x4E, 0x47])  # PNG header
    response = ResponseWrapper.from_binary(binary_data)

    retrieved = response.as_bytes()
    assert retrieved == binary_data
    assert len(retrieved) == 4
    assert retrieved[0] == 0x89
