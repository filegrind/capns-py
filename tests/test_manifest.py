"""Tests for CapManifest - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import json
from capns import CapUrn
from capns.cap.definition import Cap, CapArg, StdinSource
from capns.bifaci.manifest import CapManifest
from capns.urn.media_urn import MEDIA_VOID, MEDIA_OBJECT


def _test_urn(tags: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags}'


# TEST148: Test creating cap manifest with name, version, description, and caps
def test_148_cap_manifest_creation():
    urn = CapUrn.from_string(_test_urn("op=extract;target=metadata"))
    cap = Cap(urn, "Extract Metadata", "extract-metadata")

    manifest = CapManifest(
        name="TestComponent",
        version="0.1.0",
        description="A test component for validation",
        caps=[cap],
    )

    assert manifest.name == "TestComponent"
    assert manifest.version == "0.1.0"
    assert manifest.description == "A test component for validation"
    assert len(manifest.caps) == 1
    assert manifest.author is None


# TEST149: Test cap manifest with author field sets author correctly
def test_149_cap_manifest_with_author():
    urn = CapUrn.from_string(_test_urn("op=extract;target=metadata"))
    cap = Cap(urn, "Extract Metadata", "extract-metadata")

    manifest = CapManifest(
        name="TestComponent",
        version="0.1.0",
        description="A test component for validation",
        caps=[cap],
    ).with_author("Test Author")

    assert manifest.author == "Test Author"


# TEST150: Test cap manifest JSON serialization and deserialization roundtrip
def test_150_cap_manifest_json_serialization():
    urn = CapUrn.from_string(_test_urn("op=extract;target=metadata"))
    cap = Cap(urn, "Extract Metadata", "extract-metadata")

    # Add stdin via args architecture
    stdin_arg = CapArg(
        media_urn="media:pdf;bytes",
        required=True,
        sources=[StdinSource("media:pdf;bytes")],
    )
    cap.add_arg(stdin_arg)

    manifest = CapManifest(
        name="TestComponent",
        version="0.1.0",
        description="A test component for validation",
        caps=[cap],
    ).with_author("Test Author")

    # Test serialization
    json_str = manifest.to_json()
    assert '"name":"TestComponent"' in json_str or '"name": "TestComponent"' in json_str
    assert '"version":"0.1.0"' in json_str or '"version": "0.1.0"' in json_str
    assert '"author":"Test Author"' in json_str or '"author": "Test Author"' in json_str
    assert '"stdin":"media:pdf;bytes"' in json_str or '"stdin": "media:pdf;bytes"' in json_str

    # Test deserialization
    deserialized = CapManifest.from_json(json_str)
    assert deserialized.name == manifest.name
    assert deserialized.version == manifest.version
    assert deserialized.description == manifest.description
    assert deserialized.author == manifest.author
    assert len(deserialized.caps) == len(manifest.caps)
    assert deserialized.caps[0].get_stdin_media_urn() == manifest.caps[0].get_stdin_media_urn()


# TEST151: Test cap manifest deserialization fails when required fields are missing
def test_151_cap_manifest_required_fields():
    # Test that deserialization fails when required fields are missing
    invalid_json = '{"name": "TestComponent"}'
    with pytest.raises((KeyError, json.JSONDecodeError, TypeError)):
        CapManifest.from_json(invalid_json)

    invalid_json2 = '{"name": "TestComponent", "version": "1.0.0"}'
    with pytest.raises((KeyError, json.JSONDecodeError, TypeError)):
        CapManifest.from_json(invalid_json2)


# TEST152: Test cap manifest with multiple caps stores and retrieves all capabilities
def test_152_cap_manifest_with_multiple_caps():
    id1 = CapUrn.from_string(_test_urn("op=extract;target=metadata"))
    cap1 = Cap(id1, "Extract Metadata", "extract-metadata")

    id2 = CapUrn.from_string(_test_urn("op=extract;target=outline"))
    metadata = {"supports_outline": "true"}
    cap2 = Cap.with_metadata(id2, "Extract Outline", "extract-outline", metadata)

    manifest = CapManifest(
        name="MultiCapComponent",
        version="1.0.0",
        description="Component with multiple caps",
        caps=[cap1, cap2],
    )

    assert len(manifest.caps) == 2
    # urn_string now includes in/out
    assert "op=extract" in manifest.caps[0].urn_string()
    assert "target=metadata" in manifest.caps[0].urn_string()
    assert "op=extract" in manifest.caps[1].urn_string()
    assert "target=outline" in manifest.caps[1].urn_string()
    assert manifest.caps[1].has_metadata("supports_outline")


# TEST153: Test cap manifest with page_url field sets page URL correctly
def test_153_cap_manifest_with_page_url():
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    manifest = CapManifest(
        name="TestComponent",
        version="1.0.0",
        description="Test component",
        caps=[cap],
    ).with_page_url("https://github.com/example/test")

    assert manifest.page_url == "https://github.com/example/test"


# TEST154: Test cap manifest JSON includes optional fields only when set
def test_154_cap_manifest_optional_fields():
    urn = CapUrn.from_string(_test_urn("op=test"))
    cap = Cap(urn, "Test", "test")

    # Without optional fields
    manifest1 = CapManifest(
        name="TestComponent",
        version="1.0.0",
        description="Test",
        caps=[cap],
    )

    json1 = manifest1.to_json()
    assert '"author"' not in json1
    assert '"page_url"' not in json1

    # With optional fields
    manifest2 = manifest1.with_author("Author").with_page_url("https://example.com")
    json2 = manifest2.to_json()
    assert '"author"' in json2
    assert '"page_url"' in json2


# TEST155: Test cap manifest roundtrip preserves all data including nested cap structures
def test_155_cap_manifest_complex_roundtrip():
    urn = CapUrn.from_string(_test_urn("op=process"))
    cap = Cap(urn, "Process", "process")
    cap.set_description("A processing capability")

    stdin_arg = CapArg(
        media_urn="media:bytes",
        required=True,
        sources=[StdinSource("media:bytes")],
        arg_description="Input data",
    )
    cap.add_arg(stdin_arg)

    manifest = CapManifest(
        name="ComplexComponent",
        version="2.0.0",
        description="Complex test component",
        caps=[cap],
    ).with_author("Test Author").with_page_url("https://example.com")

    # Serialize and deserialize
    json_str = manifest.to_json()
    restored = CapManifest.from_json(json_str)

    assert restored.name == manifest.name
    assert restored.version == manifest.version
    assert restored.description == manifest.description
    assert restored.author == manifest.author
    assert restored.page_url == manifest.page_url
    assert len(restored.caps) == len(manifest.caps)
    assert restored.caps[0].title == manifest.caps[0].title
    assert restored.caps[0].command == manifest.caps[0].command
    assert len(restored.caps[0].get_args()) == len(manifest.caps[0].get_args())
