"""Tests for media_spec module

Full test coverage matching Rust reference implementation.
Tests media URN resolution, media spec definitions, and validation.
"""

import pytest
import tempfile
from pathlib import Path

from capns.media.spec import (
    MediaValidation,
    MediaSpecDef,
    ResolvedMediaSpec,
    resolve_media_urn,
    validate_media_specs_no_duplicates,
    MediaSpecError,
    UnresolvableMediaUrn,
    DuplicateMediaUrn,
)
from capns.media.registry import MediaUrnRegistry


# Helper to create a test registry
async def create_test_registry():
    """Create a registry for testing"""
    temp_dir = Path(tempfile.mkdtemp())
    cache_dir = temp_dir / "media"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return MediaUrnRegistry.new_for_test(cache_dir)


# Helper to create media specs vec for tests
def create_media_specs(specs):
    """Create media specs list"""
    return specs


# =============================================================================
# Media URN resolution tests
# =============================================================================


# TEST088: Test resolving string media URN from registry returns correct media type and profile
@pytest.mark.asyncio
async def test_088_resolve_from_registry_str():
    registry = await create_test_registry()
    resolved = await resolve_media_urn("media:textable", None, registry)
    assert resolved.media_type == "text/plain"
    # Registry provides the full spec including profile
    assert resolved.profile_uri is not None


# TEST089: Test resolving object media URN from registry returns JSON media type
@pytest.mark.asyncio
async def test_089_resolve_from_registry_obj():
    registry = await create_test_registry()
    resolved = await resolve_media_urn("media:record;textable", None, registry)
    assert resolved.media_type == "application/json"


# TEST090: Test resolving wildcard media URN returns octet-stream and is_binary true
@pytest.mark.asyncio
async def test_090_resolve_from_registry_binary():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:",
            media_type="application/octet-stream",
            title="Bytes",
            profile_uri="https://capns.org/schema/bytes",
            schema=None,
            description="Raw byte sequence.",
            validation=None,
            metadata=None,
            extensions=[],
        )
    ])
    resolved = await resolve_media_urn("media:", media_specs, registry)
    assert resolved.media_type == "application/octet-stream"
    assert resolved.is_binary()


# TEST091: Test resolving custom media URN from local media_specs takes precedence over registry
@pytest.mark.asyncio
async def test_091_resolve_custom_media_spec():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:custom-spec;json",
            media_type="application/json",
            title="Custom Spec",
            profile_uri="https://example.com/schema",
            schema=None,
            description=None,
            validation=None,
            metadata=None,
            extensions=[],
        )
    ])

    # Local media_specs takes precedence over registry
    resolved = await resolve_media_urn("media:custom-spec;json", media_specs, registry)
    assert resolved.media_urn == "media:custom-spec;json"
    assert resolved.media_type == "application/json"
    assert resolved.profile_uri == "https://example.com/schema"
    assert resolved.schema is None


# TEST092: Test resolving custom object form media spec with schema from local media_specs
@pytest.mark.asyncio
async def test_092_resolve_custom_with_schema():
    registry = await create_test_registry()
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"}
        }
    }
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:output-spec;json;record",
            media_type="application/json",
            title="Output Spec",
            profile_uri="https://example.com/schema/output",
            schema=schema,
            description=None,
            validation=None,
            metadata=None,
            extensions=[],
        )
    ])

    resolved = await resolve_media_urn("media:output-spec;json;record", media_specs, registry)
    assert resolved.media_urn == "media:output-spec;json;record"
    assert resolved.media_type == "application/json"
    assert resolved.profile_uri == "https://example.com/schema/output"
    assert resolved.schema == schema


# TEST093: Test resolving unknown media URN fails with UnresolvableMediaUrn error
@pytest.mark.asyncio
async def test_093_resolve_unresolvable_fails_hard():
    registry = await create_test_registry()
    # URN not in local media_specs and not in registry
    with pytest.raises(UnresolvableMediaUrn) as exc_info:
        await resolve_media_urn("media:completely-unknown-urn-not-in-registry", None, registry)
    assert "media:completely-unknown-urn-not-in-registry" in str(exc_info.value)


# TEST094: Test local media_specs definition overrides registry definition for same URN
@pytest.mark.asyncio
async def test_094_local_overrides_registry():
    registry = await create_test_registry()
    # Custom definition in media_specs takes precedence over registry
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:textable",
            media_type="application/json",  # Override: normally text/plain
            title="Custom String",
            profile_uri="https://custom.example.com/str",
            schema=None,
            description=None,
            validation=None,
            metadata=None,
            extensions=[],
        )
    ])

    resolved = await resolve_media_urn("media:textable", media_specs, registry)
    # Custom definition used, not registry
    assert resolved.media_type == "application/json"
    assert resolved.profile_uri == "https://custom.example.com/str"


# =============================================================================
# MediaSpecDef serialization tests
# =============================================================================


# TEST095: Test MediaSpecDef serializes with required fields and skips None fields
def test_095_media_spec_def_serialize():
    spec_def = MediaSpecDef(
        urn="media:test;json",
        media_type="application/json",
        title="Test Media",
        profile_uri="https://example.com/profile",
        schema=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    data = spec_def.to_dict()
    assert data["urn"] == "media:test;json"
    assert data["media_type"] == "application/json"
    assert data["profile_uri"] == "https://example.com/profile"
    assert data["title"] == "Test Media"
    # None schema is skipped
    assert "schema" not in data
    # None description is also skipped
    assert "description" not in data


# TEST096: Test deserializing MediaSpecDef from JSON object
def test_096_media_spec_def_deserialize():
    data = {
        "urn": "media:test;json",
        "media_type": "application/json",
        "title": "Test"
    }
    spec_def = MediaSpecDef.from_dict(data)
    assert spec_def.urn == "media:test;json"
    assert spec_def.media_type == "application/json"
    assert spec_def.title == "Test"
    assert spec_def.profile_uri is None


# =============================================================================
# Duplicate URN validation tests
# =============================================================================


# TEST097: Test duplicate URN validation catches duplicates
def test_097_validate_no_duplicate_urns_catches_duplicates():
    media_specs = [
        MediaSpecDef(
            urn="media:dup;json",
            media_type="application/json",
            title="First",
        ),
        MediaSpecDef(
            urn="media:dup;json",
            media_type="application/json",
            title="Second",
        ),  # duplicate
    ]
    with pytest.raises(DuplicateMediaUrn) as exc_info:
        validate_media_specs_no_duplicates(media_specs)
    assert "media:dup;json" in str(exc_info.value)


# TEST098: Test duplicate URN validation passes for unique URNs
def test_098_validate_no_duplicate_urns_passes_for_unique():
    media_specs = [
        MediaSpecDef(
            urn="media:first;json",
            media_type="application/json",
            title="First",
        ),
        MediaSpecDef(
            urn="media:second;json",
            media_type="application/json",
            title="Second",
        ),
    ]
    # Should not raise
    validate_media_specs_no_duplicates(media_specs)


# =============================================================================
# ResolvedMediaSpec tests
# =============================================================================


# TEST099: Test ResolvedMediaSpec is_binary returns true for non-textable media URN
def test_099_resolved_is_binary():
    resolved = ResolvedMediaSpec(
        media_urn="media:",
        media_type="application/octet-stream",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_binary()
    assert not resolved.is_record()
    assert not resolved.is_json()


# TEST100: Test ResolvedMediaSpec is_record returns true for record marker tag media URN
def test_100_resolved_is_record():
    resolved = ResolvedMediaSpec(
        media_urn="media:record;textable",
        media_type="application/json",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_record()
    assert not resolved.is_binary()
    assert resolved.is_scalar()  # record without list marker is scalar cardinality
    assert not resolved.is_list()


# TEST101: Test ResolvedMediaSpec is_scalar returns true when list marker tag is NOT present
def test_101_resolved_is_scalar():
    resolved = ResolvedMediaSpec(
        media_urn="media:textable",
        media_type="text/plain",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_scalar()
    assert not resolved.is_record()
    assert not resolved.is_list()


# TEST102: Test ResolvedMediaSpec is_list returns true for list marker tag media URN
def test_102_resolved_is_list():
    resolved = ResolvedMediaSpec(
        media_urn="media:list;textable",
        media_type="application/json",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_list()
    assert not resolved.is_record()
    assert not resolved.is_scalar()


# TEST103: Test ResolvedMediaSpec is_json returns true when json marker tag is present
def test_103_resolved_is_json():
    resolved = ResolvedMediaSpec(
        media_urn="media:json;record;textable",
        media_type="application/json",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_json()
    assert resolved.is_record()
    assert not resolved.is_binary()


# TEST104: Test ResolvedMediaSpec is_text returns true when textable tag is present
def test_104_resolved_is_text():
    resolved = ResolvedMediaSpec(
        media_urn="media:textable",
        media_type="text/plain",
        profile_uri=None,
        schema=None,
        title=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=[],
    )
    assert resolved.is_text()
    assert not resolved.is_binary()
    assert not resolved.is_json()


# =============================================================================
# Metadata propagation tests
# =============================================================================


# TEST105: Test metadata propagates from media spec def to resolved media spec
@pytest.mark.asyncio
async def test_105_metadata_propagation():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:custom-setting;setting",
            media_type="text/plain",
            title="Custom Setting",
            profile_uri="https://example.com/schema",
            schema=None,
            description="A custom setting",
            validation=None,
            metadata={
                "category_key": "interface",
                "ui_type": "SETTING_UI_TYPE_CHECKBOX"
            },
            extensions=[],
        )
    ])

    resolved = await resolve_media_urn("media:custom-setting;setting", media_specs, registry)
    assert resolved.metadata is not None
    assert resolved.metadata.get("category_key") == "interface"
    assert resolved.metadata.get("ui_type") == "SETTING_UI_TYPE_CHECKBOX"


# TEST106: Test metadata and validation can coexist in media spec definition
@pytest.mark.asyncio
async def test_106_metadata_with_validation():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:bounded-number;numeric;setting",
            media_type="text/plain",
            title="Bounded Number",
            profile_uri="https://example.com/schema",
            schema=None,
            description=None,
            validation=MediaValidation(
                min=0.0,
                max=100.0,
                min_length=None,
                max_length=None,
                pattern=None,
                allowed_values=None,
            ),
            metadata={
                "category_key": "inference",
                "ui_type": "SETTING_UI_TYPE_SLIDER"
            },
            extensions=[],
        )
    ])

    resolved = await resolve_media_urn("media:bounded-number;numeric;setting", media_specs, registry)

    # Verify validation
    assert resolved.validation is not None
    assert resolved.validation.min == 0.0
    assert resolved.validation.max == 100.0

    # Verify metadata
    assert resolved.metadata is not None
    assert resolved.metadata.get("category_key") == "inference"


# =============================================================================
# Extension field tests
# =============================================================================


# TEST107: Test extensions field propagates from media spec def to resolved
@pytest.mark.asyncio
async def test_107_extensions_propagation():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:custom-pdf",
            media_type="application/pdf",
            title="PDF Document",
            profile_uri="https://capns.org/schema/pdf",
            schema=None,
            description="A PDF document",
            validation=None,
            metadata=None,
            extensions=["pdf"],
        )
    ])

    resolved = await resolve_media_urn("media:custom-pdf", media_specs, registry)
    assert resolved.extensions == ["pdf"]


# TEST108: Test extensions serializes/deserializes correctly in MediaSpecDef
def test_108_extensions_serialization():
    spec_def = MediaSpecDef(
        urn="media:json-data",
        media_type="application/json",
        title="JSON Data",
        profile_uri="https://example.com/profile",
        schema=None,
        description=None,
        validation=None,
        metadata=None,
        extensions=["json"],
    )
    data = spec_def.to_dict()
    assert data["extensions"] == ["json"]

    # Deserialize and verify
    parsed = MediaSpecDef.from_dict(data)
    assert parsed.extensions == ["json"]


# TEST109: Test extensions can coexist with metadata and validation
@pytest.mark.asyncio
async def test_109_extensions_with_metadata_and_validation():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:custom-output;json",
            media_type="application/json",
            title="Custom Output",
            profile_uri="https://example.com/schema",
            schema=None,
            description=None,
            validation=MediaValidation(
                min=None,
                max=None,
                min_length=1,
                max_length=1000,
                pattern=None,
                allowed_values=None,
            ),
            metadata={"category": "output"},
            extensions=["json"],
        )
    ])

    resolved = await resolve_media_urn("media:custom-output;json", media_specs, registry)

    # Verify all fields are present
    assert resolved.validation is not None
    assert resolved.metadata is not None
    assert resolved.extensions == ["json"]


# TEST110: Test multiple extensions in a media spec
@pytest.mark.asyncio
async def test_110_multiple_extensions():
    registry = await create_test_registry()
    media_specs = create_media_specs([
        MediaSpecDef(
            urn="media:image;jpeg",
            media_type="image/jpeg",
            title="JPEG Image",
            profile_uri="https://capns.org/schema/jpeg",
            schema=None,
            description="JPEG image data",
            validation=None,
            metadata=None,
            extensions=["jpg", "jpeg"],
        )
    ])

    resolved = await resolve_media_urn("media:image;jpeg", media_specs, registry)
    assert resolved.extensions == ["jpg", "jpeg"]
    assert len(resolved.extensions) == 2
