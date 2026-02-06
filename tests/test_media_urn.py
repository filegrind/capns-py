"""Tests for MediaUrn - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns import (
    MediaUrn,
    MediaUrnError,
    MEDIA_VOID,
    MEDIA_STRING,
    MEDIA_INTEGER,
    MEDIA_NUMBER,
    MEDIA_BOOLEAN,
    MEDIA_OBJECT,
    MEDIA_BINARY,
    MEDIA_PNG,
    MEDIA_JSON,
    MEDIA_AVAILABILITY_OUTPUT,
    MEDIA_PATH_OUTPUT,
    binary_media_urn_for_ext,
    text_media_urn_for_ext,
    image_media_urn_for_ext,
    audio_media_urn_for_ext,
)


# TEST060: Test wrong prefix fails with InvalidPrefix error showing expected and actual prefix
def test_wrong_prefix_fails():
    with pytest.raises(MediaUrnError, match="Invalid prefix"):
        MediaUrn.from_string("cap:string")


# TEST061: Test is_binary returns true only when bytes marker tag is present
def test_is_binary():
    binary_urn = MediaUrn.from_string(MEDIA_BINARY)
    assert binary_urn.is_binary()

    # PNG is also binary
    png_urn = MediaUrn.from_string(MEDIA_PNG)
    assert png_urn.is_binary()

    # String is not binary
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_binary()


# TEST062: Test is_map returns true when form=map tag is present indicating key-value structure
def test_is_map():
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert obj_urn.is_map()

    # JSON is also a map
    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_map()

    # String is not a map
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_map()


# TEST063: Test is_scalar returns true when form=scalar tag is present indicating single value
def test_is_scalar():
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert string_urn.is_scalar()

    int_urn = MediaUrn.from_string(MEDIA_INTEGER)
    assert int_urn.is_scalar()

    # Object is not scalar
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert not obj_urn.is_scalar()


# TEST064: Test is_list returns true when form=list tag is present indicating ordered collection
def test_is_list():
    # String array is a list
    list_urn = MediaUrn.from_string("media:textable;form=list")
    assert list_urn.is_list()

    # Scalar is not a list
    scalar_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not scalar_urn.is_list()


# TEST065: Test is_structured returns true for map or list forms indicating structured data types
def test_is_structured():
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert obj_urn.is_structured()

    list_urn = MediaUrn.from_string("media:textable;form=list")
    assert list_urn.is_structured()

    # Scalar is not structured
    scalar_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not scalar_urn.is_structured()


# TEST066: Test is_json returns true only when json marker tag is present for JSON representation
def test_is_json():
    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_json()

    # Object is not necessarily JSON (could be other map formats)
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert not obj_urn.is_json()


# TEST067: Test is_text returns true only when textable marker tag is present
def test_is_text():
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert string_urn.is_text()

    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_text()

    # Binary is not textable
    bin_urn = MediaUrn.from_string(MEDIA_BINARY)
    assert not bin_urn.is_text()


# TEST068: Test is_void returns true when void flag or type=void tag is present
def test_is_void():
    void_urn = MediaUrn.from_string(MEDIA_VOID)
    assert void_urn.is_void()

    # String is not void
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_void()


# TEST071: Test to_string roundtrip ensures serialization and deserialization preserve URN structure
def test_to_string_roundtrip():
    original = "media:application;subtype=json;v=1"
    urn = MediaUrn.from_string(original)
    serialized = urn.to_string()
    reparsed = MediaUrn.from_string(serialized)
    assert urn == reparsed


# TEST072: Test all media URN constants parse successfully as valid media URNs
def test_all_constants_parse():
    constants = [
        MEDIA_VOID,
        MEDIA_STRING,
        MEDIA_INTEGER,
        MEDIA_NUMBER,
        MEDIA_BOOLEAN,
        MEDIA_OBJECT,
        MEDIA_BINARY,
        MEDIA_PNG,
        MEDIA_JSON,
    ]
    for const in constants:
        urn = MediaUrn.from_string(const)
        assert urn is not None
        # Roundtrip should work
        reparsed = MediaUrn.from_string(urn.to_string())
        assert urn == reparsed


# TEST073: Test extension helper functions create media URNs with ext tag and correct format
def test_extension_helpers():
    # Binary with extension
    bin_ext = binary_media_urn_for_ext("dat")
    bin_urn = MediaUrn.from_string(bin_ext)
    assert bin_urn.extension() == "dat"

    # Text with extension
    text_ext = text_media_urn_for_ext("txt")
    text_urn = MediaUrn.from_string(text_ext)
    assert text_urn.extension() == "txt"
    assert text_urn.is_text()

    # Image with extension
    img_ext = image_media_urn_for_ext("jpg")
    img_urn = MediaUrn.from_string(img_ext)
    assert img_urn.extension() == "jpg"

    # Audio with extension
    audio_ext = audio_media_urn_for_ext("mp3")
    audio_urn = MediaUrn.from_string(audio_ext)
    assert audio_urn.extension() == "mp3"


# TEST074: Test media URN matching using tagged URN semantics with specific and generic requirements
def test_media_urn_matching():
    # Generic handler (just bytes) can handle specific request (pdf;bytes)
    # Semantics: request.matches(handler) checks if request satisfies handler's requirement
    generic_handler = MediaUrn.from_string("media:bytes")
    specific_request = MediaUrn.from_string("media:pdf;bytes")
    # Specific request (pdf;bytes) satisfies generic handler requirement (bytes)
    assert specific_request.matches(generic_handler), "Specific pdf;bytes request should satisfy generic bytes handler"

    # Reverse: generic request does NOT satisfy specific handler requirement
    # Generic request (just bytes) does NOT satisfy specific handler requirement (pdf;bytes)
    assert not generic_handler.matches(specific_request), "Generic bytes request should NOT satisfy specific pdf;bytes handler"


# TEST075: Test matching with implicit wildcards where handlers with fewer tags can handle more requests
def test_matching_implicit_wildcards():
    # Handler with no form tag can handle any form
    # Semantics: request.matches(handler)
    generic_handler = MediaUrn.from_string("media:textable")
    specific_scalar_request = MediaUrn.from_string("media:textable;form=scalar")
    specific_list_request = MediaUrn.from_string("media:textable;form=list")

    # Specific requests satisfy generic handler (missing tags are wildcards)
    assert specific_scalar_request.matches(generic_handler)
    assert specific_list_request.matches(generic_handler)


# TEST076: Test specificity increases with more tags for ranking matches
def test_specificity_ranking():
    urn1 = MediaUrn.from_string("media:bytes")
    urn2 = MediaUrn.from_string("media:pdf;bytes")
    urn3 = MediaUrn.from_string("media:image;png;bytes;thumbnail")

    # More tags = higher specificity
    assert urn1.specificity() < urn2.specificity()
    assert urn2.specificity() < urn3.specificity()


# TEST077: Test serde roundtrip serializes to JSON string and deserializes back correctly
def test_string_roundtrip():
    # Python doesn't have serde, but we test string roundtrip
    original_str = "media:application;subtype=json;v=1"
    urn = MediaUrn.from_string(original_str)
    serialized = urn.to_string()
    reparsed = MediaUrn.from_string(serialized)
    assert urn == reparsed


# TEST078: Debug test for matching behavior between different media URN types
def test_matching_debug():
    # pdf;bytes request satisfies bytes handler requirement (specific matches generic)
    bytes_handler = MediaUrn.from_string("media:bytes")
    pdf_request = MediaUrn.from_string("media:pdf;bytes")
    assert pdf_request.matches(bytes_handler)

    # pdf;bytes and epub;bytes are incompatible (different primary markers)
    epub_urn = MediaUrn.from_string("media:epub;bytes")
    # pdf request does NOT satisfy epub handler (missing epub tag)
    assert not pdf_request.matches(epub_urn)
    # epub request does NOT satisfy pdf handler (missing pdf tag)
    assert not epub_urn.matches(pdf_request)


# TEST304: Test MEDIA_AVAILABILITY_OUTPUT constant parses as valid media URN with correct tags
def test_media_availability_output_constant():
    urn = MediaUrn.from_string(MEDIA_AVAILABILITY_OUTPUT)
    assert urn is not None
    # Should have textable and form=map tags
    assert urn.is_text()
    assert urn.is_map()


# TEST305: Test MEDIA_PATH_OUTPUT constant parses as valid media URN with correct tags
def test_media_path_output_constant():
    urn = MediaUrn.from_string(MEDIA_PATH_OUTPUT)
    assert urn is not None
    # Should have textable and form=map tags
    assert urn.is_text()
    assert urn.is_map()


# TEST306: Test MEDIA_AVAILABILITY_OUTPUT and MEDIA_PATH_OUTPUT are distinct URNs
def test_availability_and_path_output_distinct():
    avail_urn = MediaUrn.from_string(MEDIA_AVAILABILITY_OUTPUT)
    path_urn = MediaUrn.from_string(MEDIA_PATH_OUTPUT)
    assert avail_urn != path_urn
    assert avail_urn.to_string() != path_urn.to_string()
