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
    MEDIA_PDF,
    MEDIA_AVAILABILITY_OUTPUT,
    MEDIA_PATH_OUTPUT,
    MEDIA_STRING_ARRAY,
    MEDIA_INTEGER_ARRAY,
    MEDIA_NUMBER_ARRAY,
    MEDIA_BOOLEAN_ARRAY,
    MEDIA_AUDIO,
    MEDIA_VIDEO,
    MEDIA_AUDIO_SPEECH,
    MEDIA_IMAGE_THUMBNAIL,
    MEDIA_FILE_PATH,
    MEDIA_FILE_PATH_ARRAY,
    MEDIA_DECISION,
    MEDIA_DECISION_ARRAY,
    binary_media_urn_for_ext,
    text_media_urn_for_ext,
    image_media_urn_for_ext,
    audio_media_urn_for_ext,
)


# TEST060: Test wrong prefix fails with InvalidPrefix error showing expected and actual prefix
def test_060_wrong_prefix_fails():
    with pytest.raises(MediaUrnError, match="Invalid prefix"):
        MediaUrn.from_string("cap:string")


# TEST061: Test is_binary returns true when textable marker tag is NOT present
def test_061_is_binary():
    binary_urn = MediaUrn.from_string(MEDIA_BINARY)
    assert binary_urn.is_binary()

    # PNG is also binary
    png_urn = MediaUrn.from_string(MEDIA_PNG)
    assert png_urn.is_binary()

    # String is not binary
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_binary()


# TEST062: Test is_record returns true when record marker tag is present indicating key-value structure
def test_062_is_record():
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert obj_urn.is_record()

    # JSON is also a record
    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_record()

    # String is not a record
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_record()


# TEST063: Test is_scalar returns true when list marker tag is NOT present indicating single value
def test_063_is_scalar():
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert string_urn.is_scalar()

    int_urn = MediaUrn.from_string(MEDIA_INTEGER)
    assert int_urn.is_scalar()

    # Arrays are not scalar
    array_urn = MediaUrn.from_string(MEDIA_STRING_ARRAY)
    assert not array_urn.is_scalar()


# TEST064: Test is_list returns true when list marker tag is present indicating ordered collection
def test_064_is_list():
    list_urn = MediaUrn.from_string(MEDIA_STRING_ARRAY)
    assert list_urn.is_list()

    int_array_urn = MediaUrn.from_string(MEDIA_INTEGER_ARRAY)
    assert int_array_urn.is_list()

    # Scalar is not a list
    scalar_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not scalar_urn.is_list()


# TEST065: Test is_record and is_list for structure checking (is_structured removed from MediaUrn)
def test_065_record_and_list():
    # Record has internal structure
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert obj_urn.is_record()
    assert not obj_urn.is_opaque()

    # List is a collection
    list_urn = MediaUrn.from_string(MEDIA_STRING_ARRAY)
    assert list_urn.is_list()
    assert not list_urn.is_scalar()

    # Opaque scalar has no structure
    scalar_urn = MediaUrn.from_string(MEDIA_STRING)
    assert scalar_urn.is_opaque()
    assert not scalar_urn.is_record()

    # Binary wildcard is opaque
    bin_urn = MediaUrn.from_string(MEDIA_BINARY)
    assert bin_urn.is_opaque()
    assert not bin_urn.is_record()


# TEST066: Test is_json returns true only when json marker tag is present for JSON representation
def test_066_is_json():
    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_json()

    # Object is not necessarily JSON (could be other map formats)
    obj_urn = MediaUrn.from_string(MEDIA_OBJECT)
    assert not obj_urn.is_json()


# TEST067: Test is_text returns true only when textable marker tag is present
def test_067_is_text():
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert string_urn.is_text()

    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_text()

    # Binary is not textable
    bin_urn = MediaUrn.from_string(MEDIA_BINARY)
    assert not bin_urn.is_text()


# TEST068: Test is_void returns true when void flag or type=void tag is present
def test_068_is_void():
    void_urn = MediaUrn.from_string(MEDIA_VOID)
    assert void_urn.is_void()

    # String is not void
    string_urn = MediaUrn.from_string(MEDIA_STRING)
    assert not string_urn.is_void()


# TEST071: Test to_string roundtrip ensures serialization and deserialization preserve URN structure
def test_071_to_string_roundtrip():
    original = "media:application;subtype=json;v=1"
    urn = MediaUrn.from_string(original)
    serialized = urn.to_string()
    reparsed = MediaUrn.from_string(serialized)
    assert urn == reparsed


# TEST072: Test all media URN constants parse successfully as valid media URNs
def test_072_all_constants_parse():
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
def test_073_extension_helpers():
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
def test_074_media_urn_matching():
    generic_handler = MediaUrn.from_string("media:")
    specific_request = MediaUrn.from_string("media:pdf")
    assert specific_request.conforms_to(generic_handler), "Specific pdf request should conform to generic handler"
    assert not generic_handler.conforms_to(specific_request), "Generic request should NOT conform to specific pdf handler"


# TEST075: Test matching with implicit wildcards where handlers with fewer tags can handle more requests
def test_075_matching():
    generic_handler = MediaUrn.from_string("media:textable")
    specific_scalar_request = MediaUrn.from_string("media:textable")
    specific_list_request = MediaUrn.from_string("media:textable;list")

    assert specific_scalar_request.conforms_to(generic_handler)
    assert specific_list_request.conforms_to(generic_handler)


# TEST076: Test specificity increases with more tags for ranking matches
def test_076_specificity():
    urn1 = MediaUrn.from_string("media:")
    urn2 = MediaUrn.from_string("media:pdf")
    urn3 = MediaUrn.from_string("media:image;png;thumbnail")

    assert urn1.specificity() < urn2.specificity()
    assert urn2.specificity() < urn3.specificity()


# TEST077: Test serde roundtrip serializes to JSON string and deserializes back correctly
def test_077_serde_roundtrip():
    original_str = "media:application;subtype=json;v=1"
    urn = MediaUrn.from_string(original_str)
    serialized = urn.to_string()
    reparsed = MediaUrn.from_string(serialized)
    assert urn == reparsed


# TEST304: Test MEDIA_AVAILABILITY_OUTPUT constant parses as valid media URN with correct tags
def test_304_media_availability_output_constant():
    urn = MediaUrn.from_string(MEDIA_AVAILABILITY_OUTPUT)
    assert urn is not None
    assert urn.is_text()
    assert urn.is_record()


# TEST305: Test MEDIA_PATH_OUTPUT constant parses as valid media URN with correct tags
def test_305_media_path_output_constant():
    urn = MediaUrn.from_string(MEDIA_PATH_OUTPUT)
    assert urn is not None
    assert urn.is_text()
    assert urn.is_record()


# TEST306: Test MEDIA_AVAILABILITY_OUTPUT and MEDIA_PATH_OUTPUT are distinct URNs
def test_306_availability_and_path_output_distinct():
    avail_urn = MediaUrn.from_string(MEDIA_AVAILABILITY_OUTPUT)
    path_urn = MediaUrn.from_string(MEDIA_PATH_OUTPUT)
    assert avail_urn != path_urn
    assert avail_urn.to_string() != path_urn.to_string()


# TEST546: is_image returns true only when image marker tag is present
def test_546_is_image():
    assert MediaUrn.from_string(MEDIA_PNG).is_image()
    assert MediaUrn.from_string(MEDIA_IMAGE_THUMBNAIL).is_image()
    assert MediaUrn.from_string("media:image;jpg").is_image()
    # Non-image types
    assert not MediaUrn.from_string(MEDIA_PDF).is_image()
    assert not MediaUrn.from_string(MEDIA_STRING).is_image()
    assert not MediaUrn.from_string(MEDIA_AUDIO).is_image()
    assert not MediaUrn.from_string(MEDIA_VIDEO).is_image()


# TEST547: is_audio returns true only when audio marker tag is present
def test_547_is_audio():
    assert MediaUrn.from_string(MEDIA_AUDIO).is_audio()
    assert MediaUrn.from_string(MEDIA_AUDIO_SPEECH).is_audio()
    assert MediaUrn.from_string("media:audio;mp3").is_audio()
    # Non-audio types
    assert not MediaUrn.from_string(MEDIA_VIDEO).is_audio()
    assert not MediaUrn.from_string(MEDIA_PNG).is_audio()
    assert not MediaUrn.from_string(MEDIA_STRING).is_audio()


# TEST548: is_video returns true only when video marker tag is present
def test_548_is_video():
    assert MediaUrn.from_string(MEDIA_VIDEO).is_video()
    assert MediaUrn.from_string("media:video;mp4").is_video()
    # Non-video types
    assert not MediaUrn.from_string(MEDIA_AUDIO).is_video()
    assert not MediaUrn.from_string(MEDIA_PNG).is_video()
    assert not MediaUrn.from_string(MEDIA_STRING).is_video()


# TEST549: is_numeric returns true only when numeric marker tag is present
def test_549_is_numeric():
    assert MediaUrn.from_string(MEDIA_INTEGER).is_numeric()
    assert MediaUrn.from_string(MEDIA_NUMBER).is_numeric()
    assert MediaUrn.from_string(MEDIA_INTEGER_ARRAY).is_numeric()
    assert MediaUrn.from_string(MEDIA_NUMBER_ARRAY).is_numeric()
    # Non-numeric types
    assert not MediaUrn.from_string(MEDIA_STRING).is_numeric()
    assert not MediaUrn.from_string(MEDIA_BOOLEAN).is_numeric()
    assert not MediaUrn.from_string(MEDIA_BINARY).is_numeric()


# TEST550: is_bool returns true only when bool marker tag is present
def test_550_is_bool():
    assert MediaUrn.from_string(MEDIA_BOOLEAN).is_bool()
    assert MediaUrn.from_string(MEDIA_BOOLEAN_ARRAY).is_bool()
    assert MediaUrn.from_string(MEDIA_DECISION).is_bool()
    assert MediaUrn.from_string(MEDIA_DECISION_ARRAY).is_bool()
    # Non-bool types
    assert not MediaUrn.from_string(MEDIA_STRING).is_bool()
    assert not MediaUrn.from_string(MEDIA_INTEGER).is_bool()
    assert not MediaUrn.from_string(MEDIA_BINARY).is_bool()


# TEST551: is_file_path returns true for scalar file-path, false for array
def test_551_is_file_path():
    assert MediaUrn.from_string(MEDIA_FILE_PATH).is_file_path()
    # Array file-path is NOT is_file_path (it's is_file_path_array)
    assert not MediaUrn.from_string(MEDIA_FILE_PATH_ARRAY).is_file_path()
    # Non-file-path types
    assert not MediaUrn.from_string(MEDIA_STRING).is_file_path()
    assert not MediaUrn.from_string(MEDIA_BINARY).is_file_path()


# TEST552: is_file_path_array returns true for list file-path, false for scalar
def test_552_is_file_path_array():
    assert MediaUrn.from_string(MEDIA_FILE_PATH_ARRAY).is_file_path_array()
    # Scalar file-path is NOT is_file_path_array
    assert not MediaUrn.from_string(MEDIA_FILE_PATH).is_file_path_array()
    # Non-file-path types
    assert not MediaUrn.from_string(MEDIA_STRING_ARRAY).is_file_path_array()


# TEST553: is_any_file_path returns true for both scalar and array file-path
def test_553_is_any_file_path():
    assert MediaUrn.from_string(MEDIA_FILE_PATH).is_any_file_path()
    assert MediaUrn.from_string(MEDIA_FILE_PATH_ARRAY).is_any_file_path()
    # Non-file-path types
    assert not MediaUrn.from_string(MEDIA_STRING).is_any_file_path()
    assert not MediaUrn.from_string(MEDIA_STRING_ARRAY).is_any_file_path()


# TEST555: with_tag adds a tag and without_tag removes it
def test_555_with_tag_and_without_tag():
    urn = MediaUrn.from_string("media:string")
    with_ext = urn.with_tag("ext", "pdf")
    assert with_ext.extension() == "pdf"
    # Original unchanged
    assert urn.extension() is None

    # Remove the tag
    without_ext = with_ext.without_tag("ext")
    assert without_ext.extension() is None
    # Removing non-existent tag is a no-op
    same = urn.without_tag("nonexistent")
    assert same == urn


# TEST556: image_media_urn_for_ext creates valid image media URN
def test_556_image_media_urn_for_ext():
    jpg_urn_str = image_media_urn_for_ext("jpg")
    parsed = MediaUrn.from_string(jpg_urn_str)
    assert parsed.is_image(), "image helper must set image tag"
    assert parsed.is_binary(), "image helper must produce binary (non-textable) URN"
    assert parsed.extension() == "jpg"


# TEST557: audio_media_urn_for_ext creates valid audio media URN
def test_557_audio_media_urn_for_ext():
    mp3_urn_str = audio_media_urn_for_ext("mp3")
    parsed = MediaUrn.from_string(mp3_urn_str)
    assert parsed.is_audio(), "audio helper must set audio tag"
    assert parsed.is_binary(), "audio helper must produce binary (non-textable) URN"
    assert parsed.extension() == "mp3"


# TEST558: predicates are consistent with constants
def test_558_predicate_constant_consistency():
    # MEDIA_INTEGER must be numeric, text, scalar, NOT binary/bool/image/audio/video
    int_urn = MediaUrn.from_string(MEDIA_INTEGER)
    assert int_urn.is_numeric()
    assert int_urn.is_text()
    assert int_urn.is_scalar()
    assert not int_urn.is_binary()
    assert not int_urn.is_bool()
    assert not int_urn.is_image()
    assert not int_urn.is_list()

    # MEDIA_BOOLEAN must be bool, text, scalar, NOT numeric
    bool_urn = MediaUrn.from_string(MEDIA_BOOLEAN)
    assert bool_urn.is_bool()
    assert bool_urn.is_text()
    assert bool_urn.is_scalar()
    assert not bool_urn.is_numeric()

    # MEDIA_JSON must be json, text, record, scalar (single object), NOT binary
    json_urn = MediaUrn.from_string(MEDIA_JSON)
    assert json_urn.is_json()
    assert json_urn.is_text()
    assert json_urn.is_record()
    assert json_urn.is_scalar()  # JSON object is a single value (scalar cardinality)
    assert not json_urn.is_binary()
    assert not json_urn.is_list()

    # MEDIA_VOID is void, NOT anything else
    void_urn = MediaUrn.from_string(MEDIA_VOID)
    assert void_urn.is_void()
    assert not void_urn.is_text()
    assert void_urn.is_binary()  # void has no textable tag
    assert not void_urn.is_numeric()
