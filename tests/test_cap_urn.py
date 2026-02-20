"""Tests for CapUrn - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import hashlib
from capns import (
    CapUrn,
    CapUrnError,
    CapUrnBuilder,
    CapMatcher,
    MediaUrn,
    MEDIA_VOID,
    MEDIA_OBJECT,
    MEDIA_STRING,
    MEDIA_INTEGER,
    MEDIA_BINARY,
    CAP_IDENTITY,
)


def _test_urn(tags_part: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags_part}'


# TEST001: Test that cap URN is created with tags parsed correctly and direction specs accessible
def test_001_cap_urn_creation():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf;target=thumbnail"))
    assert cap.get_tag("op") == "generate"
    assert cap.get_tag("target") == "thumbnail"
    assert cap.get_tag("ext") == "pdf"
    # Direction specs are required and accessible
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT


# TEST002: Test that missing 'in' or 'out' defaults to media: wildcard
def test_002_direction_specs_default_to_wildcard():
    # Missing 'in' defaults to media:
    cap = CapUrn.from_string(f'cap:out="{MEDIA_OBJECT}";op=test')
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == MEDIA_OBJECT

    # Missing 'out' defaults to media:
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";op=test')
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == "media:"

    # Both present should succeed
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=test')
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT


# TEST003: Test that direction specs must match exactly, different in/out types don't match, wildcard matches any
def test_003_direction_matching():
    in_str = "media:textable;form=scalar"  # MEDIA_STRING
    out_obj = "media:form=map;textable"  # MEDIA_OBJECT
    in_bin = "media:bytes"  # MEDIA_BINARY
    out_int = "media:integer;textable;numeric;form=scalar"  # MEDIA_INTEGER

    # Direction specs must match for caps to match
    cap1 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_obj}"')
    cap2 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_obj}"')
    assert cap1.accepts(cap2)

    # Different in_urn should not match
    cap3 = CapUrn.from_string(f'cap:in="{in_bin}";op=test;out="{out_obj}"')
    assert not cap1.accepts(cap3)

    # Different out_urn should not match
    cap4 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_int}"')
    assert not cap1.accepts(cap4)

    # Wildcard in=* direction: cap5 has media: for in, specific for out
    cap5 = CapUrn.from_string(f'cap:in=*;op=test;out="{out_obj}"')
    # cap1 (specific in) as pattern rejects cap5 (bare media: in) — specific pattern doesn't accept broad instance
    assert not cap1.accepts(cap5)
    # cap5 (wildcard in) as pattern accepts cap1 (specific in) — wildcard pattern accepts anything
    assert cap5.accepts(cap1)


# TEST004: Test that unquoted keys and values are normalized to lowercase
def test_004_unquoted_values_lowercased():
    # Unquoted values are normalized to lowercase
    cap = CapUrn.from_string(_test_urn("OP=Generate;EXT=PDF;Target=Thumbnail"))

    # Keys are always lowercase
    assert cap.get_tag("op") == "generate"
    assert cap.get_tag("ext") == "pdf"
    assert cap.get_tag("target") == "thumbnail"

    # Key lookup is case-insensitive
    assert cap.get_tag("OP") == "generate"
    assert cap.get_tag("Op") == "generate"

    # Both URNs parse to same lowercase values (same tags, same values)
    cap2 = CapUrn.from_string(_test_urn("op=generate;ext=pdf;target=thumbnail"))
    assert cap.to_string() == cap2.to_string()
    assert cap == cap2


# TEST005: Test that quoted values preserve case while unquoted are lowercased
def test_005_quoted_values_preserve_case():
    # Quoted values preserve their case
    cap = CapUrn.from_string(_test_urn(r'key="Value With Spaces"'))
    assert cap.get_tag("key") == "Value With Spaces"

    # Key is still lowercase
    cap2 = CapUrn.from_string(_test_urn(r'KEY="Value With Spaces"'))
    assert cap2.get_tag("key") == "Value With Spaces"

    # Unquoted vs quoted case difference
    unquoted = CapUrn.from_string(_test_urn("key=UPPERCASE"))
    quoted = CapUrn.from_string(_test_urn(r'key="UPPERCASE"'))
    assert unquoted.get_tag("key") == "uppercase"  # lowercase
    assert quoted.get_tag("key") == "UPPERCASE"  # preserved
    assert unquoted != quoted  # NOT equal


# TEST006: Test that quoted values can contain special characters (semicolons, equals, spaces)
def test_006_quoted_value_special_chars():
    # Semicolons in quoted values
    cap = CapUrn.from_string(_test_urn(r'key="value;with;semicolons"'))
    assert cap.get_tag("key") == "value;with;semicolons"

    # Equals in quoted values
    cap2 = CapUrn.from_string(_test_urn(r'key="value=with=equals"'))
    assert cap2.get_tag("key") == "value=with=equals"

    # Spaces in quoted values
    cap3 = CapUrn.from_string(_test_urn(r'key="hello world"'))
    assert cap3.get_tag("key") == "hello world"


# TEST007: Test that escape sequences in quoted values (\" and \\) are parsed correctly
def test_007_quoted_value_escape_sequences():
    # Escaped quotes
    cap = CapUrn.from_string(_test_urn(r'key="value\"quoted\""'))
    assert cap.get_tag("key") == r'value"quoted"'

    # Escaped backslashes
    cap2 = CapUrn.from_string(_test_urn(r'key="path\\file"'))
    assert cap2.get_tag("key") == r'path\file'

    # Mixed escapes
    cap3 = CapUrn.from_string(_test_urn(r'key="say \"hello\\world\""'))
    assert cap3.get_tag("key") == r'say "hello\world"'


# TEST008: Test that mixed quoted and unquoted values in same URN parse correctly
def test_008_mixed_quoted_unquoted():
    cap = CapUrn.from_string(_test_urn(r'a="Quoted";b=simple'))
    assert cap.get_tag("a") == "Quoted"
    assert cap.get_tag("b") == "simple"


# TEST009: Test that unterminated quote produces UnterminatedQuote error
def test_009_unterminated_quote_error():
    with pytest.raises(CapUrnError, match="Unterminated quote"):
        CapUrn.from_string(_test_urn(r'key="unterminated'))


# TEST010: Test that invalid escape sequences (like \n, \x) produce InvalidEscapeSequence error
def test_010_invalid_escape_sequence_error():
    with pytest.raises(CapUrnError, match="Invalid escape sequence"):
        CapUrn.from_string(_test_urn(r'key="bad\n"'))

    # Invalid escape at end
    with pytest.raises(CapUrnError, match="Invalid escape sequence"):
        CapUrn.from_string(_test_urn(r'key="bad\x"'))


# TEST011: Test that serialization uses smart quoting (no quotes for simple lowercase, quotes for special chars/uppercase)
def test_011_serialization_smart_quoting():
    # Simple lowercase value - no quoting needed
    cap = CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("key", "simple").build()
    # The serialized form should contain key=simple (unquoted)
    s = cap.to_string()
    assert "key=simple" in s

    # Value with spaces - needs quoting
    cap2 = CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("key", "has spaces").build()
    s2 = cap2.to_string()
    assert r'key="has spaces"' in s2

    # Value with uppercase - needs quoting to preserve
    cap4 = CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("key", "HasUpper").build()
    s4 = cap4.to_string()
    assert r'key="HasUpper"' in s4


# TEST012: Test that simple cap URN round-trips (parse -> serialize -> parse equals original)
def test_012_round_trip_simple():
    original = _test_urn("op=generate;ext=pdf")
    cap = CapUrn.from_string(original)
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed


# TEST013: Test that quoted values round-trip preserving case and spaces
def test_013_round_trip_quoted():
    original = _test_urn(r'key="Value With Spaces"')
    cap = CapUrn.from_string(original)
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed
    assert reparsed.get_tag("key") == "Value With Spaces"


# TEST014: Test that escape sequences round-trip correctly
def test_014_round_trip_escapes():
    original = _test_urn(r'key="value\"with\\escapes"')
    cap = CapUrn.from_string(original)
    assert cap.get_tag("key") == r'value"with\escapes'
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed


# TEST015: Test that cap: prefix is required and case-insensitive
def test_015_cap_prefix_required():
    # Missing cap: prefix should fail
    with pytest.raises(CapUrnError):
        CapUrn.from_string(f'in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=generate')

    # Valid cap: prefix should work
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap.get_tag("op") == "generate"

    # Case-insensitive prefix
    cap2 = CapUrn.from_string(f'CAP:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=generate')
    assert cap2.get_tag("op") == "generate"


# TEST016: Test that trailing semicolon is equivalent (same hash, same string, matches)
def test_016_trailing_semicolon_equivalence():
    # Both with and without trailing semicolon should be equivalent
    cap1 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(_test_urn("op=generate;ext=pdf") + ";")

    # They should be equal
    assert cap1 == cap2

    # They should have same hash
    assert hash(cap1) == hash(cap2)

    # They should have same string representation (canonical form)
    assert cap1.to_string() == cap2.to_string()

    # They should accept each other
    assert cap1.accepts(cap2)
    assert cap2.accepts(cap1)


# TEST017: Test tag matching: exact match, subset match, wildcard match, value mismatch
def test_017_tag_matching():
    # Exact match
    cap1 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap1.accepts(cap2)

    # cap1(op,ext) as pattern rejects cap3(op) missing ext
    cap3 = CapUrn.from_string(_test_urn("op=generate"))  # Missing ext tag
    assert not cap1.accepts(cap3), "Pattern rejects instance missing required tag"
    # Routing: cap3(op) accepts cap1(op,ext) — instance has op → match
    assert cap3.accepts(cap1), "cap3 missing ext is wildcard, accepts cap1 with ext"

    # Wildcard: cap has wildcard value -> can handle any value
    cap4 = CapUrn.from_string(_test_urn("op=*;ext=pdf"))
    assert cap4.accepts(cap1)  # cap4 can handle cap1

    # Value mismatch
    cap5 = CapUrn.from_string(_test_urn("op=generate;ext=docx"))
    assert not cap1.accepts(cap5)


# TEST018: Test that quoted values with different case do NOT match (case-sensitive)
def test_018_quoted_values_case_sensitive():
    cap1 = CapUrn.from_string(_test_urn(r'key="CaseSensitive"'))
    cap2 = CapUrn.from_string(_test_urn(r'key="casesensitive"'))
    assert not cap1.accepts(cap2)


# TEST019: Test that missing tags are treated as wildcards (cap without tag matches any value for that tag)
def test_019_missing_tags_as_wildcards():
    # Cap without ext tag can handle request with any ext value
    cap = CapUrn.from_string(_test_urn("op=generate"))  # No ext tag
    request1 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    request2 = CapUrn.from_string(_test_urn("op=generate;ext=docx"))

    # Cap can accept both requests (missing tag is wildcard)
    assert cap.accepts(request1)
    assert cap.accepts(request2)


# TEST020: Test specificity calculation (direction specs use MediaUrn tag count, wildcards don't count)
def test_020_specificity_calculation():
    # More tags in direction specs = higher specificity
    cap1 = CapUrn.from_string(f'cap:in="media:string";out="media:object";op=test')
    cap2 = CapUrn.from_string(f'cap:in="media:textable;form=scalar";out="media:form=map;textable";op=test')
    # cap2 has more MediaUrn tags, so it's more specific
    assert cap2.specificity() > cap1.specificity()

    # Wildcards in tags don't count
    cap3 = CapUrn.from_string(_test_urn("op=generate;ext=*"))
    cap4 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap4.specificity() > cap3.specificity()


# TEST021: Test builder creates cap URN with correct tags and direction specs
def test_021_builder_creates_cap_urn():
    cap = (
        CapUrnBuilder()
        .in_spec(MEDIA_VOID)
        .out_spec(MEDIA_OBJECT)
        .tag("op", "generate")
        .tag("ext", "pdf")
        .build()
    )
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT
    assert cap.get_tag("op") == "generate"
    assert cap.get_tag("ext") == "pdf"


# TEST022: Test builder requires both in_spec and out_spec
def test_022_builder_requires_direction_specs():
    # Missing in_spec
    with pytest.raises(CapUrnError, match="Missing required 'in' spec"):
        CapUrnBuilder().out_spec(MEDIA_OBJECT).tag("op", "test").build()

    # Missing out_spec
    with pytest.raises(CapUrnError, match="Missing required 'out' spec"):
        CapUrnBuilder().in_spec(MEDIA_VOID).tag("op", "test").build()

    # Both present should work
    cap = CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("op", "test").build()
    assert cap is not None


# TEST023: Test builder lowercases keys but preserves value case
def test_023_builder_key_normalization():
    cap = (
        CapUrnBuilder()
        .in_spec(MEDIA_VOID)
        .out_spec(MEDIA_OBJECT)
        .tag("OP", "Generate")  # Key uppercase, value mixed case
        .build()
    )
    # Key should be lowercase
    assert cap.get_tag("op") == "Generate"
    assert cap.get_tag("OP") == "Generate"  # Case-insensitive lookup
    # Value case should be preserved
    assert cap.get_tag("op") == "Generate"


# TEST024: Test directional accepts (different op values, wildcard, direction mismatch)
def test_024_directional_accepts():
    # Different op values: neither accepts the other
    cap1 = CapUrn.from_string(_test_urn("op=generate"))
    cap2 = CapUrn.from_string(_test_urn("op=convert"))
    assert not cap1.accepts(cap2)
    assert not cap2.accepts(cap1)

    # Wildcard op accepts specific op
    cap_wildcard = CapUrn.from_string(_test_urn("op=*"))
    assert cap_wildcard.accepts(cap1)
    # cap1 also accepts wildcard (missing non-direction tag = implicit wildcard for cap matching)
    assert cap1.accepts(cap_wildcard)

    # Different direction specs: neither accepts the other
    cap3 = CapUrn.from_string(f'cap:in="media:bytes";out="media:form=map;textable";op=test')
    cap4 = CapUrn.from_string(f'cap:in="media:textable;form=scalar";out="media:integer;textable;numeric;form=scalar";op=test')
    assert not cap3.accepts(cap4)
    assert not cap4.accepts(cap3)


# TEST025: Test find_best_match returns most specific matching cap
def test_025_find_best_match():
    # This test requires implementing a find_best_match function
    # For now, we test the specificity and matching directly
    caps = [
        CapUrn.from_string(_test_urn("op=*")),  # Generic
        CapUrn.from_string(_test_urn("op=generate;ext=pdf")),  # Specific
    ]
    request = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))

    # Both accept, but the second is more specific
    matching = [c for c in caps if c.accepts(request)]
    assert len(matching) == 2
    best = max(matching, key=lambda c: c.specificity())
    assert best == caps[1]


# TEST026: Test merge combines tags from both caps, subset keeps only specified tags
def test_026_merge_and_subset():
    cap1 = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(_test_urn("op=convert;target=thumbnail"))

    # Merge: cap2 takes precedence
    merged = cap1.merge(cap2)
    assert merged.get_tag("op") == "convert"  # From cap2
    assert merged.get_tag("ext") == "pdf"  # From cap1
    assert merged.get_tag("target") == "thumbnail"  # From cap2

    # Subset
    subset = cap1.subset(["op"])
    assert subset.get_tag("op") == "generate"
    assert subset.get_tag("ext") is None  # Not in subset


# TEST027: Test with_wildcard_tag sets tag to wildcard, including in/out
def test_027_with_wildcard_tag():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))

    # Wildcard a regular tag
    cap2 = cap.with_wildcard_tag("ext")
    assert cap2.get_tag("ext") == "*"

    # Wildcard in direction — stores literal "*" (matching Rust TEST027)
    cap3 = cap.with_wildcard_tag("in")
    assert cap3.in_spec() == "*"

    # Wildcard out direction — stores literal "*" (matching Rust TEST027)
    cap4 = cap.with_wildcard_tag("out")
    assert cap4.out_spec() == "*"


# TEST028: Test bare "cap:" defaults to media: for both directions (identity morphism)
def test_028_empty_cap_urn_defaults():
    cap = CapUrn.from_string("cap:")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"
    assert len(cap.tags) == 0


# TEST029: Test minimal valid cap URN has just in and out, empty tags
def test_029_minimal_valid_cap_urn():
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}"')
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT
    assert len(cap.tags) == 0


# TEST030: Test extended characters (forward slashes, colons) in tag values
def test_030_extended_characters_in_values():
    cap = CapUrn.from_string(_test_urn("path=path/to/file;url=http://example.com"))
    assert cap.get_tag("path") == "path/to/file"
    assert cap.get_tag("url") == "http://example.com"


# TEST031: Test wildcard rejected in keys but accepted in values
def test_031_wildcard_in_keys_and_values():
    # Wildcard in value is accepted
    cap = CapUrn.from_string(_test_urn("op=*"))
    assert cap.get_tag("op") == "*"

    # Wildcard in key should fail (handled by tagged-urn)
    with pytest.raises(CapUrnError):
        CapUrn.from_string(_test_urn("*=value"))


# TEST032: Test duplicate keys are rejected with DuplicateKey error
def test_032_duplicate_keys_rejected():
    with pytest.raises(CapUrnError, match="Duplicate"):
        CapUrn.from_string(_test_urn("op=generate;op=convert"))


# TEST033: Test pure numeric keys rejected, mixed alphanumeric allowed, numeric values allowed
def test_033_numeric_keys():
    # Pure numeric key should fail (handled by tagged-urn)
    with pytest.raises(CapUrnError, match="numeric"):
        CapUrn.from_string(_test_urn("123=value"))

    # Mixed alphanumeric key is allowed
    cap = CapUrn.from_string(_test_urn("key123=value"))
    assert cap.get_tag("key123") == "value"

    # Numeric value is allowed
    cap2 = CapUrn.from_string(_test_urn("key=123"))
    assert cap2.get_tag("key") == "123"


# TEST034: Test empty values are rejected
def test_034_empty_values_rejected():
    # Empty value in builder
    with pytest.raises(CapUrnError, match="Empty value"):
        CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("key", "").build()


# TEST035: Test has_tag is case-sensitive for values, case-insensitive for keys, works for in/out
def test_035_has_tag_behavior():
    cap = CapUrn.from_string(_test_urn(r'key="Value"'))

    # Key is case-insensitive
    assert cap.has_tag("key", "Value")
    assert cap.has_tag("KEY", "Value")
    assert cap.has_tag("Key", "Value")

    # Value is case-sensitive
    assert cap.has_tag("key", "Value")
    assert not cap.has_tag("key", "value")
    assert not cap.has_tag("key", "VALUE")

    # Works for in/out
    assert cap.has_tag("in", MEDIA_VOID)
    assert cap.has_tag("out", MEDIA_OBJECT)


# TEST036: Test with_tag preserves value case
def test_036_with_tag_preserves_case():
    cap = CapUrn.from_string(_test_urn("op=generate"))
    cap2 = cap.with_tag("key", "MixedCase")
    assert cap2.get_tag("key") == "MixedCase"


# TEST037: Test with_tag rejects empty value
def test_037_with_tag_rejects_empty():
    cap = CapUrn.from_string(_test_urn("op=generate"))
    with pytest.raises(CapUrnError, match="Empty value"):
        cap.with_tag("key", "")


# TEST038: Test semantic equivalence of unquoted and quoted simple lowercase values
def test_038_semantic_equivalence_quoted_unquoted():
    cap1 = CapUrn.from_string(_test_urn("key=simple"))
    cap2 = CapUrn.from_string(_test_urn(r'key="simple"'))
    # Both should have the same value
    assert cap1.get_tag("key") == cap2.get_tag("key")
    assert cap1 == cap2


# TEST039: Test get_tag returns direction specs (in/out) with case-insensitive lookup
def test_039_get_tag_direction_specs():
    cap = CapUrn.from_string(_test_urn("op=generate"))

    # get_tag works for in/out
    assert cap.get_tag("in") == MEDIA_VOID
    assert cap.get_tag("out") == MEDIA_OBJECT

    # Case-insensitive
    assert cap.get_tag("IN") == MEDIA_VOID
    assert cap.get_tag("OUT") == MEDIA_OBJECT
    assert cap.get_tag("In") == MEDIA_VOID
    assert cap.get_tag("Out") == MEDIA_OBJECT

    # Also accessible via methods
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT


# ============================================================================
# Matching Semantics Tests
# ============================================================================


# TEST040: Matching semantics - exact match succeeds
def test_040_matching_semantics_exact_match():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap.accepts(request), "Test 1: Exact match should succeed"


# TEST041: Matching semantics - cap missing tag matches (implicit wildcard)
def test_041_matching_semantics_cap_missing_tag():
    cap = CapUrn.from_string(_test_urn("op=generate"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap.accepts(request), "Test 2: Cap missing tag should accept (implicit wildcard)"


# TEST042: Pattern rejects instance missing required tags
def test_042_matching_semantics_cap_has_extra_tag():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf;version=2"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    # cap(op,ext,version) as pattern rejects request missing version
    assert not cap.accepts(request), "Pattern rejects instance missing required tag"
    # Routing: request(op,ext) accepts cap(op,ext,version) — instance has all request needs
    assert request.accepts(cap), "Request pattern satisfied by more-specific cap"


# TEST043: Matching semantics - request wildcard matches specific cap value
def test_043_matching_semantics_request_has_wildcard():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=*"))
    assert cap.accepts(request), "Test 4: Request wildcard should be accepted"


# TEST044: Matching semantics - cap wildcard matches specific request value
def test_044_matching_semantics_cap_has_wildcard():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=*"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    assert cap.accepts(request), "Test 5: Cap wildcard should accept"


# TEST045: Matching semantics - value mismatch does not match
def test_045_matching_semantics_value_mismatch():
    cap = CapUrn.from_string(_test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(_test_urn("op=generate;ext=docx"))
    assert not cap.accepts(request), "Test 6: Value mismatch should not accept"


# TEST046: Matching semantics - fallback pattern (cap missing tag = implicit wildcard)
def test_046_matching_semantics_fallback_pattern():
    in_bin = "media:bytes"
    cap = CapUrn.from_string(f'cap:in="{in_bin}";op=generate_thumbnail;out="{in_bin}"')
    request = CapUrn.from_string(f'cap:ext=wav;in="{in_bin}";op=generate_thumbnail;out="{in_bin}"')
    assert cap.accepts(request), "Test 7: Fallback pattern should accept (cap missing ext = implicit wildcard)"


# TEST047: Matching semantics - thumbnail fallback with void input
def test_047_matching_semantics_thumbnail_void_input():
    out_bin = "media:bytes"
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";op=generate_thumbnail;out="{out_bin}"')
    request = CapUrn.from_string(f'cap:ext=wav;in="{MEDIA_VOID}";op=generate_thumbnail;out="{out_bin}"')
    assert cap.accepts(request), "Test 7b: Thumbnail fallback with void input should accept"


# TEST048: Matching semantics - wildcard direction matches anything
def test_048_matching_semantics_wildcard_direction():
    cap = CapUrn.from_string("cap:in=*;out=*")
    request = CapUrn.from_string(f'cap:ext=pdf;in="media:textable;form=scalar";op=generate;out="{MEDIA_OBJECT}"')
    assert cap.accepts(request), "Test 8: Wildcard direction should accept any direction"


# TEST049: Non-overlapping tags — neither direction accepts
def test_049_matching_semantics_cross_dimension():
    cap = CapUrn.from_string(_test_urn("op=generate"))
    request = CapUrn.from_string(_test_urn("ext=pdf"))
    # cap(op) rejects request missing op; request(ext) rejects cap missing ext
    assert not cap.accepts(request), "Pattern rejects instance missing required tag"
    assert not request.accepts(cap), "Reverse also rejects — non-overlapping tags"


# TEST050: Matching semantics - direction mismatch prevents matching
def test_050_matching_semantics_direction_mismatch():
    # media:textable;form=scalar (string) has different tags than media:bytes
    # Neither can provide input for the other (completely different marker tags)
    cap = CapUrn.from_string(f'cap:in="media:textable;form=scalar";op=generate;out="{MEDIA_OBJECT}"')
    request = CapUrn.from_string(f'cap:in="media:bytes";op=generate;out="{MEDIA_OBJECT}"')
    assert not cap.accepts(request), "Test 10: Direction mismatch should not accept"


# TEST051: Semantic direction matching - generic provider matches specific request
def test_051_direction_semantic_matching():
    # A cap accepting media:bytes (generic) should match a request with media:pdf;bytes (specific)
    generic_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    pdf_request = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert generic_cap.accepts(pdf_request), "Generic bytes provider must accept specific pdf;bytes request"

    # Generic cap also accepts epub;bytes (any bytes subtype)
    epub_request = CapUrn.from_string(
        'cap:in="media:epub;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert generic_cap.accepts(epub_request), "Generic bytes provider must accept epub;bytes request"

    # Reverse: specific cap does NOT accept generic request
    pdf_cap = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    generic_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert not pdf_cap.accepts(generic_request), "Specific pdf;bytes cap must NOT accept generic bytes request"

    # Incompatible types: pdf cap does NOT accept epub request
    assert not pdf_cap.accepts(epub_request), "PDF-specific cap must NOT accept epub request"

    # Output direction: cap producing more specific output accepts less specific request
    specific_out_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    generic_out_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;bytes"'
    )
    assert specific_out_cap.accepts(generic_out_request), "Cap producing specific output must satisfy generic request"

    # Reverse output: generic output cap does NOT accept specific output request
    generic_out_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;bytes"'
    )
    specific_out_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert not generic_out_cap.accepts(specific_out_request), "Cap producing generic output must NOT satisfy specific request"


# TEST052: Semantic direction specificity - more media URN tags = higher specificity
def test_052_direction_semantic_specificity():
    # media:bytes has 1 tag, media:pdf;bytes has 2 tags
    # media:image;png;bytes;thumbnail has 4 tags
    generic_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    specific_cap = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )

    # generic: bytes(1) + image;png;bytes;thumbnail(4) + op(1) = 6
    assert generic_cap.specificity() == 6
    # specific: pdf;bytes(2) + image;png;bytes;thumbnail(4) + op(1) = 7
    assert specific_cap.specificity() == 7

    assert specific_cap.specificity() > generic_cap.specificity(), "pdf;bytes cap must be more specific than bytes cap"

    # Find best match: should prefer the more specific cap when both match
    pdf_request = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    caps = [generic_cap, specific_cap]
    matching = [c for c in caps if c.accepts(pdf_request)]
    best = max(matching, key=lambda c: c.specificity())
    # MediaUrn alphabetizes tags, so pdf;bytes becomes bytes;pdf in canonical form
    assert best.in_spec() == "media:bytes;pdf" or best.in_spec() == "media:pdf;bytes", "Must prefer the more specific pdf;bytes provider"


# =============================================================================
# Tier Tests (TEST559-TEST567)
# =============================================================================


# TEST559: without_tag removes tag, ignores in/out, case-insensitive for keys
def test_559_without_tag():
    cap = CapUrn.from_string(
        'cap:in="media:void";op=test;ext=pdf;out="media:void"'
    )
    removed = cap.without_tag("ext")
    assert removed.get_tag("ext") is None
    assert removed.get_tag("op") == "test"

    # Case-insensitive removal
    removed2 = cap.without_tag("EXT")
    assert removed2.get_tag("ext") is None

    # Removing in/out is silently ignored
    same = cap.without_tag("in")
    assert same.in_spec() == MEDIA_VOID
    same2 = cap.without_tag("out")
    assert same2.out_spec() == MEDIA_VOID

    # Removing non-existent tag is no-op
    same3 = cap.without_tag("nonexistent")
    assert same3 == cap


# TEST560: with_in_spec and with_out_spec change direction specs
def test_560_with_in_out_spec():
    cap = CapUrn.from_string(
        'cap:in="media:void";op=test;out="media:void"'
    )

    changed_in = cap.with_in_spec("media:bytes")
    assert changed_in.in_spec() == "media:bytes"
    assert changed_in.out_spec() == MEDIA_VOID
    assert changed_in.get_tag("op") == "test"

    changed_out = cap.with_out_spec("media:string")
    assert changed_out.in_spec() == MEDIA_VOID
    assert changed_out.out_spec() == "media:string"

    # Chain both
    changed_both = cap.with_in_spec("media:pdf;bytes").with_out_spec("media:txt;textable")
    assert changed_both.in_spec() == "media:pdf;bytes" or changed_both.in_spec() == "media:bytes;pdf"
    assert changed_both.out_spec() == "media:txt;textable" or changed_both.out_spec() == "media:textable;txt"


# TEST561: in_media_urn and out_media_urn parse direction specs into MediaUrn
def test_561_in_out_media_urn():
    cap = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=extract;out="media:txt;textable"'
    )

    in_urn = cap.in_media_urn()
    assert in_urn.is_binary()
    assert in_urn.has_tag("pdf", "*")

    out_urn = cap.out_media_urn()
    assert out_urn.is_text()
    assert out_urn.has_tag("txt", "*")

    # Wildcard media: is valid but has no tags
    wildcard_cap = CapUrn.from_string("cap:")
    wildcard_in = wildcard_cap.in_media_urn()
    assert wildcard_in is not None, "bare media: should parse as valid MediaUrn"


# TEST562: canonical_option returns None for None input, canonical string for Some
def test_562_canonical_option():
    # None input -> None
    result = CapUrn.canonical_option(None)
    assert result is None

    # Some valid input -> canonical string
    input_str = 'cap:op=test;in="media:void";out="media:void"'
    result = CapUrn.canonical_option(input_str)
    assert result is not None
    original = CapUrn.from_string(input_str)
    reparsed = CapUrn.from_string(result)
    assert original == reparsed

    # Some invalid input -> error
    with pytest.raises(Exception):
        CapUrn.canonical_option("invalid")


# TEST563: CapMatcher::find_all_matches returns all matching caps sorted by specificity
def test_563_find_all_matches():
    caps = [
        CapUrn.from_string('cap:in="media:void";op=test;out="media:void"'),
        CapUrn.from_string('cap:in="media:void";op=test;ext=pdf;out="media:void"'),
        CapUrn.from_string('cap:in="media:void";op=different;out="media:void"'),
    ]

    request = CapUrn.from_string('cap:in="media:void";op=test;out="media:void"')
    matches = CapMatcher.find_all_matches(caps, request)

    # Should find 2 matches (op=test and op=test;ext=pdf), not op=different
    assert len(matches) == 2
    # Sorted by specificity descending: ext=pdf first (more specific)
    assert matches[0].specificity() >= matches[1].specificity()
    assert matches[0].get_tag("ext") == "pdf"


# TEST564: CapMatcher::are_compatible detects bidirectional overlap
def test_564_are_compatible():
    caps1 = [
        CapUrn.from_string('cap:in="media:void";op=test;out="media:void"'),
    ]
    caps2 = [
        CapUrn.from_string('cap:in="media:void";op=test;ext=pdf;out="media:void"'),
    ]
    caps3 = [
        CapUrn.from_string('cap:in="media:void";op=different;out="media:void"'),
    ]

    # caps1 (op=test) accepts caps2 (op=test;ext=pdf) -> compatible
    assert CapMatcher.are_compatible(caps1, caps2)

    # caps1 (op=test) vs caps3 (op=different) -> not compatible
    assert not CapMatcher.are_compatible(caps1, caps3)

    # Empty sets are not compatible
    assert not CapMatcher.are_compatible([], caps1)
    assert not CapMatcher.are_compatible(caps1, [])


# TEST565: tags_to_string returns only tags portion without prefix
def test_565_tags_to_string():
    cap = CapUrn.from_string(
        'cap:in="media:void";op=test;out="media:void"'
    )
    tags_str = cap.tags_to_string()
    # Should NOT start with "cap:"
    assert not tags_str.startswith("cap:")
    # Should contain in, out, op tags
    assert "op=test" in tags_str


# TEST566: with_tag silently ignores in/out keys
def test_566_with_tag_ignores_in_out():
    cap = CapUrn.from_string(
        'cap:in="media:void";op=test;out="media:void"'
    )
    # Attempting to set in/out via with_tag is silently ignored
    same = cap.with_tag("in", "media:bytes")
    assert same.in_spec() == MEDIA_VOID, "with_tag must not change in_spec"

    same2 = cap.with_tag("out", "media:bytes")
    assert same2.out_spec() == MEDIA_VOID, "with_tag must not change out_spec"


# TEST567: conforms_to_str and accepts_str work with string arguments
def test_567_str_variants():
    cap = CapUrn.from_string(
        'cap:in="media:void";op=test;out="media:void"'
    )

    # accepts_str
    assert cap.accepts_str('cap:in="media:void";op=test;ext=pdf;out="media:void"')
    assert not cap.accepts_str('cap:in="media:void";op=different;out="media:void"')

    # conforms_to_str
    assert cap.conforms_to_str('cap:in="media:void";op=test;out="media:void"')

    # Invalid URN string -> error
    with pytest.raises(Exception):
        cap.accepts_str("invalid")
    with pytest.raises(Exception):
        cap.conforms_to_str("invalid")


# =============================================================================
# Wildcard/Identity Tests (TEST639-TEST653)
# =============================================================================


# TEST639: cap: (empty) defaults to in=media:;out=media:
def test_639_wildcard_empty_cap_defaults():
    cap = CapUrn.from_string("cap:")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"
    assert len(cap.tags) == 0


# TEST640: cap:in defaults out to media:
def test_640_wildcard_in_only_defaults_out():
    cap = CapUrn.from_string("cap:in")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"


# TEST641: cap:out defaults in to media:
def test_641_wildcard_out_only_defaults_in():
    cap = CapUrn.from_string("cap:out")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"


# TEST642: cap:in;out both become media:
def test_642_wildcard_in_out_no_values():
    cap = CapUrn.from_string("cap:in;out")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"


# TEST643: cap:in=*;out=* becomes media:
def test_643_wildcard_explicit_asterisk():
    cap = CapUrn.from_string("cap:in=*;out=*")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"


# TEST644: cap:in=media:bytes;out=* has specific in, wildcard out
def test_644_wildcard_specific_in_wildcard_out():
    cap = CapUrn.from_string("cap:in=media:bytes;out=*")
    assert cap.in_spec() == "media:bytes"
    assert cap.out_spec() == "media:"


# TEST645: cap:in=*;out=media:text has wildcard in, specific out
def test_645_wildcard_in_specific_out():
    cap = CapUrn.from_string("cap:in=*;out=media:text")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:text"


# TEST646: cap:in=foo fails (invalid media URN)
def test_646_wildcard_invalid_in_spec():
    with pytest.raises(CapUrnError):
        CapUrn.from_string("cap:in=foo;out=media:")


# TEST647: cap:in=media:bytes;out=bar fails (invalid media URN)
def test_647_wildcard_invalid_out_spec():
    with pytest.raises(CapUrnError):
        CapUrn.from_string("cap:in=media:bytes;out=bar")


# TEST648: Wildcard in/out match specific caps
def test_648_wildcard_accepts_specific():
    wildcard = CapUrn.from_string("cap:")
    specific = CapUrn.from_string("cap:in=media:bytes;out=media:text")

    assert wildcard.accepts(specific), "Wildcard should accept specific"
    assert specific.conforms_to(wildcard), "Specific should conform to wildcard"


# TEST649: Specificity - wildcard has 0, specific has tag count
def test_649_wildcard_specificity_scoring():
    wildcard = CapUrn.from_string("cap:")
    specific = CapUrn.from_string("cap:in=media:bytes;out=media:text")

    assert wildcard.specificity() == 0, "Wildcard cap should have zero specificity"
    assert specific.specificity() > 0, "Specific cap should have non-zero specificity"


# TEST650: cap:in;out;op=test preserves other tags
def test_650_wildcard_preserve_other_tags():
    cap = CapUrn.from_string("cap:in;out;op=test")
    assert cap.in_spec() == "media:"
    assert cap.out_spec() == "media:"
    assert cap.get_tag("op") == "test"


# TEST651: All identity forms produce the same CapUrn
def test_651_wildcard_identity_forms_equivalent():
    forms = [
        "cap:",
        "cap:in;out",
        "cap:in=*;out=*",
        "cap:in=media:;out=media:",
    ]

    caps = [CapUrn.from_string(f) for f in forms]
    for i in range(len(caps)):
        for j in range(i + 1, len(caps)):
            assert caps[i].in_spec() == caps[j].in_spec(), f"in_spec mismatch: {forms[i]} vs {forms[j]}"
            assert caps[i].out_spec() == caps[j].out_spec(), f"out_spec mismatch: {forms[i]} vs {forms[j]}"
            assert caps[i].accepts(caps[j]), f"{forms[i]} should accept {forms[j]}"
            assert caps[j].accepts(caps[i]), f"{forms[j]} should accept {forms[i]}"


# TEST652: CAP_IDENTITY constant matches identity caps regardless of string form
def test_652_wildcard_cap_identity_constant():
    identity = CapUrn.from_string(CAP_IDENTITY)

    assert identity.in_spec() == "media:"
    assert identity.out_spec() == "media:"

    # Identity accepts anything (no tag constraints)
    specific = CapUrn.from_string('cap:in=media:bytes;out=media:text;op=convert')
    assert identity.accepts(specific), "Identity should accept any cap"
    assert specific.conforms_to(identity), "Specific conforms to identity"


# TEST653: Identity (no tags) does not match specific requests via routing
def test_653_wildcard_identity_routing_isolation():
    identity = CapUrn.from_string("cap:")
    specific_request = CapUrn.from_string('cap:in="media:void";op=test;out="media:void"')

    # For routing: request.accepts(registered_cap)
    # specific_request(op=test) rejects identity (missing op) -> NOT routed to identity
    assert not specific_request.accepts(identity), "Specific request must not accept identity cap"

    # Identity (no tag constraints) accepts the specific request
    assert identity.accepts(specific_request), "Identity pattern accepts any instance"
