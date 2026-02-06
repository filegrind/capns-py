"""Tests for CapUrn - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
import hashlib
from capns import (
    CapUrn,
    CapUrnError,
    CapUrnBuilder,
    MEDIA_VOID,
    MEDIA_OBJECT,
    MEDIA_STRING,
    MEDIA_INTEGER,
    MEDIA_BINARY,
)


def test_urn(tags_part: str) -> str:
    """Helper to build cap URN with standard in/out for testing"""
    return f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";{tags_part}'


# TEST001: Test that cap URN is created with tags parsed correctly and direction specs accessible
def test_cap_urn_creation():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf;target=thumbnail"))
    assert cap.get_tag("op") == "generate"
    assert cap.get_tag("target") == "thumbnail"
    assert cap.get_tag("ext") == "pdf"
    # Direction specs are required and accessible
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT


# TEST002: Test that missing 'in' spec fails with MissingInSpec, missing 'out' fails with MissingOutSpec
def test_direction_specs_required():
    # Missing 'in' should fail
    with pytest.raises(CapUrnError, match="Missing required 'in' spec"):
        CapUrn.from_string(f'cap:out="{MEDIA_OBJECT}";op=test')

    # Missing 'out' should fail
    with pytest.raises(CapUrnError, match="Missing required 'out' spec"):
        CapUrn.from_string(f'cap:in="{MEDIA_VOID}";op=test')

    # Both present should succeed
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=test')
    assert cap is not None


# TEST003: Test that direction specs must match exactly, different in/out types don't match, wildcard matches any
def test_direction_matching():
    in_str = "media:textable;form=scalar"  # MEDIA_STRING
    out_obj = "media:form=map;textable"  # MEDIA_OBJECT
    in_bin = "media:bytes"  # MEDIA_BINARY
    out_int = "media:integer;textable;numeric;form=scalar"  # MEDIA_INTEGER

    # Direction specs must match for caps to match
    cap1 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_obj}"')
    cap2 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_obj}"')
    assert cap1.matches(cap2)

    # Different in_urn should not match
    cap3 = CapUrn.from_string(f'cap:in="{in_bin}";op=test;out="{out_obj}"')
    assert not cap1.matches(cap3)

    # Different out_urn should not match
    cap4 = CapUrn.from_string(f'cap:in="{in_str}";op=test;out="{out_int}"')
    assert not cap1.matches(cap4)

    # Wildcard in direction should match
    cap5 = CapUrn.from_string(f'cap:in=*;op=test;out="{out_obj}"')
    assert cap1.matches(cap5)
    assert cap5.matches(cap1)


# TEST004: Test that unquoted keys and values are normalized to lowercase
def test_unquoted_values_lowercased():
    # Unquoted values are normalized to lowercase
    cap = CapUrn.from_string(test_urn("OP=Generate;EXT=PDF;Target=Thumbnail"))

    # Keys are always lowercase
    assert cap.get_tag("op") == "generate"
    assert cap.get_tag("ext") == "pdf"
    assert cap.get_tag("target") == "thumbnail"

    # Key lookup is case-insensitive
    assert cap.get_tag("OP") == "generate"
    assert cap.get_tag("Op") == "generate"

    # Both URNs parse to same lowercase values (same tags, same values)
    cap2 = CapUrn.from_string(test_urn("op=generate;ext=pdf;target=thumbnail"))
    assert cap.to_string() == cap2.to_string()
    assert cap == cap2


# TEST005: Test that quoted values preserve case while unquoted are lowercased
def test_quoted_values_preserve_case():
    # Quoted values preserve their case
    cap = CapUrn.from_string(test_urn(r'key="Value With Spaces"'))
    assert cap.get_tag("key") == "Value With Spaces"

    # Key is still lowercase
    cap2 = CapUrn.from_string(test_urn(r'KEY="Value With Spaces"'))
    assert cap2.get_tag("key") == "Value With Spaces"

    # Unquoted vs quoted case difference
    unquoted = CapUrn.from_string(test_urn("key=UPPERCASE"))
    quoted = CapUrn.from_string(test_urn(r'key="UPPERCASE"'))
    assert unquoted.get_tag("key") == "uppercase"  # lowercase
    assert quoted.get_tag("key") == "UPPERCASE"  # preserved
    assert unquoted != quoted  # NOT equal


# TEST006: Test that quoted values can contain special characters (semicolons, equals, spaces)
def test_quoted_value_special_chars():
    # Semicolons in quoted values
    cap = CapUrn.from_string(test_urn(r'key="value;with;semicolons"'))
    assert cap.get_tag("key") == "value;with;semicolons"

    # Equals in quoted values
    cap2 = CapUrn.from_string(test_urn(r'key="value=with=equals"'))
    assert cap2.get_tag("key") == "value=with=equals"

    # Spaces in quoted values
    cap3 = CapUrn.from_string(test_urn(r'key="hello world"'))
    assert cap3.get_tag("key") == "hello world"


# TEST007: Test that escape sequences in quoted values (\" and \\) are parsed correctly
def test_quoted_value_escape_sequences():
    # Escaped quotes
    cap = CapUrn.from_string(test_urn(r'key="value\"quoted\""'))
    assert cap.get_tag("key") == r'value"quoted"'

    # Escaped backslashes
    cap2 = CapUrn.from_string(test_urn(r'key="path\\file"'))
    assert cap2.get_tag("key") == r'path\file'

    # Mixed escapes
    cap3 = CapUrn.from_string(test_urn(r'key="say \"hello\\world\""'))
    assert cap3.get_tag("key") == r'say "hello\world"'


# TEST008: Test that mixed quoted and unquoted values in same URN parse correctly
def test_mixed_quoted_unquoted():
    cap = CapUrn.from_string(test_urn(r'a="Quoted";b=simple'))
    assert cap.get_tag("a") == "Quoted"
    assert cap.get_tag("b") == "simple"


# TEST009: Test that unterminated quote produces UnterminatedQuote error
def test_unterminated_quote_error():
    with pytest.raises(CapUrnError, match="Unterminated quote"):
        CapUrn.from_string(test_urn(r'key="unterminated'))


# TEST010: Test that invalid escape sequences (like \n, \x) produce InvalidEscapeSequence error
def test_invalid_escape_sequence_error():
    with pytest.raises(CapUrnError, match="Invalid escape sequence"):
        CapUrn.from_string(test_urn(r'key="bad\n"'))

    # Invalid escape at end
    with pytest.raises(CapUrnError, match="Invalid escape sequence"):
        CapUrn.from_string(test_urn(r'key="bad\x"'))


# TEST011: Test that serialization uses smart quoting (no quotes for simple lowercase, quotes for special chars/uppercase)
def test_serialization_smart_quoting():
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
def test_round_trip_simple():
    original = test_urn("op=generate;ext=pdf")
    cap = CapUrn.from_string(original)
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed


# TEST013: Test that quoted values round-trip preserving case and spaces
def test_round_trip_quoted():
    original = test_urn(r'key="Value With Spaces"')
    cap = CapUrn.from_string(original)
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed
    assert reparsed.get_tag("key") == "Value With Spaces"


# TEST014: Test that escape sequences round-trip correctly
def test_round_trip_escapes():
    original = test_urn(r'key="value\"with\\escapes"')
    cap = CapUrn.from_string(original)
    assert cap.get_tag("key") == r'value"with\escapes'
    serialized = cap.to_string()
    reparsed = CapUrn.from_string(serialized)
    assert cap == reparsed


# TEST015: Test that cap: prefix is required and case-insensitive
def test_cap_prefix_required():
    # Missing cap: prefix should fail
    with pytest.raises(CapUrnError):
        CapUrn.from_string(f'in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=generate')

    # Valid cap: prefix should work
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap.get_tag("op") == "generate"

    # Case-insensitive prefix
    cap2 = CapUrn.from_string(f'CAP:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}";op=generate')
    assert cap2.get_tag("op") == "generate"


# TEST016: Test that trailing semicolon is equivalent (same hash, same string, matches)
def test_trailing_semicolon_equivalence():
    # Both with and without trailing semicolon should be equivalent
    cap1 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(test_urn("op=generate;ext=pdf") + ";")

    # They should be equal
    assert cap1 == cap2

    # They should have same hash
    assert hash(cap1) == hash(cap2)

    # They should have same string representation (canonical form)
    assert cap1.to_string() == cap2.to_string()

    # They should match each other
    assert cap1.matches(cap2)
    assert cap2.matches(cap1)


# TEST017: Test tag matching: exact match, subset match, wildcard match, value mismatch
def test_tag_matching():
    # Exact match
    cap1 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap1.matches(cap2)

    # Subset: cap1 has extra tag, cap2 doesn't specify it -> cap1 can handle cap2
    cap3 = CapUrn.from_string(test_urn("op=generate"))  # Missing ext tag
    assert cap1.matches(cap3)

    # Wildcard: cap has wildcard value -> can handle any value
    cap4 = CapUrn.from_string(test_urn("op=*;ext=pdf"))
    assert cap4.matches(cap1)  # cap4 can handle cap1

    # Value mismatch
    cap5 = CapUrn.from_string(test_urn("op=generate;ext=docx"))
    assert not cap1.matches(cap5)


# TEST018: Test that quoted values with different case do NOT match (case-sensitive)
def test_quoted_values_case_sensitive():
    cap1 = CapUrn.from_string(test_urn(r'key="CaseSensitive"'))
    cap2 = CapUrn.from_string(test_urn(r'key="casesensitive"'))
    assert not cap1.matches(cap2)


# TEST019: Test that missing tags are treated as wildcards (cap without tag matches any value for that tag)
def test_missing_tags_as_wildcards():
    # Cap without ext tag can handle request with any ext value
    cap = CapUrn.from_string(test_urn("op=generate"))  # No ext tag
    request1 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    request2 = CapUrn.from_string(test_urn("op=generate;ext=docx"))

    # Cap can handle both requests (missing tag is wildcard)
    assert cap.matches(request1)
    assert cap.matches(request2)


# TEST020: Test specificity calculation (direction specs use MediaUrn tag count, wildcards don't count)
def test_specificity_calculation():
    # More tags in direction specs = higher specificity
    cap1 = CapUrn.from_string(f'cap:in="media:string";out="media:object";op=test')
    cap2 = CapUrn.from_string(f'cap:in="media:textable;form=scalar";out="media:form=map;textable";op=test')
    # cap2 has more MediaUrn tags, so it's more specific
    assert cap2.specificity() > cap1.specificity()

    # Wildcards in tags don't count
    cap3 = CapUrn.from_string(test_urn("op=generate;ext=*"))
    cap4 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap4.specificity() > cap3.specificity()


# TEST021: Test builder creates cap URN with correct tags and direction specs
def test_builder_creates_cap_urn():
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
def test_builder_requires_direction_specs():
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
def test_builder_key_normalization():
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


# TEST024: Test compatibility checking (missing tags = wildcards, different directions = incompatible)
def test_compatibility_checking():
    # Compatible: same direction specs
    cap1 = CapUrn.from_string(test_urn("op=generate"))
    cap2 = CapUrn.from_string(test_urn("op=convert"))
    assert cap1.is_compatible_with(cap2)

    # Incompatible: different direction specs (both sides)
    cap3 = CapUrn.from_string(f'cap:in="media:bytes";out="media:form=map;textable";op=test')
    cap4 = CapUrn.from_string(f'cap:in="media:textable;form=scalar";out="media:integer;textable;numeric;form=scalar";op=test')
    assert not cap3.is_compatible_with(cap4)


# TEST025: Test find_best_match returns most specific matching cap
def test_find_best_match():
    # This test requires implementing a find_best_match function
    # For now, we test the specificity and matching directly
    caps = [
        CapUrn.from_string(test_urn("op=*")),  # Generic
        CapUrn.from_string(test_urn("op=generate;ext=pdf")),  # Specific
    ]
    request = CapUrn.from_string(test_urn("op=generate;ext=pdf"))

    # Both match, but the second is more specific
    matching = [c for c in caps if c.matches(request)]
    assert len(matching) == 2
    best = max(matching, key=lambda c: c.specificity())
    assert best == caps[1]


# TEST026: Test merge combines tags from both caps, subset keeps only specified tags
def test_merge_and_subset():
    cap1 = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    cap2 = CapUrn.from_string(test_urn("op=convert;target=thumbnail"))

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
def test_with_wildcard_tag():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf"))

    # Wildcard a regular tag
    cap2 = cap.with_wildcard_tag("ext")
    assert cap2.get_tag("ext") == "*"

    # Wildcard in direction
    cap3 = cap.with_wildcard_tag("in")
    assert cap3.in_spec() == "*"

    # Wildcard out direction
    cap4 = cap.with_wildcard_tag("out")
    assert cap4.out_spec() == "*"


# TEST028: Test empty cap URN fails with MissingInSpec
def test_empty_cap_urn_fails():
    with pytest.raises(CapUrnError):
        CapUrn.from_string("cap:")


# TEST029: Test minimal valid cap URN has just in and out, empty tags
def test_minimal_valid_cap_urn():
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";out="{MEDIA_OBJECT}"')
    assert cap.in_spec() == MEDIA_VOID
    assert cap.out_spec() == MEDIA_OBJECT
    assert len(cap.tags) == 0


# TEST030: Test extended characters (forward slashes, colons) in tag values
def test_extended_characters_in_values():
    cap = CapUrn.from_string(test_urn("path=path/to/file;url=http://example.com"))
    assert cap.get_tag("path") == "path/to/file"
    assert cap.get_tag("url") == "http://example.com"


# TEST031: Test wildcard rejected in keys but accepted in values
def test_wildcard_in_keys_and_values():
    # Wildcard in value is accepted
    cap = CapUrn.from_string(test_urn("op=*"))
    assert cap.get_tag("op") == "*"

    # Wildcard in key should fail (handled by tagged-urn)
    with pytest.raises(CapUrnError):
        CapUrn.from_string(test_urn("*=value"))


# TEST032: Test duplicate keys are rejected with DuplicateKey error
def test_duplicate_keys_rejected():
    with pytest.raises(CapUrnError, match="Duplicate"):
        CapUrn.from_string(test_urn("op=generate;op=convert"))


# TEST033: Test pure numeric keys rejected, mixed alphanumeric allowed, numeric values allowed
def test_numeric_keys():
    # Pure numeric key should fail (handled by tagged-urn)
    with pytest.raises(CapUrnError, match="numeric"):
        CapUrn.from_string(test_urn("123=value"))

    # Mixed alphanumeric key is allowed
    cap = CapUrn.from_string(test_urn("key123=value"))
    assert cap.get_tag("key123") == "value"

    # Numeric value is allowed
    cap2 = CapUrn.from_string(test_urn("key=123"))
    assert cap2.get_tag("key") == "123"


# TEST034: Test empty values are rejected
def test_empty_values_rejected():
    # Empty value in builder
    with pytest.raises(CapUrnError, match="Empty value"):
        CapUrnBuilder().in_spec(MEDIA_VOID).out_spec(MEDIA_OBJECT).tag("key", "").build()


# TEST035: Test has_tag is case-sensitive for values, case-insensitive for keys, works for in/out
def test_has_tag_behavior():
    cap = CapUrn.from_string(test_urn(r'key="Value"'))

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
def test_with_tag_preserves_case():
    cap = CapUrn.from_string(test_urn("op=generate"))
    cap2 = cap.with_tag("key", "MixedCase")
    assert cap2.get_tag("key") == "MixedCase"


# TEST037: Test with_tag rejects empty value
def test_with_tag_rejects_empty():
    cap = CapUrn.from_string(test_urn("op=generate"))
    with pytest.raises(CapUrnError, match="Empty value"):
        cap.with_tag("key", "")


# TEST038: Test semantic equivalence of unquoted and quoted simple lowercase values
def test_semantic_equivalence_quoted_unquoted():
    cap1 = CapUrn.from_string(test_urn("key=simple"))
    cap2 = CapUrn.from_string(test_urn(r'key="simple"'))
    # Both should have the same value
    assert cap1.get_tag("key") == cap2.get_tag("key")
    assert cap1 == cap2


# TEST039: Test get_tag returns direction specs (in/out) with case-insensitive lookup
def test_get_tag_direction_specs():
    cap = CapUrn.from_string(test_urn("op=generate"))

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
def test_matching_semantics_test1_exact_match():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap.matches(request), "Test 1: Exact match should succeed"


# TEST041: Matching semantics - cap missing tag matches (implicit wildcard)
def test_matching_semantics_test2_cap_missing_tag():
    cap = CapUrn.from_string(test_urn("op=generate"))
    request = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap.matches(request), "Test 2: Cap missing tag should match (implicit wildcard)"


# TEST042: Matching semantics - cap with extra tag matches
def test_matching_semantics_test3_cap_has_extra_tag():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf;version=2"))
    request = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap.matches(request), "Test 3: Cap with extra tag should match"


# TEST043: Matching semantics - request wildcard matches specific cap value
def test_matching_semantics_test4_request_has_wildcard():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(test_urn("op=generate;ext=*"))
    assert cap.matches(request), "Test 4: Request wildcard should match"


# TEST044: Matching semantics - cap wildcard matches specific request value
def test_matching_semantics_test5_cap_has_wildcard():
    cap = CapUrn.from_string(test_urn("op=generate;ext=*"))
    request = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    assert cap.matches(request), "Test 5: Cap wildcard should match"


# TEST045: Matching semantics - value mismatch does not match
def test_matching_semantics_test6_value_mismatch():
    cap = CapUrn.from_string(test_urn("op=generate;ext=pdf"))
    request = CapUrn.from_string(test_urn("op=generate;ext=docx"))
    assert not cap.matches(request), "Test 6: Value mismatch should not match"


# TEST046: Matching semantics - fallback pattern (cap missing tag = implicit wildcard)
def test_matching_semantics_test7_fallback_pattern():
    in_bin = "media:bytes"
    cap = CapUrn.from_string(f'cap:in="{in_bin}";op=generate_thumbnail;out="{in_bin}"')
    request = CapUrn.from_string(f'cap:ext=wav;in="{in_bin}";op=generate_thumbnail;out="{in_bin}"')
    assert cap.matches(request), "Test 7: Fallback pattern should match (cap missing ext = implicit wildcard)"


# TEST047: Matching semantics - thumbnail fallback with void input
def test_matching_semantics_test7b_thumbnail_void_input():
    out_bin = "media:bytes"
    cap = CapUrn.from_string(f'cap:in="{MEDIA_VOID}";op=generate_thumbnail;out="{out_bin}"')
    request = CapUrn.from_string(f'cap:ext=wav;in="{MEDIA_VOID}";op=generate_thumbnail;out="{out_bin}"')
    assert cap.matches(request), "Test 7b: Thumbnail fallback with void input should match"


# TEST048: Matching semantics - wildcard direction matches anything
def test_matching_semantics_test8_wildcard_direction_matches_anything():
    cap = CapUrn.from_string("cap:in=*;out=*")
    request = CapUrn.from_string(f'cap:ext=pdf;in="media:textable;form=scalar";op=generate;out="{MEDIA_OBJECT}"')
    assert cap.matches(request), "Test 8: Wildcard direction should match any direction"


# TEST049: Matching semantics - cross-dimension independence
def test_matching_semantics_test9_cross_dimension_independence():
    cap = CapUrn.from_string(test_urn("op=generate"))
    request = CapUrn.from_string(test_urn("ext=pdf"))
    assert cap.matches(request), "Test 9: Cross-dimension independence should match"


# TEST050: Matching semantics - direction mismatch prevents matching
def test_matching_semantics_test10_direction_mismatch():
    # media:textable;form=scalar (string) has different tags than media:bytes
    # Neither can provide input for the other (completely different marker tags)
    cap = CapUrn.from_string(f'cap:in="media:textable;form=scalar";op=generate;out="{MEDIA_OBJECT}"')
    request = CapUrn.from_string(f'cap:in="media:bytes";op=generate;out="{MEDIA_OBJECT}"')
    assert not cap.matches(request), "Test 10: Direction mismatch should not match"


# TEST051: Semantic direction matching - generic provider matches specific request
def test_direction_semantic_matching():
    # A cap accepting media:bytes (generic) should match a request with media:pdf;bytes (specific)
    generic_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    pdf_request = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert generic_cap.matches(pdf_request), "Generic bytes provider must match specific pdf;bytes request"

    # Generic cap also matches epub;bytes (any bytes subtype)
    epub_request = CapUrn.from_string(
        'cap:in="media:epub;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert generic_cap.matches(epub_request), "Generic bytes provider must match epub;bytes request"

    # Reverse: specific cap does NOT match generic request
    pdf_cap = CapUrn.from_string(
        'cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    generic_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert not pdf_cap.matches(generic_request), "Specific pdf;bytes cap must NOT match generic bytes request"

    # Incompatible types: pdf cap does NOT match epub request
    assert not pdf_cap.matches(epub_request), "PDF-specific cap must NOT match epub request"

    # Output direction: cap producing more specific output matches less specific request
    specific_out_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    generic_out_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;bytes"'
    )
    assert specific_out_cap.matches(generic_out_request), "Cap producing specific output must satisfy generic request"

    # Reverse output: generic output cap does NOT match specific output request
    generic_out_cap = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;bytes"'
    )
    specific_out_request = CapUrn.from_string(
        'cap:in="media:bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"'
    )
    assert not generic_out_cap.matches(specific_out_request), "Cap producing generic output must NOT satisfy specific request"


# TEST052: Semantic direction specificity - more media URN tags = higher specificity
def test_direction_semantic_specificity():
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
    matching = [c for c in caps if c.matches(pdf_request)]
    best = max(matching, key=lambda c: c.specificity())
    assert best.in_spec() == "media:bytes;pdf", "Must prefer the more specific pdf;bytes provider"
