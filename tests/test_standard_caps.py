"""Tests for standard caps URN builders - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns import CapUrn, MediaUrn
from capns.standard.caps import (
    model_availability_urn,
    model_path_urn,
    llm_conversation_urn,
)
from capns.media_urn import (
    MEDIA_MODEL_SPEC,
    MEDIA_AVAILABILITY_OUTPUT,
    MEDIA_PATH_OUTPUT,
    MEDIA_STRING,
    MEDIA_LLM_INFERENCE_OUTPUT,
)


# TEST307: Test model_availability_urn builds valid cap URN with correct op and media specs
def test_model_availability_urn():
    urn = model_availability_urn()
    assert urn.has_tag("op", "model-availability"), "URN must have op=model-availability"
    assert urn.in_spec() == MEDIA_MODEL_SPEC, "input must be model-spec"
    assert urn.out_spec() == MEDIA_AVAILABILITY_OUTPUT, "output must be availability output"


# TEST308: Test model_path_urn builds valid cap URN with correct op and media specs
def test_model_path_urn():
    urn = model_path_urn()
    assert urn.has_tag("op", "model-path"), "URN must have op=model-path"
    assert urn.in_spec() == MEDIA_MODEL_SPEC, "input must be model-spec"
    assert urn.out_spec() == MEDIA_PATH_OUTPUT, "output must be path output"


# TEST309: Test model_availability_urn and model_path_urn produce distinct URNs
def test_model_availability_and_path_are_distinct():
    avail = model_availability_urn()
    path = model_path_urn()
    assert avail.to_string() != path.to_string(), "availability and path must be distinct cap URNs"


# TEST310: Test llm_conversation_urn uses unconstrained tag (not constrained)
def test_llm_conversation_urn_unconstrained():
    urn = llm_conversation_urn("en")
    assert urn.get_tag("unconstrained") is not None, "LLM conversation URN must have 'unconstrained' tag"
    assert urn.has_tag("op", "conversation"), "must have op=conversation"
    assert urn.has_tag("language", "en"), "must have language=en"


# TEST311: Test llm_conversation_urn in/out specs match the expected media URNs semantically
def test_llm_conversation_urn_specs():
    urn = llm_conversation_urn("fr")

    # Compare semantically via MediaUrn matching (tag order may differ)
    in_spec = MediaUrn.from_string(urn.in_spec())
    expected_in = MediaUrn.from_string(MEDIA_STRING)
    assert in_spec.matches(expected_in), f"in_spec '{urn.in_spec()}' must match MEDIA_STRING '{MEDIA_STRING}'"

    out_spec = MediaUrn.from_string(urn.out_spec())
    expected_out = MediaUrn.from_string(MEDIA_LLM_INFERENCE_OUTPUT)
    assert out_spec.matches(expected_out), f"out_spec '{urn.out_spec()}' must match '{MEDIA_LLM_INFERENCE_OUTPUT}'"


# TEST312: Test all URN builders produce parseable cap URNs
def test_all_urn_builders_produce_valid_urns():
    # Each of these must not raise
    avail = model_availability_urn()
    path = model_path_urn()
    conv = llm_conversation_urn("en")

    # Verify they roundtrip through CapUrn parsing
    avail_str = model_availability_urn().to_string()
    parsed = CapUrn.from_string(avail_str)
    assert parsed is not None, "model_availability_urn must be parseable"

    path_str = model_path_urn().to_string()
    parsed = CapUrn.from_string(path_str)
    assert parsed is not None, "model_path_urn must be parseable"
