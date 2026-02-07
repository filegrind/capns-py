"""Standard capability URN builders

This module provides standard capability URN builders used across
all MACINA providers. These are the single source of truth for URN construction.
"""

from typing import Optional
from capns.cap_urn import CapUrn, CapUrnBuilder
from capns.media_urn import (
    # Primitives
    MEDIA_STRING,
    MEDIA_INTEGER,
    MEDIA_BOOLEAN,
    MEDIA_OBJECT,
    MEDIA_BINARY,
    # Semantic media types
    MEDIA_PNG,
    # Document types
    MEDIA_PDF,
    MEDIA_EPUB,
    # Text format types
    MEDIA_MD,
    MEDIA_TXT,
    MEDIA_RST,
    MEDIA_LOG,
    # Semantic input types
    MEDIA_FRONTMATTER_TEXT,
    MEDIA_MODEL_SPEC,
    MEDIA_MODEL_REPO,
    MEDIA_JSON_SCHEMA,
    # Semantic output types
    MEDIA_IMAGE_THUMBNAIL,
    # CAPNS output types
    MEDIA_MODEL_DIM,
    MEDIA_DOWNLOAD_OUTPUT,
    MEDIA_LIST_OUTPUT,
    MEDIA_STATUS_OUTPUT,
    MEDIA_CONTENTS_OUTPUT,
    MEDIA_AVAILABILITY_OUTPUT,
    MEDIA_PATH_OUTPUT,
    MEDIA_EMBEDDING_VECTOR,
    MEDIA_JSON,
    MEDIA_LLM_INFERENCE_OUTPUT,
    MEDIA_DECISION,
    MEDIA_DECISION_ARRAY,
    MEDIA_DISBOUND_PAGE,
    MEDIA_FILE_METADATA,
    MEDIA_DOCUMENT_OUTLINE,
)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def input_media_urn_for_ext(ext: Optional[str]) -> str:
    """Get the input media URN for a file extension

    Uses PRIMARY type naming where the type IS the format.
    - Document files (pdf, epub): type=pdf, type=epub
    - Text format files (md, txt, rst, log): type=md, type=txt, etc.
    - Generic/unknown: type=binary (fallback)
    """
    if ext is None:
        return MEDIA_BINARY

    ext_lower = ext.lower()

    # Document types (PRIMARY naming)
    if ext_lower == "pdf":
        return MEDIA_PDF
    elif ext_lower == "epub":
        return MEDIA_EPUB
    # Text format types (PRIMARY naming)
    elif ext_lower == "md":
        return MEDIA_MD
    elif ext_lower == "txt":
        return MEDIA_TXT
    elif ext_lower == "rst":
        return MEDIA_RST
    elif ext_lower == "log":
        return MEDIA_LOG
    # Generic text
    elif ext_lower == "text":
        return MEDIA_STRING
    # Fallback
    else:
        return MEDIA_BINARY


# =============================================================================
# URN BUILDER FUNCTIONS
# =============================================================================
# These are the SINGLE SOURCE OF TRUTH for URN construction.


# -----------------------------------------------------------------------------
# LLM URN BUILDERS
# -----------------------------------------------------------------------------


def llm_conversation_urn(lang_code: str) -> CapUrn:
    """Build URN for conversation capability"""
    return (
        CapUrnBuilder()
        .tag("op", "conversation")
        .tag("unconstrained", "*")  # solo_tag equivalent
        .tag("language", lang_code)
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_LLM_INFERENCE_OUTPUT)
        .build()
    )


def llm_multiplechoice_urn(lang_code: str) -> CapUrn:
    """Build URN for multiplechoice capability"""
    return (
        CapUrnBuilder()
        .tag("op", "multiplechoice")
        .tag("constrained", "*")
        .tag("language", lang_code)
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_LLM_INFERENCE_OUTPUT)
        .build()
    )


def llm_codegeneration_urn(lang_code: str) -> CapUrn:
    """Build URN for codegeneration capability"""
    return (
        CapUrnBuilder()
        .tag("op", "codegeneration")
        .tag("constrained", "*")
        .tag("language", lang_code)
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_LLM_INFERENCE_OUTPUT)
        .build()
    )


def llm_creative_urn(lang_code: str) -> CapUrn:
    """Build URN for creative capability"""
    return (
        CapUrnBuilder()
        .tag("op", "creative")
        .tag("constrained", "*")
        .tag("language", lang_code)
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_LLM_INFERENCE_OUTPUT)
        .build()
    )


def llm_summarization_urn(lang_code: str) -> CapUrn:
    """Build URN for summarization capability"""
    return (
        CapUrnBuilder()
        .tag("op", "summarization")
        .tag("constrained", "*")
        .tag("language", lang_code)
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_LLM_INFERENCE_OUTPUT)
        .build()
    )


# -----------------------------------------------------------------------------
# EMBEDDING URN BUILDERS
# -----------------------------------------------------------------------------


def embeddings_dimensions_urn() -> CapUrn:
    """Build URN for embeddings-dimensions capability"""
    return (
        CapUrnBuilder()
        .tag("op", "embeddings_dimensions")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_MODEL_DIM)
        .build()
    )


def embeddings_generation_urn() -> CapUrn:
    """Build URN for text embeddings-generation capability"""
    return (
        CapUrnBuilder()
        .tag("op", "generate_embeddings")
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_EMBEDDING_VECTOR)
        .build()
    )


def image_embeddings_generation_urn() -> CapUrn:
    """Build URN for image embeddings-generation capability"""
    return (
        CapUrnBuilder()
        .tag("op", "generate_image_embeddings")
        .tag("ml-model", "*")
        .tag("candle", "*")
        .in_spec(MEDIA_PNG)
        .out_spec(MEDIA_EMBEDDING_VECTOR)
        .build()
    )


# -----------------------------------------------------------------------------
# MODEL MANAGEMENT URN BUILDERS
# -----------------------------------------------------------------------------


def model_download_urn() -> CapUrn:
    """Build URN for model-download capability"""
    return (
        CapUrnBuilder()
        .tag("op", "download-model")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_DOWNLOAD_OUTPUT)
        .build()
    )


def model_list_urn() -> CapUrn:
    """Build URN for model-list capability"""
    return (
        CapUrnBuilder()
        .tag("op", "list-models")
        .in_spec(MEDIA_MODEL_REPO)
        .out_spec(MEDIA_LIST_OUTPUT)
        .build()
    )


def model_status_urn() -> CapUrn:
    """Build URN for model-status capability"""
    return (
        CapUrnBuilder()
        .tag("op", "model-status")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_STATUS_OUTPUT)
        .build()
    )


def model_contents_urn() -> CapUrn:
    """Build URN for model-contents capability"""
    return (
        CapUrnBuilder()
        .tag("op", "model-contents")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_CONTENTS_OUTPUT)
        .build()
    )


def model_availability_urn() -> CapUrn:
    """Build URN for model-availability capability"""
    return (
        CapUrnBuilder()
        .tag("op", "model-availability")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_AVAILABILITY_OUTPUT)
        .build()
    )


def model_path_urn() -> CapUrn:
    """Build URN for model-path capability"""
    return (
        CapUrnBuilder()
        .tag("op", "model-path")
        .in_spec(MEDIA_MODEL_SPEC)
        .out_spec(MEDIA_PATH_OUTPUT)
        .build()
    )


# -----------------------------------------------------------------------------
# DOCUMENT PROCESSING URN BUILDERS
# -----------------------------------------------------------------------------


def generate_thumbnail_urn(ext: Optional[str] = None) -> CapUrn:
    """Build URN for generate-thumbnail capability

    If ext is provided, builds a URN with appropriate input type for that extension.
    If ext is None, builds a generic fallback URN that matches binary files.
    """
    input_spec = input_media_urn_for_ext(ext)

    return (
        CapUrnBuilder()
        .tag("op", "generate_thumbnail")
        .in_spec(input_spec)
        .out_spec(MEDIA_IMAGE_THUMBNAIL)
        .build()
    )


def disbind_urn(ext: Optional[str] = None) -> CapUrn:
    """Build URN for disbind capability"""
    return (
        CapUrnBuilder()
        .tag("op", "disbind")
        .in_spec(input_media_urn_for_ext(ext))
        .out_spec(MEDIA_DISBOUND_PAGE)
        .build()
    )


def extract_metadata_urn(ext: Optional[str] = None) -> CapUrn:
    """Build URN for extract-metadata capability"""
    return (
        CapUrnBuilder()
        .tag("op", "extract_metadata")
        .in_spec(input_media_urn_for_ext(ext))
        .out_spec(MEDIA_FILE_METADATA)
        .build()
    )


def extract_outline_urn(ext: Optional[str] = None) -> CapUrn:
    """Build URN for extract-outline capability"""
    return (
        CapUrnBuilder()
        .tag("op", "extract_outline")
        .in_spec(input_media_urn_for_ext(ext))
        .out_spec(MEDIA_DOCUMENT_OUTLINE)
        .build()
    )


# -----------------------------------------------------------------------------
# TEXT PROCESSING URN BUILDERS
# -----------------------------------------------------------------------------


def frontmatter_summarization_urn(lang_code: str) -> CapUrn:
    """Build URN for frontmatter-summarization capability"""
    return (
        CapUrnBuilder()
        .tag("op", "generate_frontmatter_summary")
        .tag("language", lang_code)
        .tag("constrained", "*")
        .in_spec(MEDIA_FRONTMATTER_TEXT)
        .out_spec(MEDIA_STRING)
        .build()
    )


def structured_query_urn(lang_code: str) -> CapUrn:
    """Build URN for structured-query capability"""
    return (
        CapUrnBuilder()
        .tag("op", "query_structured")
        .tag("language", lang_code)
        .tag("constrained", "*")
        .in_spec(MEDIA_JSON_SCHEMA)
        .out_spec(MEDIA_JSON)
        .build()
    )


def bit_choice_urn(lang_code: str) -> CapUrn:
    """Build URN for bit-choice capability"""
    return (
        CapUrnBuilder()
        .tag("op", "choose_bit")
        .tag("language", lang_code)
        .tag("constrained", "*")
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_DECISION)
        .build()
    )


def bit_choices_urn(lang_code: str) -> CapUrn:
    """Build URN for bit-choices capability"""
    return (
        CapUrnBuilder()
        .tag("op", "choose_bits")
        .tag("language", lang_code)
        .tag("constrained", "*")
        .in_spec(MEDIA_STRING)
        .out_spec(MEDIA_DECISION_ARRAY)
        .build()
    )
