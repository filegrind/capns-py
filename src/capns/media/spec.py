"""MediaSpec parsing and media URN resolution

This module provides:
- Media URN resolution (e.g., `media:string` → resolved media spec)
- MediaSpec parsing (canonical form: `text/plain; profile=https://...`)
- MediaSpecDef for defining specs in cap definitions
- MediaValidation for validation rules inherent to media types

## Media URN Format
Media URNs are tagged URNs with "media" prefix, e.g., `media:string`
Built-in primitives are available without explicit declaration.

## MediaSpec Format
Canonical form: `<media-type>; profile=<url>`
Example: `text/plain; profile=https://capns.org/schema/str`
"""

import os
from typing import List, Optional, Any, Dict

from capns.urn.media_urn import MediaUrn


# =============================================================================
# PROFILE URLS (canonical /schema/ path)
# =============================================================================

# Base URL for capns schemas (default, use `get_schema_base()` for configurable version)
SCHEMA_BASE = "https://capns.org/schema"


def get_schema_base() -> str:
    """Get the schema base URL from environment variables or default

    Checks in order:
    1. `CAPNS_SCHEMA_BASE_URL` environment variable
    2. `CAPNS_REGISTRY_URL` environment variable + "/schema"
    3. Default: "https://capns.org/schema"
    """
    schema_url = os.getenv("CAPNS_SCHEMA_BASE_URL")
    if schema_url:
        return schema_url

    registry_url = os.getenv("CAPNS_REGISTRY_URL")
    if registry_url:
        return f"{registry_url}/schema"

    return SCHEMA_BASE


def get_profile_url(profile_name: str) -> str:
    """Get a profile URL for the given profile name

    Example:
        url = get_profile_url("str")  # Returns "{schema_base}/str"
    """
    return f"{get_schema_base()}/{profile_name}"


# Profile URL for string type
PROFILE_STR = "https://capns.org/schema/str"
# Profile URL for integer type
PROFILE_INT = "https://capns.org/schema/int"
# Profile URL for number type
PROFILE_NUM = "https://capns.org/schema/num"
# Profile URL for boolean type
PROFILE_BOOL = "https://capns.org/schema/bool"
# Profile URL for JSON object type
PROFILE_OBJ = "https://capns.org/schema/obj"
# Profile URL for string array type
PROFILE_STR_ARRAY = "https://capns.org/schema/str-array"
# Profile URL for integer array type
PROFILE_INT_ARRAY = "https://capns.org/schema/int-array"
# Profile URL for number array type
PROFILE_NUM_ARRAY = "https://capns.org/schema/num-array"
# Profile URL for boolean array type
PROFILE_BOOL_ARRAY = "https://capns.org/schema/bool-array"
# Profile URL for object array type
PROFILE_OBJ_ARRAY = "https://capns.org/schema/obj-array"
# Profile URL for void (no input)
PROFILE_VOID = "https://capns.org/schema/void"

# =============================================================================
# SEMANTIC CONTENT TYPE PROFILE URLS
# =============================================================================

# Profile URL for image data (png, jpg, gif, etc.)
PROFILE_IMAGE = "https://capns.org/schema/image"
# Profile URL for audio data (wav, mp3, flac, etc.)
PROFILE_AUDIO = "https://capns.org/schema/audio"
# Profile URL for video data (mp4, webm, mov, etc.)
PROFILE_VIDEO = "https://capns.org/schema/video"
# Profile URL for generic text
PROFILE_TEXT = "https://capns.org/schema/text"

# =============================================================================
# DOCUMENT TYPE PROFILE URLS (PRIMARY naming)
# =============================================================================

# Profile URL for PDF documents
PROFILE_PDF = "https://capns.org/schema/pdf"
# Profile URL for EPUB documents
PROFILE_EPUB = "https://capns.org/schema/epub"

# =============================================================================
# TEXT FORMAT TYPE PROFILE URLS (PRIMARY naming)
# =============================================================================

# Profile URL for Markdown text
PROFILE_MD = "https://capns.org/schema/md"
# Profile URL for plain text
PROFILE_TXT = "https://capns.org/schema/txt"
# Profile URL for reStructuredText
PROFILE_RST = "https://capns.org/schema/rst"
# Profile URL for log files
PROFILE_LOG = "https://capns.org/schema/log"
# Profile URL for HTML documents
PROFILE_HTML = "https://capns.org/schema/html"
# Profile URL for XML documents
PROFILE_XML = "https://capns.org/schema/xml"
# Profile URL for JSON data
PROFILE_JSON = "https://capns.org/schema/json"
# Profile URL for YAML data
PROFILE_YAML = "https://capns.org/schema/yaml"

# =============================================================================
# CAPNS OUTPUT PROFILE URLS
# =============================================================================

# Profile URL for model download output
PROFILE_CAPNS_DOWNLOAD_OUTPUT = "https://capns.org/schema/download-output"
# Profile URL for model load output
PROFILE_CAPNS_LOAD_OUTPUT = "https://capns.org/schema/load-output"
# Profile URL for model unload output
PROFILE_CAPNS_UNLOAD_OUTPUT = "https://capns.org/schema/unload-output"
# Profile URL for model list output
PROFILE_CAPNS_LIST_OUTPUT = "https://capns.org/schema/model-list"
# Profile URL for model status output
PROFILE_CAPNS_STATUS_OUTPUT = "https://capns.org/schema/status-output"
# Profile URL for model contents output
PROFILE_CAPNS_CONTENTS_OUTPUT = "https://capns.org/schema/contents-output"
# Profile URL for embeddings generate output
PROFILE_CAPNS_GENERATE_OUTPUT = "https://capns.org/schema/embeddings"
# Profile URL for structured query output
PROFILE_CAPNS_STRUCTURED_QUERY_OUTPUT = "https://capns.org/schema/structured-query-output"
# Profile URL for questions array
PROFILE_CAPNS_QUESTIONS_ARRAY = "https://capns.org/schema/questions-array"


# =============================================================================
# MEDIA VALIDATION (for media spec definitions)
# =============================================================================


class MediaValidation:
    """Validation rules for media types

    These rules are inherent to the semantic media type and are defined
    in the media spec, not on individual arguments or outputs.
    """

    def __init__(
        self,
        min: Optional[float] = None,
        max: Optional[float] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        allowed_values: Optional[List[str]] = None,
    ):
        self.min = min
        self.max = max
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.allowed_values = allowed_values

    def is_empty(self) -> bool:
        """Check if all validation fields are empty/None"""
        return (
            self.min is None
            and self.max is None
            and self.min_length is None
            and self.max_length is None
            and self.pattern is None
            and self.allowed_values is None
        )

    @staticmethod
    def numeric_range(min: Optional[float], max: Optional[float]) -> "MediaValidation":
        """Create validation with min/max numeric constraints"""
        return MediaValidation(min=min, max=max)

    @staticmethod
    def string_length(
        min_length: Optional[int], max_length: Optional[int]
    ) -> "MediaValidation":
        """Create validation with string length constraints"""
        return MediaValidation(min_length=min_length, max_length=max_length)

    @staticmethod
    def with_pattern(pattern: str) -> "MediaValidation":
        """Create validation with pattern"""
        return MediaValidation(pattern=pattern)

    @staticmethod
    def with_allowed_values(values: List[str]) -> "MediaValidation":
        """Create validation with allowed values"""
        return MediaValidation(allowed_values=values)

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        result = {}
        if self.min is not None:
            result["min"] = self.min
        if self.max is not None:
            result["max"] = self.max
        if self.min_length is not None:
            result["min_length"] = self.min_length
        if self.max_length is not None:
            result["max_length"] = self.max_length
        if self.pattern is not None:
            result["pattern"] = self.pattern
        if self.allowed_values is not None:
            result["allowed_values"] = self.allowed_values
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "MediaValidation":
        """Parse from dict"""
        return cls(
            min=data.get("min"),
            max=data.get("max"),
            min_length=data.get("min_length"),
            max_length=data.get("max_length"),
            pattern=data.get("pattern"),
            allowed_values=data.get("allowed_values"),
        )

    def __eq__(self, other) -> bool:
        if not isinstance(other, MediaValidation):
            return False
        return (
            self.min == other.min
            and self.max == other.max
            and self.min_length == other.min_length
            and self.max_length == other.max_length
            and self.pattern == other.pattern
            and self.allowed_values == other.allowed_values
        )


# =============================================================================
# MEDIA SPEC DEFINITION (for cap definitions)
# =============================================================================


class MediaSpecDef:
    """Media spec definition - can be string (compact) or object (rich)

    Used in the `media_specs` map of a cap definition.

    Media spec definition for inline media_specs in cap definitions.

    This is the same structure as media spec JSON files in the registry.
    Each media spec has a unique URN that identifies it.
    """

    def __init__(
        self,
        urn: str,
        media_type: str,
        title: str,
        profile_uri: Optional[str] = None,
        schema: Optional[Any] = None,
        description: Optional[str] = None,
        validation: Optional[MediaValidation] = None,
        metadata: Optional[Any] = None,
        extensions: Optional[List[str]] = None,
    ):
        """Create a new media spec definition

        Args:
            urn: The media URN identifier (e.g., "media:pdf;binary")
            media_type: The MIME media type (e.g., "application/json", "text/plain")
            title: Human-readable title for the media type (required)
            profile_uri: Optional profile URI for schema reference
            schema: Optional local JSON Schema for validation
            description: Optional description of the media type
            validation: Optional validation rules for this media type
            metadata: Optional metadata (arbitrary key-value pairs for display/categorization)
            extensions: File extensions for storing this media type (e.g., ["pdf"], ["jpg", "jpeg"])
        """
        self.urn = urn
        self.media_type = media_type
        self.title = title
        self.profile_uri = profile_uri
        self.schema = schema
        self.description = description
        self.validation = validation
        self.metadata = metadata
        self.extensions = extensions or []

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        result = {
            "urn": self.urn,
            "media_type": self.media_type,
            "title": self.title,
        }
        if self.profile_uri is not None:
            result["profile_uri"] = self.profile_uri
        if self.schema is not None:
            result["schema"] = self.schema
        if self.description is not None:
            result["description"] = self.description
        if self.validation is not None:
            result["validation"] = self.validation.to_dict()
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.extensions:
            result["extensions"] = self.extensions
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "MediaSpecDef":
        """Parse from dict"""
        validation = None
        if "validation" in data:
            validation = MediaValidation.from_dict(data["validation"])

        return cls(
            urn=data["urn"],
            media_type=data["media_type"],
            title=data["title"],
            profile_uri=data.get("profile_uri"),
            schema=data.get("schema"),
            description=data.get("description"),
            validation=validation,
            metadata=data.get("metadata"),
            extensions=data.get("extensions", []),
        )

    def __eq__(self, other) -> bool:
        if not isinstance(other, MediaSpecDef):
            return False
        return (
            self.urn == other.urn
            and self.media_type == other.media_type
            and self.title == other.title
            and self.profile_uri == other.profile_uri
            and self.schema == other.schema
            and self.description == other.description
            and self.validation == other.validation
            and self.metadata == other.metadata
            and self.extensions == other.extensions
        )


# =============================================================================
# RESOLVED MEDIA SPEC
# =============================================================================


class ResolvedMediaSpec:
    """Fully resolved media spec with all fields populated

    This is the result of resolving a media URN through the media_specs table
    or from a built-in definition.
    """

    def __init__(
        self,
        media_urn: str,
        media_type: str,
        profile_uri: Optional[str] = None,
        schema: Optional[Any] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        validation: Optional[MediaValidation] = None,
        metadata: Optional[Any] = None,
        extensions: Optional[List[str]] = None,
    ):
        """Create a resolved media spec

        Args:
            media_urn: The media URN that was resolved
            media_type: The MIME media type (e.g., "application/json", "text/plain")
            profile_uri: Optional profile URI
            schema: Optional local JSON Schema for validation
            title: Display-friendly title for the media type
            description: Optional description of the media type
            validation: Optional validation rules from the media spec definition
            metadata: Optional metadata (arbitrary key-value pairs for display/categorization)
            extensions: File extensions for storing this media type (e.g., ["pdf"], ["jpg", "jpeg"])
        """
        self.media_urn = media_urn
        self.media_type = media_type
        self.profile_uri = profile_uri
        self.schema = schema
        self.title = title
        self.description = description
        self.validation = validation
        self.metadata = metadata
        self.extensions = extensions or []

    def _parse_media_urn(self) -> MediaUrn:
        """Parse the media URN, raising if invalid (should never happen for resolved specs)"""
        return MediaUrn.from_string(self.media_urn)

    def is_binary(self) -> bool:
        """Check if this represents binary (non-text) data.
        Returns True if the "textable" marker tag is NOT present in the source media URN.
        """
        return self._parse_media_urn().is_binary()

    def is_map(self) -> bool:
        """Check if this represents a map/object structure (form=map).
        This indicates a key-value structure, regardless of representation format.
        """
        return self._parse_media_urn().is_map()

    def is_scalar(self) -> bool:
        """Check if this represents a scalar value (form=scalar).
        This indicates a single value, not a collection.
        """
        return self._parse_media_urn().is_scalar()

    def is_list(self) -> bool:
        """Check if this represents a list/array structure (form=list).
        This indicates an ordered collection of values.
        """
        return self._parse_media_urn().is_list()

    def is_structured(self) -> bool:
        """Check if this represents structured data (map or list).
        Structured data can be serialized as JSON when transmitted as text.
        Note: This does NOT check for the explicit `json` tag - use is_json() for that.
        """
        return self.is_map() or self.is_list()

    def is_json(self) -> bool:
        """Check if this represents JSON representation specifically.
        Returns true if the "json" marker tag is present in the source media URN.
        Note: This only checks for explicit JSON format marker.
        For checking if data is structured (map/list), use is_structured().
        """
        return self._parse_media_urn().is_json()

    def is_text(self) -> bool:
        """Check if this represents text data.
        Returns true if the "textable" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_text()

    def is_image(self) -> bool:
        """Check if this represents image data.
        Returns true if the "image" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_image()

    def is_audio(self) -> bool:
        """Check if this represents audio data.
        Returns true if the "audio" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_audio()

    def is_video(self) -> bool:
        """Check if this represents video data.
        Returns true if the "video" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_video()

    def is_numeric(self) -> bool:
        """Check if this represents numeric data.
        Returns true if the "numeric" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_numeric()

    def is_bool(self) -> bool:
        """Check if this represents boolean data.
        Returns true if the "bool" marker tag is present in the source media URN.
        """
        return self._parse_media_urn().is_bool()

    def __eq__(self, other) -> bool:
        if not isinstance(other, ResolvedMediaSpec):
            return False
        return (
            self.media_urn == other.media_urn
            and self.media_type == other.media_type
            and self.profile_uri == other.profile_uri
            and self.schema == other.schema
            and self.title == other.title
            and self.description == other.description
            and self.validation == other.validation
            and self.metadata == other.metadata
            and self.extensions == other.extensions
        )


# =============================================================================
# MEDIA URN RESOLUTION
# =============================================================================


class MediaSpecError(Exception):
    """Base exception for media spec errors"""
    pass


class UnresolvableMediaUrn(MediaSpecError):
    """Media URN cannot be resolved (not in media_specs and not in registry)"""
    pass


class DuplicateMediaUrn(MediaSpecError):
    """Duplicate media URN in media_specs array"""
    pass


async def resolve_media_urn(
    media_urn: str,
    media_specs: Optional[List[MediaSpecDef]],
    registry: "capns.media_registry.MediaUrnRegistry",
) -> ResolvedMediaSpec:
    """Resolve a media URN to a full media spec definition.

    This is the SINGLE resolution path for all media URN lookups.

    Resolution order:
    1. Cap's local `media_specs` array (HIGHEST - cap-specific definitions)
    2. Registry's local cache (bundled standard specs)
    3. Online registry fetch (with graceful degradation if unreachable)
    4. If none resolve → Error

    Args:
        media_urn: The media URN to resolve (e.g., "media:textable;form=scalar")
        media_specs: Optional media_specs array from the cap definition
        registry: The MediaUrnRegistry for cache and remote lookups

    Returns:
        The resolved media spec

    Raises:
        UnresolvableMediaUrn: If the media URN cannot be resolved from any source
    """
    # 1. First, try cap's local media_specs (highest priority - cap-specific definitions)
    if media_specs:
        for spec_def in media_specs:
            if spec_def.urn == media_urn:
                return ResolvedMediaSpec(
                    media_urn=spec_def.urn,
                    media_type=spec_def.media_type,
                    profile_uri=spec_def.profile_uri,
                    schema=spec_def.schema,
                    title=spec_def.title,
                    description=spec_def.description,
                    validation=spec_def.validation,
                    metadata=spec_def.metadata,
                    extensions=spec_def.extensions,
                )

    # 2. Try registry (checks local cache first, then online with graceful degradation)
    try:
        stored_spec = await registry.get_media_spec(media_urn)
        return ResolvedMediaSpec(
            media_urn=media_urn,
            media_type=stored_spec.media_type,
            profile_uri=stored_spec.profile_uri,
            schema=stored_spec.schema,
            title=stored_spec.title,
            description=stored_spec.description,
            validation=(
                MediaValidation.from_dict(stored_spec.validation)
                if stored_spec.validation
                else None
            ),
            metadata=stored_spec.metadata,
            extensions=stored_spec.extensions,
        )
    except Exception as e:
        # Registry lookup failed (not in cache, online unreachable or not found)
        # Log and continue to error
        print(
            f"[WARN] Media URN '{media_urn}' not found in registry: {e} - "
            f"ensure it's defined in capns-dot-org/standard/media/"
        )

    # Fail - not found in any source
    raise UnresolvableMediaUrn(
        f"cannot resolve media URN '{media_urn}' - not found in cap's media_specs or registry"
    )


def validate_media_specs_no_duplicates(media_specs: List[MediaSpecDef]) -> None:
    """Validate that media_specs array has no duplicate URNs.

    Args:
        media_specs: The media_specs array to validate

    Raises:
        DuplicateMediaUrn: If any URN appears more than once
    """
    seen = set()
    for spec in media_specs:
        if spec.urn in seen:
            raise DuplicateMediaUrn(spec.urn)
        seen.add(spec.urn)
