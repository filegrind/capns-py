"""Media URN - Data type specification using tagged URN format

Media URNs use the tagged URN format with "media" prefix to describe
data types. They replace the old spec ID system (e.g., `media:string`).

Format: `media:<type>[;subtype=<subtype>][;v=<version>][;profile=<url>][;...]`

Examples:
- `media:string`
- `media:object`
- `media:application;subtype=json;profile="https://example.com/schema"`
- `media:image;subtype=png`

Media URNs are just tagged URNs with the "media" prefix. Comparison and
matching use standard tagged URN semantics.
"""

from typing import Optional
from tagged_urn import TaggedUrn, TaggedUrnBuilder, TaggedUrnError


# =============================================================================
# STANDARD MEDIA URN CONSTANTS
# =============================================================================

# Primitive types - URNs must match base.toml definitions
# Media URN for void (no input/output) - no coercion tags
MEDIA_VOID = "media:void"
# Media URN for string type - textable (can become text), scalar (single value)
MEDIA_STRING = "media:textable;form=scalar"
# Media URN for integer type - textable, numeric (math ops valid), scalar
MEDIA_INTEGER = "media:integer;textable;numeric;form=scalar"
# Media URN for number type - textable, numeric, scalar (no primary type prefix)
MEDIA_NUMBER = "media:textable;numeric;form=scalar"
# Media URN for boolean type - uses "bool" not "boolean" per base.toml
MEDIA_BOOLEAN = "media:bool;textable;form=scalar"
# Media URN for JSON object type - textable (via JSON.stringify), form=map (key-value structure)
MEDIA_OBJECT = "media:form=map;textable"
# Media URN for binary data - binary (raw bytes)
MEDIA_BINARY = "media:bytes"

# Array types - URNs must match base.toml definitions
# Media URN for string array type - textable, list (no primary type prefix)
MEDIA_STRING_ARRAY = "media:textable;form=list"
# Media URN for integer array type - textable, numeric, list (per base.toml:46)
MEDIA_INTEGER_ARRAY = "media:integer;textable;numeric;form=list"
# Media URN for number array type - textable, numeric, list (no primary type prefix)
MEDIA_NUMBER_ARRAY = "media:textable;numeric;form=list"
# Media URN for boolean array type - uses "bool" not "boolean" per base.toml
MEDIA_BOOLEAN_ARRAY = "media:bool;textable;form=list"
# Media URN for object array type - generic list (item type defined in schema)
MEDIA_OBJECT_ARRAY = "media:form=list;textable"

# Semantic media types for specialized content
# Media URN for PNG image data - matches CATALOG: media:image;png;bytes
MEDIA_PNG = "media:image;png;bytes"
# Media URN for audio data (wav, mp3, flac, etc.)
MEDIA_AUDIO = "media:wav;audio;bytes;"
# Media URN for video data (mp4, webm, mov, etc.)
MEDIA_VIDEO = "media:video;bytes"

# Semantic AI input types - distinguished by their purpose/context
# Media URN for audio input containing speech for transcription (Whisper)
MEDIA_AUDIO_SPEECH = "media:audio;wav;bytes;speech"
# Media URN for thumbnail image output
MEDIA_IMAGE_THUMBNAIL = "media:image;png;bytes;thumbnail"

# Collection types for folder hierarchies
# Media URN for a collection (folder with nested structure as form=map)
MEDIA_COLLECTION = "media:collection;form=map"
# Media URN for a flat collection (folder contents as form=list)
MEDIA_COLLECTION_LIST = "media:collection;form=list"

# Document types (PRIMARY naming - type IS the format)
# Media URN for PDF documents
MEDIA_PDF = "media:pdf;bytes"
# Media URN for EPUB documents
MEDIA_EPUB = "media:epub;bytes"

# Text format types (PRIMARY naming - type IS the format)
# Media URN for Markdown text
MEDIA_MD = "media:md;textable"
# Media URN for plain text
MEDIA_TXT = "media:txt;textable"
# Media URN for reStructuredText
MEDIA_RST = "media:rst;textable"
# Media URN for log files
MEDIA_LOG = "media:log;textable"
# Media URN for HTML documents
MEDIA_HTML = "media:html;textable"
# Media URN for XML documents
MEDIA_XML = "media:xml;textable"
# Media URN for JSON data
MEDIA_JSON = "media:json;textable;form=map"
# Media URN for JSON with schema constraint (input for structured queries) - matches CATALOG
MEDIA_JSON_SCHEMA = "media:json;json-schema;textable;form=map"
# Media URN for YAML data
MEDIA_YAML = "media:yaml;textable;form=map"

# File path types - for arguments that represent filesystem paths
# Media URN for a single file path - textable, scalar, and marked as a file-path for special handling
MEDIA_FILE_PATH = "media:file-path;textable;form=scalar"
# Media URN for an array of file paths - textable, list (per file-path.toml)
MEDIA_FILE_PATH_ARRAY = "media:file-path;textable;form=list"

# Semantic text input types - distinguished by their purpose/context
# Media URN for frontmatter text (book metadata)
MEDIA_FRONTMATTER_TEXT = "media:frontmatter;textable;form=scalar"
# Media URN for model spec (provider:model format, HuggingFace name, etc.)
MEDIA_MODEL_SPEC = "media:model-spec;textable;form=scalar"
# Media URN for MLX model path
MEDIA_MLX_MODEL_PATH = "media:mlx-model-path;textable;form=scalar"
# Media URN for model repository (input for list-models) - matches CATALOG
MEDIA_MODEL_REPO = "media:model-repo;textable;form=map"

# CAPNS output types - all form=map structures (JSON objects)
# Media URN for model dimension output - matches CATALOG
MEDIA_MODEL_DIM = "media:model-dim;integer;textable;numeric;form=scalar"
# Media URN for model download output - textable, form=map
MEDIA_DOWNLOAD_OUTPUT = "media:download-result;textable;form=map"
# Media URN for model list output - textable, form=map
MEDIA_LIST_OUTPUT = "media:model-list;textable;form=map"
# Media URN for model status output - textable, form=map
MEDIA_STATUS_OUTPUT = "media:model-status;textable;form=map"
# Media URN for model contents output - textable, form=map
MEDIA_CONTENTS_OUTPUT = "media:model-contents;textable;form=map"
# Media URN for model availability output - textable, form=map
MEDIA_AVAILABILITY_OUTPUT = "media:model-availability;textable;form=map"
# Media URN for model path output - textable, form=map
MEDIA_PATH_OUTPUT = "media:model-path;textable;form=map"
# Media URN for embedding vector output - textable, form=map
MEDIA_EMBEDDING_VECTOR = "media:embedding-vector;textable;form=map"
# Media URN for LLM inference output - textable, form=map
MEDIA_LLM_INFERENCE_OUTPUT = "media:generated-text;textable;form=map"
# Media URN for extracted metadata - textable, form=map
MEDIA_FILE_METADATA = "media:file-metadata;textable;form=map"
# Media URN for extracted outline - textable, form=map
MEDIA_DOCUMENT_OUTLINE = "media:document-outline;textable;form=map"
# Media URN for disbound page - textable, form=list (array of page objects)
MEDIA_DISBOUND_PAGE = "media:disbound-page;textable;form=list"
# Media URN for caption output - textable, form=map
MEDIA_CAPTION_OUTPUT = "media:image-caption;textable;form=map"
# Media URN for transcription output - textable, form=map
MEDIA_TRANSCRIPTION_OUTPUT = "media:transcription;textable;form=map"
# Media URN for vision inference output - textable, form=map
MEDIA_VISION_INFERENCE_OUTPUT = "media:vision-inference-output;textable;form=map"
# Media URN for decision output (bit choice) - matches CATALOG
MEDIA_DECISION = "media:decision;bool;textable;form=scalar"
# Media URN for decision array output (bit choices) - matches CATALOG
MEDIA_DECISION_ARRAY = "media:decision;bool;textable;form=list"


# Helper functions to build media URNs
def binary_media_urn_for_ext(ext: str) -> str:
    """Helper to build binary media URN with extension"""
    return f"media:binary;ext={ext}"


def text_media_urn_for_ext(ext: str) -> str:
    """Helper to build text media URN with extension"""
    return f"media:ext={ext};textable"


def image_media_urn_for_ext(ext: str) -> str:
    """Helper to build image media URN with extension"""
    return f"media:image;ext={ext};bytes"


def audio_media_urn_for_ext(ext: str) -> str:
    """Helper to build audio media URN with extension"""
    return f"media:audio;ext={ext};bytes"


# =============================================================================
# MEDIA URN TYPE
# =============================================================================

class MediaUrnError(Exception):
    """Base exception for media URN errors"""
    pass


class MediaUrn:
    """A media URN representing a data type specification

    Media URNs are tagged URNs with the "media" prefix. They describe data
    types using tags like `type`, `subtype`, `v` (version), and `profile`.

    This is a newtype wrapper around `TaggedUrn` that enforces the "media"
    prefix and provides convenient accessors for common tags.
    """

    PREFIX = "media"

    def __init__(self, urn: TaggedUrn):
        """Create a new MediaUrn from a TaggedUrn

        Raises MediaUrnError if the TaggedUrn doesn't have the "media" prefix.
        """
        if urn.get_prefix() != self.PREFIX:
            raise MediaUrnError(
                f"Invalid prefix: expected '{self.PREFIX}', got '{urn.get_prefix()}'"
            )
        self._urn = urn

    @classmethod
    def from_string(cls, s: str) -> "MediaUrn":
        """Create a MediaUrn from a string representation

        The string must be a valid tagged URN with the "media" prefix.
        Whitespace and empty input validation is handled by TaggedUrn.from_string.
        """
        urn = TaggedUrn.from_string(s)
        return cls(urn)

    def inner(self) -> TaggedUrn:
        """Get the inner TaggedUrn"""
        return self._urn

    def get_tag(self, key: str) -> Optional[str]:
        """Get any tag value by key"""
        return self._urn.get_tag(key)

    def has_tag(self, key: str, value: str) -> bool:
        """Check if this media URN has a specific tag"""
        return self._urn.has_tag(key, value)

    def with_tag(self, key: str, value: str) -> "MediaUrn":
        """Create a new MediaUrn with an additional or updated tag"""
        new_urn = self._urn.with_tag(key, value)
        return MediaUrn(new_urn)

    def without_tag(self, key: str) -> "MediaUrn":
        """Create a new MediaUrn without a specific tag"""
        new_urn = self._urn.without_tag(key)
        return MediaUrn(new_urn)

    def tags_to_string(self) -> str:
        """Serialize just the tags portion (without "media:" prefix)

        Returns tags in canonical form with proper quoting and sorting.
        """
        return self._urn.tags_to_string()

    def to_string(self) -> str:
        """Get the canonical string representation"""
        return self._urn.to_string()

    def conforms_to(self, pattern: "MediaUrn") -> bool:
        """Check if this media URN (instance) satisfies the pattern's constraints.

        An instance conforms to a pattern when the instance has all tags
        required by the pattern. Missing tags in the pattern are wildcards.
        Equivalent to pattern.accepts(self).
        """
        return self._urn.conforms_to(pattern._urn)

    def accepts(self, instance: "MediaUrn") -> bool:
        """Check if this media URN (pattern) accepts the given instance.

        A pattern accepts an instance when the instance has all tags
        required by the pattern. Missing tags in the pattern are wildcards.
        Equivalent to instance.conforms_to(self).
        """
        return self._urn.accepts(instance._urn)

    def specificity(self) -> int:
        """Get the specificity of this media URN

        Specificity is calculated from tag values (not just count).
        """
        return self._urn.specificity()

    def is_binary(self) -> bool:
        """Check if this media URN represents binary data (bytes marker tag)"""
        # Check for 'bytes' tag (valueless or with any value)
        tag_val = self._urn.get_tag("bytes")
        return tag_val is not None

    def is_map(self) -> bool:
        """Check if this media URN represents map/object structure (form=map)"""
        return self._urn.has_tag("form", "map")

    def is_scalar(self) -> bool:
        """Check if this media URN represents a single value (form=scalar)"""
        return self._urn.has_tag("form", "scalar")

    def is_list(self) -> bool:
        """Check if this media URN represents a list/array (form=list)"""
        return self._urn.has_tag("form", "list")

    def is_structured(self) -> bool:
        """Check if this media URN represents structured data (map or list)"""
        return self.is_map() or self.is_list()

    def is_json(self) -> bool:
        """Check if this media URN represents JSON data (json marker tag)"""
        tag_val = self._urn.get_tag("json")
        return tag_val is not None

    def is_text(self) -> bool:
        """Check if this media URN represents textable data (textable marker tag)"""
        tag_val = self._urn.get_tag("textable")
        return tag_val is not None

    def is_void(self) -> bool:
        """Check if this media URN represents void (no data)"""
        # Check for 'void' tag or type=void
        void_tag = self._urn.get_tag("void")
        if void_tag is not None:
            return True
        return self._urn.has_tag("type", "void")

    def extension(self) -> Optional[str]:
        """Get the extension tag value if present"""
        return self._urn.get_tag("ext")

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"MediaUrn('{self.to_string()}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MediaUrn):
            return False
        return self._urn == other._urn

    def __hash__(self) -> int:
        return hash(self._urn)
