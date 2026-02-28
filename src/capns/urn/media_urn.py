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
# Media URN for string type - textable (can become text), scalar by default (no list marker)
MEDIA_STRING = "media:textable"
# Media URN for integer type - textable, numeric (math ops valid), scalar by default
MEDIA_INTEGER = "media:integer;textable;numeric"
# Media URN for number type - textable, numeric, scalar by default (no primary type prefix)
MEDIA_NUMBER = "media:textable;numeric"
# Media URN for boolean type - uses "bool" not "boolean" per base.toml
MEDIA_BOOLEAN = "media:bool;textable"
# Media URN for JSON object type - record (key-value structure), textable (via JSON.stringify)
MEDIA_OBJECT = "media:record"
# Media URN for binary data (wildcard - matches everything)
MEDIA_BINARY = "media:"

# Array types - URNs must match base.toml definitions
# Media URN for string array type - list marker, textable (no primary type prefix)
MEDIA_STRING_ARRAY = "media:list;textable"
# Media URN for integer array type - list marker, integer, numeric, textable (per base.toml:46)
MEDIA_INTEGER_ARRAY = "media:integer;list;textable;numeric"
# Media URN for number array type - list marker, numeric, textable (no primary type prefix)
MEDIA_NUMBER_ARRAY = "media:list;textable;numeric"
# Media URN for boolean array type - list marker, bool, textable (uses "bool" not "boolean" per base.toml)
MEDIA_BOOLEAN_ARRAY = "media:bool;list;textable"
# Media URN for object array type - list marker, record (each item has structure)
MEDIA_OBJECT_ARRAY = "media:list;record"

# Semantic media types for specialized content
# Media URN for PNG image data
MEDIA_PNG = "media:image;png"
# Media URN for audio data (wav, mp3, flac, etc.)
MEDIA_AUDIO = "media:wav;audio"
# Media URN for video data (mp4, webm, mov, etc.)
MEDIA_VIDEO = "media:video"

# Semantic AI input types - distinguished by their purpose/context
# Media URN for audio input containing speech for transcription (Whisper)
MEDIA_AUDIO_SPEECH = "media:audio;wav;speech"
# Media URN for thumbnail image output
MEDIA_IMAGE_THUMBNAIL = "media:image;png;thumbnail"

# Document types (PRIMARY naming - type IS the format)
# Media URN for PDF documents
MEDIA_PDF = "media:pdf"
# Media URN for EPUB documents
MEDIA_EPUB = "media:epub"

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
MEDIA_JSON = "media:json;record;textable"
# Media URN for JSON with schema constraint (input for structured queries) - matches CATALOG
MEDIA_JSON_SCHEMA = "media:json;json-schema;record;textable"
# Media URN for YAML data
MEDIA_YAML = "media:record;textable;yaml"

# File path types - for arguments that represent filesystem paths
# Media URN for a single file path - textable, scalar, and marked as a file-path for special handling
MEDIA_FILE_PATH = "media:file-path;textable"
# Media URN for an array of file paths - textable, list (per file-path.toml)
MEDIA_FILE_PATH_ARRAY = "media:file-path;list;textable"

# Semantic text input types - distinguished by their purpose/context
# Media URN for frontmatter text (book metadata)
MEDIA_FRONTMATTER_TEXT = "media:frontmatter;textable"
# Media URN for model spec (provider:model format, HuggingFace name, etc.)
MEDIA_MODEL_SPEC = "media:model-spec;textable"
# Media URN for MLX model path
MEDIA_MLX_MODEL_PATH = "media:mlx-model-path;textable"
# Media URN for model repository (input for list-models) - matches CATALOG
MEDIA_MODEL_REPO = "media:model-repo;record;textable"

# CAPNS output types - all record structures (JSON objects)
# Media URN for model dimension output - matches CATALOG
MEDIA_MODEL_DIM = "media:integer;model-dim;numeric;textable"
# Media URN for model download output - record structure
MEDIA_DOWNLOAD_OUTPUT = "media:download-result;record;textable"
# Media URN for model list output - record structure
MEDIA_LIST_OUTPUT = "media:model-list;record;textable"
# Media URN for model status output - record structure
MEDIA_STATUS_OUTPUT = "media:model-status;record;textable"
# Media URN for model contents output - record structure
MEDIA_CONTENTS_OUTPUT = "media:model-contents;record;textable"
# Media URN for model availability output - record structure
MEDIA_AVAILABILITY_OUTPUT = "media:model-availability;record;textable"
# Media URN for model path output - record structure
MEDIA_PATH_OUTPUT = "media:model-path;record;textable"
# Media URN for embedding vector output - record structure
MEDIA_EMBEDDING_VECTOR = "media:embedding-vector;record;textable"
# Media URN for LLM inference output - record structure
MEDIA_LLM_INFERENCE_OUTPUT = "media:generated-text;record;textable"
# Media URN for extracted metadata - record structure
MEDIA_FILE_METADATA = "media:file-metadata;record;textable"
# Media URN for extracted outline - record structure
MEDIA_DOCUMENT_OUTLINE = "media:document-outline;record;textable"
# Media URN for disbound page - list (array of page objects)
MEDIA_DISBOUND_PAGE = "media:disbound-page;list;textable"
# Media URN for image description output - textable (renamed from MEDIA_CAPTION_OUTPUT)
MEDIA_IMAGE_DESCRIPTION = "media:image-description;textable"
# Media URN for transcription output - record structure
MEDIA_TRANSCRIPTION_OUTPUT = "media:record;textable;transcription"
# Media URN for decision output (bit choice) - matches CATALOG
MEDIA_DECISION = "media:bool;decision;textable"
# Media URN for decision array output (bit choices) - matches CATALOG
MEDIA_DECISION_ARRAY = "media:bool;decision;list;textable"


# Helper functions to build media URNs
def binary_media_urn_for_ext(ext: str) -> str:
    """Helper to build binary media URN with extension"""
    return f"media:binary;ext={ext}"


def text_media_urn_for_ext(ext: str) -> str:
    """Helper to build text media URN with extension"""
    return f"media:ext={ext};textable"


def image_media_urn_for_ext(ext: str) -> str:
    """Helper to build image media URN with extension"""
    return f"media:image;ext={ext}"


def audio_media_urn_for_ext(ext: str) -> str:
    """Helper to build audio media URN with extension"""
    return f"media:audio;ext={ext}"


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

    def has_marker_tag(self, tag_name: str) -> bool:
        """Check if a marker tag is present (has wildcard value).

        Marker tags are tags with wildcard values (*) that indicate
        boolean-like properties of the media type.
        """
        return self._urn.tags.get(tag_name) == "*"

    def is_binary(self) -> bool:
        """Check if this represents binary (non-text) data.
        Returns True if the "textable" marker tag is NOT present."""
        tag_val = self._urn.get_tag("textable")
        return tag_val is None

    def is_scalar(self) -> bool:
        """Check if this media URN represents a single value (not a list).
        Returns True if the "list" marker tag is NOT present."""
        return not self.has_marker_tag("list")

    def is_list(self) -> bool:
        """Check if this media URN represents a list/array.
        Returns True if the "list" marker tag is present."""
        return self.has_marker_tag("list")

    def is_record(self) -> bool:
        """Check if this media URN has internal record structure (key-value pairs).
        Returns True if the "record" marker tag is present."""
        return self.has_marker_tag("record")

    def is_opaque(self) -> bool:
        """Check if this media URN has no recognized internal structure.
        Returns True if the "record" marker tag is NOT present."""
        return not self.has_marker_tag("record")

    def is_json(self) -> bool:
        """Check if this media URN represents JSON data (json marker tag)"""
        tag_val = self._urn.get_tag("json")
        return tag_val is not None

    def is_text(self) -> bool:
        """Check if this media URN represents textable data (textable marker tag)"""
        tag_val = self._urn.get_tag("textable")
        return tag_val is not None

    def is_image(self) -> bool:
        """Check if this represents image data.
        Returns true if the "image" marker tag is present.
        """
        return self._urn.get_tag("image") is not None

    def is_audio(self) -> bool:
        """Check if this represents audio data.
        Returns true if the "audio" marker tag is present.
        """
        return self._urn.get_tag("audio") is not None

    def is_video(self) -> bool:
        """Check if this represents video data.
        Returns true if the "video" marker tag is present.
        """
        return self._urn.get_tag("video") is not None

    def is_numeric(self) -> bool:
        """Check if this represents numeric data.
        Returns true if the "numeric" marker tag is present.
        """
        return self._urn.get_tag("numeric") is not None

    def is_bool(self) -> bool:
        """Check if this represents boolean data.
        Returns true if the "bool" marker tag is present.
        """
        return self._urn.get_tag("bool") is not None

    def is_void(self) -> bool:
        """Check if this represents a void (no data) type"""
        # Check for "void" marker tag
        return "void" in self._urn.tags

    def is_file_path(self) -> bool:
        """Check if this represents a single file path type (not array).
        Returns true if the "file-path" marker tag is present AND NOT list.
        """
        return self.has_marker_tag("file-path") and self.is_scalar()

    def is_file_path_array(self) -> bool:
        """Check if this represents a file path array type.
        Returns true if the "file-path" marker tag is present AND list.
        """
        return self.has_marker_tag("file-path") and self.is_list()

    def is_any_file_path(self) -> bool:
        """Check if this represents any file path type (single or array).
        Returns true if the "file-path" marker tag is present.
        """
        return self.has_marker_tag("file-path")

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
