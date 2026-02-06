"""Cap SDK - Core cap URN and definition system

This library provides the fundamental cap URN system used across
all FGND plugins and providers. It defines the formal structure for cap
identifiers with flat tag-based naming, wildcard support, and specificity comparison.
"""

from capns.media_urn import (
    MediaUrn,
    MediaUrnError,
    # Standard media URN constants
    MEDIA_VOID,
    MEDIA_STRING,
    MEDIA_INTEGER,
    MEDIA_NUMBER,
    MEDIA_BOOLEAN,
    MEDIA_OBJECT,
    MEDIA_BINARY,
    MEDIA_STRING_ARRAY,
    MEDIA_INTEGER_ARRAY,
    MEDIA_NUMBER_ARRAY,
    MEDIA_BOOLEAN_ARRAY,
    MEDIA_OBJECT_ARRAY,
    MEDIA_PNG,
    MEDIA_AUDIO,
    MEDIA_VIDEO,
    MEDIA_AUDIO_SPEECH,
    MEDIA_IMAGE_THUMBNAIL,
    MEDIA_COLLECTION,
    MEDIA_COLLECTION_LIST,
    MEDIA_PDF,
    MEDIA_EPUB,
    MEDIA_MD,
    MEDIA_TXT,
    MEDIA_RST,
    MEDIA_LOG,
    MEDIA_HTML,
    MEDIA_XML,
    MEDIA_JSON,
    MEDIA_JSON_SCHEMA,
    MEDIA_YAML,
    MEDIA_FILE_PATH,
    MEDIA_FILE_PATH_ARRAY,
    MEDIA_FRONTMATTER_TEXT,
    MEDIA_MODEL_SPEC,
    MEDIA_MLX_MODEL_PATH,
    MEDIA_MODEL_REPO,
    MEDIA_MODEL_DIM,
    MEDIA_DOWNLOAD_OUTPUT,
    MEDIA_LIST_OUTPUT,
    MEDIA_STATUS_OUTPUT,
    MEDIA_CONTENTS_OUTPUT,
    MEDIA_AVAILABILITY_OUTPUT,
    MEDIA_PATH_OUTPUT,
    MEDIA_EMBEDDING_VECTOR,
    MEDIA_LLM_INFERENCE_OUTPUT,
    MEDIA_FILE_METADATA,
    MEDIA_DOCUMENT_OUTLINE,
    MEDIA_DISBOUND_PAGE,
    MEDIA_CAPTION_OUTPUT,
    MEDIA_TRANSCRIPTION_OUTPUT,
    MEDIA_VISION_INFERENCE_OUTPUT,
    MEDIA_DECISION,
    MEDIA_DECISION_ARRAY,
    binary_media_urn_for_ext,
    text_media_urn_for_ext,
    image_media_urn_for_ext,
    audio_media_urn_for_ext,
)

from capns.cap_urn import (
    CapUrn,
    CapUrnError,
    CapUrnBuilder,
)

from capns.response import ResponseWrapper

from capns.cap import Cap, CapArg, CapOutput, StdinSource, PositionSource, CliFlagSource, MediaSpecDef
from capns.manifest import CapManifest

from capns.validation import (
    validate_cap_args,
    validate_positional_arguments,
    ValidationError,
    MissingRequiredArgumentError,
    InvalidArgumentTypeError,
    TooManyArgumentsError,
    InvalidCapSchemaError,
    MediaSpecValidationError,
    RESERVED_CLI_FLAGS,
)

from capns.schema_validation import (
    SchemaValidator,
    SchemaValidationError,
    SchemaCompilationError,
    ArgumentValidationError,
    OutputValidationError,
    MediaUrnNotResolvedError,
)

from capns.caller import (
    StdinSourceData,
    StdinSourceFileReference,
    CapArgumentValue,
    CapSet,
    CapCaller,
)

from capns.registry import (
    CapRegistry,
    RegistryConfig,
    RegistryError,
    HttpError,
    NotFoundError,
    ParseError,
    CacheError,
    normalize_cap_urn,
)

from capns.cap_matrix import (
    CapGraph,
    CapGraphEdge,
    CapMatrix,
    CapMatrixError,
    NoSetsFoundError,
    InvalidUrnError,
)

from capns.standard.caps import (
    model_availability_urn,
    model_path_urn,
    llm_conversation_urn,
)

__all__ = [
    # MediaUrn
    "MediaUrn",
    "MediaUrnError",
    # Media constants
    "MEDIA_VOID",
    "MEDIA_STRING",
    "MEDIA_INTEGER",
    "MEDIA_NUMBER",
    "MEDIA_BOOLEAN",
    "MEDIA_OBJECT",
    "MEDIA_BINARY",
    "MEDIA_STRING_ARRAY",
    "MEDIA_INTEGER_ARRAY",
    "MEDIA_NUMBER_ARRAY",
    "MEDIA_BOOLEAN_ARRAY",
    "MEDIA_OBJECT_ARRAY",
    "MEDIA_PNG",
    "MEDIA_AUDIO",
    "MEDIA_VIDEO",
    "MEDIA_AUDIO_SPEECH",
    "MEDIA_IMAGE_THUMBNAIL",
    "MEDIA_COLLECTION",
    "MEDIA_COLLECTION_LIST",
    "MEDIA_PDF",
    "MEDIA_EPUB",
    "MEDIA_MD",
    "MEDIA_TXT",
    "MEDIA_RST",
    "MEDIA_LOG",
    "MEDIA_HTML",
    "MEDIA_XML",
    "MEDIA_JSON",
    "MEDIA_JSON_SCHEMA",
    "MEDIA_YAML",
    "MEDIA_FILE_PATH",
    "MEDIA_FILE_PATH_ARRAY",
    "MEDIA_FRONTMATTER_TEXT",
    "MEDIA_MODEL_SPEC",
    "MEDIA_MLX_MODEL_PATH",
    "MEDIA_MODEL_REPO",
    "MEDIA_MODEL_DIM",
    "MEDIA_DOWNLOAD_OUTPUT",
    "MEDIA_LIST_OUTPUT",
    "MEDIA_STATUS_OUTPUT",
    "MEDIA_CONTENTS_OUTPUT",
    "MEDIA_AVAILABILITY_OUTPUT",
    "MEDIA_PATH_OUTPUT",
    "MEDIA_EMBEDDING_VECTOR",
    "MEDIA_LLM_INFERENCE_OUTPUT",
    "MEDIA_FILE_METADATA",
    "MEDIA_DOCUMENT_OUTLINE",
    "MEDIA_DISBOUND_PAGE",
    "MEDIA_CAPTION_OUTPUT",
    "MEDIA_TRANSCRIPTION_OUTPUT",
    "MEDIA_VISION_INFERENCE_OUTPUT",
    "MEDIA_DECISION",
    "MEDIA_DECISION_ARRAY",
    "binary_media_urn_for_ext",
    "text_media_urn_for_ext",
    "image_media_urn_for_ext",
    "audio_media_urn_for_ext",
    # CapUrn
    "CapUrn",
    "CapUrnError",
    "CapUrnBuilder",
    # Response
    "ResponseWrapper",
    # Cap
    "Cap",
    "CapArg",
    "CapOutput",
    "StdinSource",
    "PositionSource",
    "CliFlagSource",
    "MediaSpecDef",
    # Manifest
    "CapManifest",
    # Validation
    "validate_cap_args",
    "validate_positional_arguments",
    "ValidationError",
    "MissingRequiredArgumentError",
    "InvalidArgumentTypeError",
    "TooManyArgumentsError",
    "InvalidCapSchemaError",
    "MediaSpecValidationError",
    "RESERVED_CLI_FLAGS",
    # Schema validation
    "SchemaValidator",
    "SchemaValidationError",
    "SchemaCompilationError",
    "ArgumentValidationError",
    "OutputValidationError",
    "MediaUrnNotResolvedError",
    # Caller
    "StdinSourceData",
    "StdinSourceFileReference",
    "CapArgumentValue",
    "CapSet",
    "CapCaller",
    # Registry
    "CapRegistry",
    "RegistryConfig",
    "RegistryError",
    "HttpError",
    "NotFoundError",
    "ParseError",
    "CacheError",
    "normalize_cap_urn",
    # CapMatrix
    "CapGraph",
    "CapGraphEdge",
    "CapMatrix",
    "CapMatrixError",
    "NoSetsFoundError",
    "InvalidUrnError",
    # Standard caps
    "model_availability_urn",
    "model_path_urn",
    "llm_conversation_urn",
]
