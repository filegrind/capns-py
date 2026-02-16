"""JSON Schema validation for capability arguments and outputs

Provides validation of JSON data against JSON Schema Draft-07.
Schemas are embedded in cap definitions or resolved from registry.
"""

import json
from typing import Dict, Any, Optional
try:
    import jsonschema
    from jsonschema import Draft7Validator, ValidationError as JsonSchemaValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    # Provide stub for when jsonschema is not available
    class Draft7Validator:
        pass


class SchemaValidationError(Exception):
    """Schema validation error"""
    pass


class SchemaCompilationError(SchemaValidationError):
    """Schema compilation failed"""
    def __init__(self, msg: str):
        super().__init__(f"Schema compilation failed: {msg}")


class ArgumentValidationError(SchemaValidationError):
    """Argument validation failed"""
    def __init__(self, argument: str, details: str):
        super().__init__(f"Validation failed for argument '{argument}': {details}")
        self.argument = argument
        self.details = details


class OutputValidationError(SchemaValidationError):
    """Output validation failed"""
    def __init__(self, details: str):
        super().__init__(f"Validation failed for output: {details}")
        self.details = details


class MediaUrnNotResolvedError(SchemaValidationError):
    """Media URN could not be resolved"""
    def __init__(self, media_urn: str, error: str):
        super().__init__(f"Media URN '{media_urn}' could not be resolved: {error}")
        self.media_urn = media_urn
        self.error = error


class SchemaValidator:
    """Schema validator with caching for performance"""

    def __init__(self):
        self.schema_cache: Dict[str, Any] = {}
        if not JSONSCHEMA_AVAILABLE:
            raise ImportError("jsonschema package is required for schema validation. Install with: pip install jsonschema")

    def validate_value_against_schema(self, name: str, value: Any, schema: Dict[str, Any]) -> None:
        """Validate a JSON value against a schema"""
        # Cache compiled schemas by schema JSON
        schema_key = json.dumps(schema, sort_keys=True)

        if schema_key not in self.schema_cache:
            try:
                validator = Draft7Validator(schema)
                self.schema_cache[schema_key] = validator
            except Exception as e:
                raise SchemaCompilationError(str(e))

        validator = self.schema_cache[schema_key]

        # Validate the value
        errors = list(validator.iter_errors(value))
        if errors:
            error_details = "\n".join([f"  - {e.message}" for e in errors])

            if name == "output":
                raise OutputValidationError(error_details)
            else:
                raise ArgumentValidationError(name, error_details)

    def validate_argument(self, cap, arg_def, value: Any) -> None:
        """Validate a single argument against its schema from cap's media_specs"""
        # Look for schema in cap's media_specs (stored as dicts)
        media_specs = cap.get_media_specs()
        schema = None

        for spec in media_specs:
            if spec["urn"] == arg_def.media_urn:
                schema = spec.get("schema")
                break

        # If no schema found, skip validation
        if schema is None:
            return

        self.validate_value_against_schema(arg_def.media_urn, value, schema)

    def validate_output(self, cap, output_def, value: Any) -> None:
        """Validate output against its schema from cap's media_specs"""
        # Look for schema in cap's media_specs (stored as dicts)
        media_specs = cap.get_media_specs()
        schema = None

        for spec in media_specs:
            if spec["urn"] == output_def.media_urn:
                schema = spec.get("schema")
                break

        # If no schema found, skip validation
        if schema is None:
            return

        self.validate_value_against_schema("output", value, schema)

    def validate_arguments(self, cap, arguments: list) -> None:
        """Validate all positional arguments for a capability"""
        from capns.cap.definition import PositionSource

        args = cap.get_args()

        # Get positional args sorted by position
        positional_args = []
        for arg in args:
            for source in arg.sources:
                if isinstance(source, PositionSource):
                    positional_args.append((arg, source.position))
                    break

        positional_args.sort(key=lambda x: x[1])

        # Validate each positional argument
        for arg_def, position in positional_args:
            if position < len(arguments):
                arg_value = arguments[position]
                self.validate_argument(cap, arg_def, arg_value)
