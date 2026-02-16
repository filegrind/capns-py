"""Response wrapper for unified plugin output handling"""

import json
from typing import Any, TypeVar, Type
from enum import Enum


T = TypeVar('T')


class ResponseContentType(Enum):
    """Content type for response data"""
    JSON = "json"
    TEXT = "text"
    BINARY = "binary"


class ResponseWrapper:
    """Unified response wrapper for all plugin operations

    Provides type-safe deserialization of plugin output.
    """

    def __init__(self, raw_bytes: bytes, content_type: ResponseContentType):
        self.raw_bytes = raw_bytes
        self.content_type = content_type

    @classmethod
    def from_json(cls, data: bytes) -> "ResponseWrapper":
        """Create from JSON output"""
        return cls(data, ResponseContentType.JSON)

    @classmethod
    def from_text(cls, data: bytes) -> "ResponseWrapper":
        """Create from text output"""
        return cls(data, ResponseContentType.TEXT)

    @classmethod
    def from_binary(cls, data: bytes) -> "ResponseWrapper":
        """Create from binary output (like PNG images)"""
        return cls(data, ResponseContentType.BINARY)

    def as_bytes(self) -> bytes:
        """Get raw bytes"""
        return self.raw_bytes

    def as_string(self) -> str:
        """Convert to string"""
        return self.raw_bytes.decode('utf-8')

    def as_int(self) -> int:
        """Convert to integer"""
        text = self.as_string().strip()

        # Try parsing as JSON number first
        try:
            json_val = json.loads(text)
            if isinstance(json_val, int):
                return json_val
            elif isinstance(json_val, float):
                return int(json_val)
        except (json.JSONDecodeError, ValueError):
            pass

        # Fall back to direct parsing
        return int(text)

    def as_float(self) -> float:
        """Convert to float"""
        text = self.as_string().strip()

        # Try parsing as JSON number first
        try:
            json_val = json.loads(text)
            if isinstance(json_val, (int, float)):
                return float(json_val)
        except (json.JSONDecodeError, ValueError):
            pass

        # Fall back to direct parsing
        return float(text)

    def as_bool(self) -> bool:
        """Convert to boolean"""
        text = self.as_string().strip().lower()

        if text in ("true", "1", "yes", "y"):
            return True
        elif text in ("false", "0", "no", "n"):
            return False
        else:
            raise ValueError(f"Cannot convert '{text}' to boolean")

    def as_type(self, type_class: Type[T]) -> T:
        """Deserialize to a specific type

        For JSON content types, uses json.loads and type construction.
        """
        if self.content_type == ResponseContentType.JSON:
            data = json.loads(self.raw_bytes.decode('utf-8'))
            # If it's a dict and the type has a from_dict method, use it
            if isinstance(data, dict) and hasattr(type_class, '__init__'):
                return type_class(**data)
            return data
        else:
            raise ValueError(f"Cannot deserialize {self.content_type} to type {type_class}")

    def __repr__(self) -> str:
        size = len(self.raw_bytes)
        return f"ResponseWrapper(type={self.content_type}, size={size})"
