"""Formal cap definition

This module defines the structure for formal cap definitions including
the cap URN, arguments, output, and metadata.
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from capns.cap_urn import CapUrn


@dataclass
class MediaSpecDef:
    """Media spec definition for inline schemas

    Represents a media URN specification with optional JSON schema,
    validation rules, and metadata.
    """
    urn: str
    media_type: str
    title: str
    profile_uri: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    validation: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    extensions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
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
            result["validation"] = self.validation
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.extensions:
            result["extensions"] = self.extensions
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MediaSpecDef":
        """Parse from dict"""
        return cls(
            urn=data["urn"],
            media_type=data["media_type"],
            title=data["title"],
            profile_uri=data.get("profile_uri"),
            schema=data.get("schema"),
            description=data.get("description"),
            validation=data.get("validation"),
            metadata=data.get("metadata"),
            extensions=data.get("extensions", []),
        )


@dataclass
class ArgSource:
    """Source specification for argument input

    Each variant represents a different way to provide the argument:
    - stdin: via standard input with a media URN
    - position: positional argument (0-based)
    - cli_flag: named CLI flag
    """

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        raise NotImplementedError("Subclasses must implement to_dict")

    def get_type(self) -> str:
        """Get the source type name"""
        raise NotImplementedError("Subclasses must implement get_type")


class StdinSource(ArgSource):
    """Argument provided via stdin"""

    def __init__(self, stdin: str):
        self.stdin = stdin

    def to_dict(self) -> Dict[str, Any]:
        return {"stdin": self.stdin}

    def get_type(self) -> str:
        return "stdin"

    def stdin_media_urn(self) -> str:
        return self.stdin

    def __eq__(self, other):
        return isinstance(other, StdinSource) and self.stdin == other.stdin


class PositionSource(ArgSource):
    """Argument at a specific position"""

    def __init__(self, position: int):
        self.position = position

    def to_dict(self) -> Dict[str, Any]:
        return {"position": self.position}

    def get_type(self) -> str:
        return "position"

    def position_value(self) -> int:
        return self.position

    def __eq__(self, other):
        return isinstance(other, PositionSource) and self.position == other.position


class CliFlagSource(ArgSource):
    """Argument via CLI flag"""

    def __init__(self, cli_flag: str):
        self.cli_flag = cli_flag

    def to_dict(self) -> Dict[str, Any]:
        return {"cli_flag": self.cli_flag}

    def get_type(self) -> str:
        return "cli_flag"

    def flag_name(self) -> str:
        return self.cli_flag

    def __eq__(self, other):
        return isinstance(other, CliFlagSource) and self.cli_flag == other.cli_flag


def arg_source_from_dict(data: Dict[str, Any]) -> ArgSource:
    """Parse ArgSource from dict"""
    if "stdin" in data:
        return StdinSource(data["stdin"])
    elif "position" in data:
        return PositionSource(data["position"])
    elif "cli_flag" in data:
        return CliFlagSource(data["cli_flag"])
    else:
        raise ValueError(f"Unknown arg source format: {data}")


@dataclass
class CapArg:
    """Cap argument definition"""

    media_urn: str
    required: bool
    sources: List[ArgSource]
    arg_description: Optional[str] = None
    default_value: Optional[Any] = None
    metadata: Optional[Dict[str, Any]] = None

    def get_media_urn(self) -> str:
        """Get the media URN"""
        return self.media_urn

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        result = {
            "media_urn": self.media_urn,
            "required": self.required,
            "sources": [s.to_dict() for s in self.sources],
        }
        if self.arg_description is not None:
            result["arg_description"] = self.arg_description
        if self.default_value is not None:
            result["default_value"] = self.default_value
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapArg":
        """Parse from dict"""
        return cls(
            media_urn=data["media_urn"],
            required=data["required"],
            sources=[arg_source_from_dict(s) for s in data["sources"]],
            arg_description=data.get("arg_description"),
            default_value=data.get("default_value"),
            metadata=data.get("metadata"),
        )


@dataclass
class CapOutput:
    """Output definition"""

    media_urn: str
    output_description: str
    metadata: Optional[Dict[str, Any]] = None

    def get_media_urn(self) -> str:
        """Get the media URN"""
        return self.media_urn

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        result = {
            "media_urn": self.media_urn,
            "output_description": self.output_description,
        }
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapOutput":
        """Parse from dict"""
        return cls(
            media_urn=data["media_urn"],
            output_description=data["output_description"],
            metadata=data.get("metadata"),
        )


class Cap:
    """Formal cap definition

    A cap definition includes:
    - URN with tags (including `op`, `in`, `out`)
    - Arguments with media URN references
    - Output with media URN reference
    - Optional metadata
    """

    def __init__(self, urn: CapUrn, title: str, command: str):
        self.urn = urn
        self.title = title
        self.command = command
        self.cap_description: Optional[str] = None
        self.args: List[CapArg] = []
        self.output: Optional[CapOutput] = None
        self.metadata: Dict[str, str] = {}
        self.media_specs: List[Dict[str, Any]] = []

    @classmethod
    def with_metadata(cls, urn: CapUrn, title: str, command: str, metadata: Dict[str, str]) -> "Cap":
        """Create a Cap with metadata"""
        cap = cls(urn, title, command)
        cap.metadata = metadata
        return cap

    def urn_string(self) -> str:
        """Get the URN as a string"""
        return self.urn.to_string()

    def get_args(self) -> List[CapArg]:
        """Get all arguments"""
        return self.args

    def add_arg(self, arg: CapArg):
        """Add an argument"""
        self.args.append(arg)

    def set_output(self, output: CapOutput):
        """Set the output definition"""
        self.output = output

    def set_description(self, description: str):
        """Set the capability description"""
        self.cap_description = description

    def has_metadata(self, key: str) -> bool:
        """Check if metadata key exists"""
        return key in self.metadata

    def get_metadata(self, key: str) -> Optional[str]:
        """Get metadata value"""
        return self.metadata.get(key)

    def set_metadata(self, key: str, value: str):
        """Set metadata value"""
        self.metadata[key] = value

    def get_stdin_media_urn(self) -> Optional[str]:
        """Get stdin media URN if any arg uses stdin source"""
        for arg in self.args:
            for source in arg.sources:
                if isinstance(source, StdinSource):
                    return source.stdin_media_urn()
        return None

    def add_media_spec(self, spec: MediaSpecDef):
        """Add an inline media spec"""
        self.media_specs.append(spec.to_dict())

    def set_media_specs(self, media_specs: List[Any]):
        """Set inline media specs (accepts MediaSpecDef or dict)"""
        self.media_specs = []
        for spec in media_specs:
            if isinstance(spec, MediaSpecDef):
                self.media_specs.append(spec.to_dict())
            elif isinstance(spec, dict):
                self.media_specs.append(spec)
            else:
                raise ValueError(f"Invalid media spec type: {type(spec)}")

    def get_media_specs(self) -> List[Dict[str, Any]]:
        """Get inline media specs as dicts"""
        return self.media_specs

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        result = {
            "urn": self.urn.to_string(),
            "title": self.title,
            "command": self.command,
        }

        if self.cap_description is not None:
            result["cap_description"] = self.cap_description

        if self.args:
            result["args"] = [arg.to_dict() for arg in self.args]

        if self.output is not None:
            result["output"] = self.output.to_dict()

        if self.metadata:
            result["metadata"] = self.metadata

        if self.media_specs:
            result["media_specs"] = self.media_specs

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Cap":
        """Parse from dict"""
        urn = CapUrn.from_string(data["urn"])
        cap = cls(urn, data["title"], data["command"])

        if "cap_description" in data:
            cap.cap_description = data["cap_description"]

        if "args" in data:
            cap.args = [CapArg.from_dict(a) for a in data["args"]]

        if "output" in data:
            cap.output = CapOutput.from_dict(data["output"])

        if "metadata" in data:
            cap.metadata = data["metadata"]

        if "media_specs" in data:
            cap.media_specs = data["media_specs"]

        return cap

    def __eq__(self, other):
        if not isinstance(other, Cap):
            return False
        return (
            self.urn == other.urn
            and self.title == other.title
            and self.command == other.command
        )
