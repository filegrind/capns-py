"""Pure cap-based execution with strict input validation

This module provides data structures and execution infrastructure for calling capabilities.
"""

from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class StdinSourceData:
    """Raw byte data for stdin - used for providers (in-process) or small inline data"""
    data: bytes

    def __repr__(self):
        return f"StdinSource::Data({len(self.data)} bytes)"


@dataclass
class StdinSourceFileReference:
    """File reference for stdin - used for plugins to read files locally on Mac side

    Avoids the 4MB gRPC limit by letting the Swift/XPC side read the file locally
    instead of sending bytes over the wire.
    """
    tracked_file_id: str
    original_path: str
    security_bookmark: bytes
    media_urn: str

    def __repr__(self):
        return (
            f"StdinSource::FileReference("
            f"id={self.tracked_file_id}, "
            f"path={self.original_path}, "
            f"bookmark={len(self.security_bookmark)} bytes, "
            f"media_urn={self.media_urn})"
        )


# Union type for StdinSource
StdinSource = StdinSourceData | StdinSourceFileReference


class CapArgumentValue:
    """Unified argument type - arguments are identified by media_urn

    The cap definition's sources specify how to extract values (stdin, position, cli_flag).
    """

    def __init__(self, media_urn: str, value: bytes):
        """Create a new CapArgumentValue

        Args:
            media_urn: Semantic identifier (e.g., "media:model-spec;textable;form=scalar")
            value: Value bytes (UTF-8 for text, raw for binary)
        """
        self.media_urn = media_urn
        self.value = value

    @classmethod
    def from_str(cls, media_urn: str, value: str) -> "CapArgumentValue":
        """Create a new CapArgumentValue from a string value"""
        return cls(media_urn, value.encode('utf-8'))

    def value_as_str(self) -> str:
        """Get the value as a UTF-8 string

        Raises:
            UnicodeDecodeError: If the value contains non-UTF-8 binary data
        """
        return self.value.decode('utf-8')

    def __repr__(self):
        try:
            str_value = self.value_as_str()
            if len(str_value) > 50:
                str_value = str_value[:50] + "..."
            return f"CapArgumentValue(media_urn={self.media_urn!r}, value={str_value!r})"
        except UnicodeDecodeError:
            return f"CapArgumentValue(media_urn={self.media_urn!r}, value=<{len(self.value)} bytes>)"

    def __eq__(self, other):
        if not isinstance(other, CapArgumentValue):
            return False
        return self.media_urn == other.media_urn and self.value == other.value

    def clone(self) -> "CapArgumentValue":
        """Create an independent copy"""
        return CapArgumentValue(self.media_urn, bytes(self.value))


class CapSet:
    """Trait for Cap Host communication

    This is an abstract base class defining the interface for capability execution.
    """

    async def execute_cap(
        self,
        cap_urn: str,
        arguments: List[CapArgumentValue],
    ) -> Tuple[Optional[bytes], Optional[str]]:
        """Execute a cap with arguments identified by media_urn

        The cap definition's sources specify how to extract values (stdin, position, cli_flag).

        Args:
            cap_urn: The capability URN to execute
            arguments: List of arguments identified by media_urn

        Returns:
            Tuple of (binary_output, text_output) where one should be None
        """
        raise NotImplementedError("CapSet.execute_cap must be implemented by subclasses")


class CapCaller:
    """Cap caller that executes capabilities with strict validation

    Validates arguments against cap definition before execution and validates
    output types against declared output specs.
    """

    def __init__(
        self,
        cap: str,
        cap_set: CapSet,
        cap_definition,
        media_registry=None,
    ):
        """Create a new cap caller with validation

        Args:
            cap: The capability URN string
            cap_set: The CapSet implementation for executing capabilities
            cap_definition: The Cap definition for validation
            media_registry: Optional media registry for spec resolution
        """
        self.cap = cap
        self.cap_set = cap_set
        self.cap_definition = cap_definition
        self.media_registry = media_registry

    def get_positional_arg_positions(self) -> Dict[str, int]:
        """Get a map of argument media_urn to position for positional arguments

        Returns only arguments that have a position source set.
        """
        from capns.cap.definition import PositionSource

        positions = {}
        for arg in self.cap_definition.get_args():
            for source in arg.sources:
                if isinstance(source, PositionSource):
                    positions[arg.media_urn] = source.position
                    break
        return positions

    def validate_arguments(self, arguments: List[CapArgumentValue]) -> None:
        """Validate arguments against cap definition

        Checks that all required arguments are provided (by media_urn).

        Raises:
            ValueError: If validation fails
        """
        arg_defs = self.cap_definition.get_args()

        # Build set of provided media_urns
        provided_urns = {arg.media_urn for arg in arguments}

        # Check all required arguments are provided
        for arg_def in arg_defs:
            if arg_def.required and arg_def.media_urn not in provided_urns:
                raise ValueError(f"Missing required argument: {arg_def.media_urn}")

        # Check for unknown arguments
        known_urns = {arg_def.media_urn for arg_def in arg_defs}

        for arg in arguments:
            if arg.media_urn not in known_urns:
                raise ValueError(
                    f"Unknown argument media_urn: {arg.media_urn} "
                    f"(cap {self.cap} accepts: {known_urns})"
                )

    async def call(self, arguments: List[CapArgumentValue]):
        """Call the cap with arguments identified by media_urn

        Validates arguments against cap definition before execution.

        Args:
            arguments: List of arguments identified by media_urn

        Returns:
            ResponseWrapper with the capability output

        Raises:
            ValueError: If validation fails
            RuntimeError: If execution fails
        """
        from capns.cap.response import ResponseWrapper

        # Validate arguments against cap definition
        self.validate_arguments(arguments)

        # Execute via cap host method
        binary_output, text_output = await self.cap_set.execute_cap(
            self.cap,
            arguments,
        )

        # Determine response type based on what was returned
        if binary_output is not None:
            return ResponseWrapper.from_binary(binary_output)
        elif text_output is not None:
            # Try to parse as JSON for structured data
            try:
                return ResponseWrapper.from_json(text_output.encode('utf-8'))
            except:
                # Fall back to plain text
                return ResponseWrapper.from_text(text_output.encode('utf-8'))
        else:
            raise RuntimeError("Cap returned no output")
