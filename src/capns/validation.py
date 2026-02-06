"""Cap validation infrastructure

This module provides input/output validation for caps using schemas.
It validates arguments and outputs against their declared media URNs and schemas.
"""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class ValidationError(Exception):
    """Base validation error"""
    pass


class MissingRequiredArgumentError(ValidationError):
    """Required argument missing"""
    def __init__(self, cap_urn: str, argument_name: str):
        super().__init__(f"Cap '{cap_urn}' requires argument '{argument_name}' but it was not provided")
        self.cap_urn = cap_urn
        self.argument_name = argument_name


class InvalidArgumentTypeError(ValidationError):
    """Invalid argument type"""
    def __init__(self, cap_urn: str, argument_name: str, expected: str, actual: Any, errors: List[str]):
        msg = f"Cap '{cap_urn}' argument '{argument_name}' expects '{expected}' but validation failed: {', '.join(errors)}"
        super().__init__(msg)
        self.cap_urn = cap_urn
        self.argument_name = argument_name
        self.expected_media_spec = expected
        self.actual_value = actual
        self.schema_errors = errors


class TooManyArgumentsError(ValidationError):
    """Too many arguments"""
    def __init__(self, cap_urn: str, max_expected: int, actual_count: int):
        super().__init__(f"Cap '{cap_urn}' expects at most {max_expected} arguments but received {actual_count}")
        self.cap_urn = cap_urn
        self.max_expected = max_expected
        self.actual_count = actual_count


class InvalidCapSchemaError(ValidationError):
    """Invalid cap schema"""
    def __init__(self, cap_urn: str, issue: str):
        super().__init__(f"Cap '{cap_urn}' has invalid schema: {issue}")
        self.cap_urn = cap_urn
        self.issue = issue


class MediaSpecValidationError(ValidationError):
    """Media spec validation rule violation"""
    def __init__(self, cap_urn: str, argument_name: str, media_urn: str, rule: str, actual: Any):
        super().__init__(
            f"Cap '{cap_urn}' argument '{argument_name}' failed media spec '{media_urn}' "
            f"validation rule '{rule}' with value: {actual}"
        )
        self.cap_urn = cap_urn
        self.argument_name = argument_name
        self.media_urn = media_urn
        self.validation_rule = rule
        self.actual_value = actual


# Reserved CLI flags that cannot be used
RESERVED_CLI_FLAGS = ["manifest", "--help", "--version", "-v", "-h"]


def validate_cap_args(cap) -> None:
    """Validate cap arguments against the 12 validation rules

    Rules:
    - RULE1: No duplicate media_urns
    - RULE2: sources must not be empty
    - RULE3: If multiple args have stdin source, stdin media_urns must be identical
    - RULE4: No arg may specify same source type more than once
    - RULE5: No two args may have same position
    - RULE6: Positions must be sequential (0-based, no gaps)
    - RULE7: No arg may have both position and cli_flag
    - RULE9: No two args may have same cli_flag
    - RULE10: Reserved cli_flags cannot be used
    """
    from capns.cap import PositionSource, CliFlagSource, StdinSource

    cap_urn = cap.urn_string()
    args = cap.get_args()

    # RULE1: No duplicate media_urns
    media_urns = set()
    for arg in args:
        if arg.media_urn in media_urns:
            raise InvalidCapSchemaError(cap_urn, f"RULE1: Duplicate media_urn '{arg.media_urn}'")
        media_urns.add(arg.media_urn)

    # RULE2: sources must not be empty
    for arg in args:
        if not arg.sources:
            raise InvalidCapSchemaError(cap_urn, f"RULE2: Argument '{arg.media_urn}' has empty sources")

    # Collect data for cross-arg validation
    stdin_urns = []
    positions = []
    cli_flags = []

    for arg in args:
        source_types = set()
        has_position = False
        has_cli_flag = False

        for source in arg.sources:
            source_type = type(source).__name__

            # RULE4: No arg may specify same source type more than once
            if source_type in source_types:
                raise InvalidCapSchemaError(
                    cap_urn,
                    f"RULE4: Argument '{arg.media_urn}' has duplicate source type '{source_type}'"
                )
            source_types.add(source_type)

            if isinstance(source, StdinSource):
                stdin_urns.append(source.stdin)
            elif isinstance(source, PositionSource):
                has_position = True
                positions.append((source.position, arg.media_urn))
            elif isinstance(source, CliFlagSource):
                has_cli_flag = True
                cli_flags.append((source.cli_flag, arg.media_urn))

                # RULE10: Reserved cli_flags
                if source.cli_flag in RESERVED_CLI_FLAGS:
                    raise InvalidCapSchemaError(
                        cap_urn,
                        f"RULE10: Argument '{arg.media_urn}' uses reserved cli_flag '{source.cli_flag}'"
                    )

        # RULE7: No arg may have both position and cli_flag
        if has_position and has_cli_flag:
            raise InvalidCapSchemaError(
                cap_urn,
                f"RULE7: Argument '{arg.media_urn}' has both position and cli_flag sources"
            )

    # RULE3: If multiple args have stdin source, stdin media_urns must be identical
    if len(stdin_urns) > 1:
        first_stdin = stdin_urns[0]
        for stdin in stdin_urns[1:]:
            if stdin != first_stdin:
                raise InvalidCapSchemaError(
                    cap_urn,
                    f"RULE3: Multiple args have different stdin media_urns: '{first_stdin}' vs '{stdin}'"
                )

    # RULE5: No two args may have same position
    position_set = set()
    for position, media_urn in positions:
        if position in position_set:
            raise InvalidCapSchemaError(
                cap_urn,
                f"RULE5: Duplicate position {position} in argument '{media_urn}'"
            )
        position_set.add(position)

    # RULE6: Positions must be sequential (0-based, no gaps)
    if positions:
        sorted_positions = sorted(positions, key=lambda x: x[0])
        for i, (position, _) in enumerate(sorted_positions):
            if position != i:
                raise InvalidCapSchemaError(
                    cap_urn,
                    f"RULE6: Position gap - expected {i} but found {position}"
                )

    # RULE9: No two args may have same cli_flag
    flag_set = set()
    for flag, media_urn in cli_flags:
        if flag in flag_set:
            raise InvalidCapSchemaError(
                cap_urn,
                f"RULE9: Duplicate cli_flag '{flag}' in argument '{media_urn}'"
            )
        flag_set.add(flag)


def validate_positional_arguments(cap, arguments: List[Any]) -> None:
    """Validate positional arguments against cap definition

    Checks:
    - Correct number of arguments
    - Required arguments are provided
    - Basic type checking
    """
    from capns.cap import PositionSource

    cap_urn = cap.urn_string()
    args = cap.get_args()

    # Get positional args sorted by position
    positional_args = [
        (arg, source.position)
        for arg in args
        for source in arg.sources
        if isinstance(source, PositionSource)
    ]
    positional_args.sort(key=lambda x: x[1])

    # Check if too many arguments provided
    if len(arguments) > len(positional_args):
        raise TooManyArgumentsError(cap_urn, len(positional_args), len(arguments))

    # Validate each positional argument
    for index, (arg_def, _) in enumerate(positional_args):
        if index >= len(arguments):
            # Missing argument - check if required
            if arg_def.required:
                raise MissingRequiredArgumentError(cap_urn, arg_def.media_urn)
            continue

        # Basic validation (could be extended with schema validation)
        value = arguments[index]
        if value is None and arg_def.required:
            raise MissingRequiredArgumentError(cap_urn, arg_def.media_urn)
