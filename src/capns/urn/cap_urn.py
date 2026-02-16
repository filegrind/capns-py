"""Flat Tag-Based Cap Identifier System

This module provides a flat, tag-based cap URN system that replaces
hierarchical naming with key-value tags to handle cross-cutting concerns and
multi-dimensional cap classification.

Cap URNs use the tagged URN format with "cap" prefix. Missing `in` or `out`
tags default to "media:" (wildcard). Explicit "*" also expands to "media:".
"""

from typing import Dict, List, Optional
from tagged_urn import TaggedUrn, TaggedUrnBuilder, TaggedUrnError
from capns.urn.media_urn import MediaUrn, MediaUrnError


class CapUrnError(Exception):
    """Base exception for cap URN errors"""
    pass


class CapUrn:
    """A cap URN using flat, ordered tags with required direction specifiers

    Direction (in→out) is integral to a cap's identity. The `in_urn` and `out_urn`
    fields specify the input and output media URNs respectively.

    Examples:
    - `cap:in="media:binary";op=generate;out="media:binary";target=thumbnail`
    - `cap:in="media:void";op=dimensions;out="media:integer"`
    - `cap:in="media:string";out="media:object";key="Value With Spaces"`
    """

    PREFIX = "cap"

    def __init__(self, in_urn: str, out_urn: str, tags: Dict[str, str]):
        """Create a new cap URN from direction specs and additional tags

        Keys are normalized to lowercase; values are preserved as-is.
        in_urn and out_urn are required direction specifiers (media URN strings).
        'in' and 'out' keys in tags dict are filtered out.
        """
        # Filter out 'in' and 'out' from tags, normalize remaining keys
        self.in_urn = in_urn
        self.out_urn = out_urn
        self.tags: Dict[str, str] = {
            k.lower(): v
            for k, v in tags.items()
            if k.lower() not in ("in", "out")
        }

    @classmethod
    def from_tags(cls, tags: Dict[str, str]) -> "CapUrn":
        """Create a cap URN from tags map that must contain 'in' and 'out'

        This is a convenience method for deserialization.
        Raises CapUrnError if 'in' or 'out' is missing.
        """
        tags_copy = tags.copy()
        in_urn = tags_copy.pop("in", None)
        out_urn = tags_copy.pop("out", None)

        if in_urn is None:
            raise CapUrnError("Missing required 'in' spec - caps must declare their input type")
        if out_urn is None:
            raise CapUrnError("Missing required 'out' spec - caps must declare their output type")

        return cls(in_urn, out_urn, tags_copy)

    @staticmethod
    def _process_direction_tag(tagged: TaggedUrn, tag_name: str) -> str:
        """Process a direction tag (in or out) with wildcard expansion

        - Missing tag → "media:" (wildcard)
        - tag=* → "media:" (wildcard)
        - tag= (empty) → error
        - tag=value → value (validated later)
        """
        value = tagged.get_tag(tag_name)
        if value is None:
            # Tag is missing - default to media: wildcard
            return "media:"
        elif value == "*":
            # Replace * with media: wildcard
            return "media:"
        elif value == "":
            # Empty value is not allowed (in= or out= with nothing after =)
            raise CapUrnError(f"Empty value for '{tag_name}' tag is not allowed")
        else:
            # Regular value - will be validated as MediaUrn later
            return value

    @classmethod
    def from_string(cls, s: str) -> "CapUrn":
        """Create a cap URN from a string representation

        Format: `cap:in="media:...";out="media:...";key1=value1;...`
        The "cap:" prefix is mandatory.
        Missing 'in' or 'out' tags default to "media:" (wildcard).
        Trailing semicolons are optional and ignored.
        Tags are automatically sorted alphabetically for canonical form.

        Case handling (inherited from TaggedUrn):
        - Keys: Always normalized to lowercase
        - Unquoted values: Normalized to lowercase
        - Quoted values: Case preserved exactly as specified
        """
        # Parse using TaggedUrn
        try:
            tagged = TaggedUrn.from_string(s)
        except TaggedUrnError as e:
            raise CapUrnError(f"Invalid cap URN: {e}") from e

        # Verify cap prefix
        if tagged.get_prefix() != cls.PREFIX:
            raise CapUrnError(f"Cap identifier must start with '{cls.PREFIX}:'")

        # Process direction tags with wildcard expansion
        in_urn = cls._process_direction_tag(tagged, "in")
        out_urn = cls._process_direction_tag(tagged, "out")

        # Validate that in and out specs are valid media URNs (or wildcard "media:")
        # After processing, "media:" is the wildcard (not "*")
        if in_urn != "media:":
            try:
                MediaUrn.from_string(in_urn)
            except MediaUrnError as e:
                raise CapUrnError(f"Invalid media URN for in spec '{in_urn}': {e}") from e

        if out_urn != "media:":
            try:
                MediaUrn.from_string(out_urn)
            except MediaUrnError as e:
                raise CapUrnError(f"Invalid media URN for out spec '{out_urn}': {e}") from e

        # Collect remaining tags (excluding in/out)
        tags = {k: v for k, v in tagged.tags.items() if k not in ("in", "out")}

        return cls(in_urn, out_urn, tags)

    def _build_tagged_urn(self) -> TaggedUrn:
        """Build a TaggedUrn representation of this CapUrn

        Internal helper for serialization and tag manipulation.
        """
        builder = TaggedUrnBuilder(self.PREFIX)
        builder.tag("in", self.in_urn)
        builder.tag("out", self.out_urn)

        for k, v in self.tags.items():
            builder.tag(k, v)

        return builder.build_allow_empty()

    def tags_to_string(self) -> str:
        """Serialize just the tags portion (without "cap:" prefix)

        Returns tags in canonical form with proper quoting and sorting.
        """
        return self._build_tagged_urn().tags_to_string()

    def to_string(self) -> str:
        """Get the canonical string representation of this cap URN

        Always includes "cap:" prefix.
        All tags (including in/out) are sorted alphabetically.
        No trailing semicolon in canonical form.
        Values are quoted only when necessary (smart quoting via TaggedUrn).
        """
        return self._build_tagged_urn().to_string()

    def get_tag(self, key: str) -> Optional[str]:
        """Get a specific tag value

        Key is normalized to lowercase for lookup.
        For 'in' and 'out', returns the direction spec fields.
        """
        key_lower = key.lower()
        if key_lower == "in":
            return self.in_urn
        elif key_lower == "out":
            return self.out_urn
        else:
            return self.tags.get(key_lower)

    def in_spec(self) -> str:
        """Get the input media URN string"""
        return self.in_urn

    def out_spec(self) -> str:
        """Get the output media URN string"""
        return self.out_urn

    def in_media_urn(self) -> MediaUrn:
        """Get the input as a parsed MediaUrn"""
        return MediaUrn.from_string(self.in_urn)

    def out_media_urn(self) -> MediaUrn:
        """Get the output as a parsed MediaUrn"""
        return MediaUrn.from_string(self.out_urn)

    def has_tag(self, key: str, value: str) -> bool:
        """Check if this cap has a specific tag with a specific value

        Key is normalized to lowercase; value comparison is case-sensitive.
        For 'in' and 'out', checks the direction spec fields.
        """
        key_lower = key.lower()
        if key_lower == "in":
            return self.in_urn == value
        elif key_lower == "out":
            return self.out_urn == value
        else:
            return self.tags.get(key_lower) == value

    def with_tag(self, key: str, value: str) -> "CapUrn":
        """Add or update a tag

        Key is normalized to lowercase; value is preserved as-is.
        Note: Cannot modify 'in' or 'out' tags - use with_in_spec/with_out_spec.
        Returns error if value is empty (use "*" for wildcard).
        """
        if not value:
            raise CapUrnError(f"Empty value for key '{key}' (use '*' for wildcard)")

        key_lower = key.lower()
        if key_lower in ("in", "out"):
            # Silently ignore attempts to set in/out via with_tag
            # Use with_in_spec/with_out_spec instead
            return CapUrn(self.in_urn, self.out_urn, self.tags)

        new_tags = self.tags.copy()
        new_tags[key_lower] = value
        return CapUrn(self.in_urn, self.out_urn, new_tags)

    def with_in_spec(self, in_urn: str) -> "CapUrn":
        """Create a new cap URN with a different input spec"""
        return CapUrn(in_urn, self.out_urn, self.tags)

    def with_out_spec(self, out_urn: str) -> "CapUrn":
        """Create a new cap URN with a different output spec"""
        return CapUrn(self.in_urn, out_urn, self.tags)

    def without_tag(self, key: str) -> "CapUrn":
        """Remove a tag

        Key is normalized to lowercase for case-insensitive removal.
        Note: Cannot remove 'in' or 'out' tags - they are required.
        """
        key_lower = key.lower()
        if key_lower in ("in", "out"):
            # Silently ignore attempts to remove in/out
            return CapUrn(self.in_urn, self.out_urn, self.tags)

        new_tags = self.tags.copy()
        new_tags.pop(key_lower, None)
        return CapUrn(self.in_urn, self.out_urn, new_tags)

    def accepts(self, request: "CapUrn") -> bool:
        """Check if this cap (pattern/handler) accepts the given request (instance).

        Direction specs use semantic TaggedUrn matching via MediaUrn:
        - Input: `cap_in.accepts(request_in)` — cap's input pattern accepts request's input
        - Output: `cap_out.conforms_to(request_out)` — cap's output conforms to request's expectation

        For other tags: cap satisfies request's tag constraints.
        Missing cap tags are wildcards (cap accepts any value for that tag).
        """
        # Input direction: self.in_urn is pattern, request.in_urn is instance
        # "media:" on the PATTERN side means "I accept any input" — skip check.
        # "media:" on the INSTANCE side is just the least specific — still check.
        if self.in_urn != "media:":
            cap_in = MediaUrn.from_string(self.in_urn)
            request_in = MediaUrn.from_string(request.in_urn)
            if not cap_in.accepts(request_in):
                return False

        # Output direction: self.out_urn is pattern, request.out_urn is instance
        # "media:" on the PATTERN side means "I accept any output" — skip check.
        # "media:" on the INSTANCE side is just the least specific — still check.
        if self.out_urn != "media:":
            cap_out = MediaUrn.from_string(self.out_urn)
            request_out = MediaUrn.from_string(request.out_urn)
            if not cap_out.conforms_to(request_out):
                return False

        # Check all tags that the pattern (self) requires.
        # The instance (request param) must satisfy every pattern constraint.
        # Missing tag in instance → instance doesn't satisfy constraint → reject.
        for self_key, self_value in self.tags.items():
            req_value = request.tags.get(self_key)
            if req_value is not None:
                if self_value == "*":
                    continue
                if req_value == "*":
                    continue
                if self_value != req_value:
                    return False
            else:
                # Instance missing a tag the pattern requires
                return False

        return True

    def conforms_to(self, cap: "CapUrn") -> bool:
        """Check if this cap URN (as a request) conforms to another cap (handler).

        Delegates to cap.accepts(self).
        """
        return cap.accepts(self)

    def accepts_str(self, request_str: str) -> bool:
        """Check if this cap accepts a string-specified request"""
        request = CapUrn.from_string(request_str)
        return self.accepts(request)

    def conforms_to_str(self, cap_str: str) -> bool:
        """Check if this cap conforms to a string-specified cap"""
        cap = CapUrn.from_string(cap_str)
        return self.conforms_to(cap)

    def specificity(self) -> int:
        """Calculate specificity score for cap matching

        More specific caps have higher scores and are preferred.
        Direction specs contribute their MediaUrn tag count (more tags = more specific).
        Other tags contribute 1 per non-wildcard value.
        """
        count = 0

        # "media:" is the wildcard (contributes 0 to specificity)
        if self.in_urn != "media:":
            in_media = MediaUrn.from_string(self.in_urn)
            count += len(in_media.inner().tags)

        if self.out_urn != "media:":
            out_media = MediaUrn.from_string(self.out_urn)
            count += len(out_media.inner().tags)

        # Count non-wildcard tags
        count += sum(1 for v in self.tags.values() if v != "*")

        return count

    def is_more_specific_than(self, other: "CapUrn") -> bool:
        """Check if this cap is more specific than another"""
        return self.specificity() > other.specificity()

    def with_wildcard_tag(self, key: str) -> "CapUrn":
        """Create a wildcard version by replacing specific values with wildcards

        For 'in' or 'out', sets the corresponding direction spec to wildcard.
        """
        key_lower = key.lower()

        if key_lower == "in":
            return CapUrn("*", self.out_urn, self.tags)
        elif key_lower == "out":
            return CapUrn(self.in_urn, "*", self.tags)
        else:
            if key_lower in self.tags:
                new_tags = self.tags.copy()
                new_tags[key_lower] = "*"
                return CapUrn(self.in_urn, self.out_urn, new_tags)
            else:
                return CapUrn(self.in_urn, self.out_urn, self.tags)

    def subset(self, keys: List[str]) -> "CapUrn":
        """Create a subset cap with only specified tags

        Note: 'in' and 'out' are always included as they are required.
        """
        new_tags = {}
        for key in keys:
            key_lower = key.lower()
            # Skip in/out as they're handled separately
            if key_lower in ("in", "out"):
                continue
            if key_lower in self.tags:
                new_tags[key_lower] = self.tags[key_lower]

        return CapUrn(self.in_urn, self.out_urn, new_tags)

    def merge(self, other: "CapUrn") -> "CapUrn":
        """Merge with another cap (other takes precedence for conflicts)

        Direction specs from other override this one's.
        """
        new_tags = self.tags.copy()
        new_tags.update(other.tags)

        return CapUrn(other.in_urn, other.out_urn, new_tags)

    @staticmethod
    def canonical(cap_urn: str) -> str:
        """Get the canonical form of a cap URN string"""
        cap = CapUrn.from_string(cap_urn)
        return cap.to_string()

    @staticmethod
    def canonical_option(cap_urn: Optional[str]) -> Optional[str]:
        """Get the canonical form of an optional cap URN string"""
        if cap_urn is not None:
            cap = CapUrn.from_string(cap_urn)
            return cap.to_string()
        return None

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"CapUrn('{self.to_string()}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CapUrn):
            return False
        return (
            self.in_urn == other.in_urn
            and self.out_urn == other.out_urn
            and self.tags == other.tags
        )

    def __hash__(self) -> int:
        return hash((self.in_urn, self.out_urn, tuple(sorted(self.tags.items()))))


class CapMatcher:
    """Cap matching and selection utilities"""

    @staticmethod
    def find_best_match(caps: List[CapUrn], request: CapUrn) -> Optional[CapUrn]:
        """Find the most specific cap that accepts a request"""
        matches = [cap for cap in caps if request.accepts(cap)]
        if not matches:
            return None
        return max(matches, key=lambda cap: cap.specificity())

    @staticmethod
    def find_all_matches(caps: List[CapUrn], request: CapUrn) -> List[CapUrn]:
        """Find all caps that match a request, sorted by specificity (most specific first)"""
        matches = [cap for cap in caps if request.accepts(cap)]
        # Sort by specificity (most specific first)
        matches.sort(key=lambda cap: cap.specificity(), reverse=True)
        return matches

    @staticmethod
    def are_compatible(caps1: List[CapUrn], caps2: List[CapUrn]) -> bool:
        """Check if two cap sets overlap (any pair where one accepts the other)"""
        return any(
            c1.accepts(c2) or c2.accepts(c1)
            for c1 in caps1
            for c2 in caps2
        )


class CapUrnBuilder:
    """Builder for creating cap URNs fluently"""

    def __init__(self):
        """Create a new builder (in_spec and out_spec are required)"""
        self._in_urn: Optional[str] = None
        self._out_urn: Optional[str] = None
        self._tags: Dict[str, str] = {}

    def in_spec(self, in_urn: str) -> "CapUrnBuilder":
        """Set the input spec (required)"""
        self._in_urn = in_urn
        return self

    def out_spec(self, out_urn: str) -> "CapUrnBuilder":
        """Set the output spec (required)"""
        self._out_urn = out_urn
        return self

    def tag(self, key: str, value: str) -> "CapUrnBuilder":
        """Add a tag with key (normalized to lowercase) and value (preserved as-is)

        Raises CapUrnError if value is empty (use "*" for wildcard).
        """
        if not value:
            raise CapUrnError(f"Empty value for key '{key}' (use '*' for wildcard)")
        self._tags[key.lower()] = value
        return self

    def solo_tag(self, key: str) -> "CapUrnBuilder":
        """Add a tag with wildcard value ("*") without requiring explicit value parameter"""
        key_lower = key.lower()
        if key_lower in ("in", "out"):
            return self
        self._tags[key_lower] = "*"
        return self

    def build(self) -> CapUrn:
        """Build the cap URN

        Raises CapUrnError if in_spec or out_spec is missing.
        """
        if self._in_urn is None:
            raise CapUrnError("Missing required 'in' spec - use in_spec() to set it")
        if self._out_urn is None:
            raise CapUrnError("Missing required 'out' spec - use out_spec() to set it")

        return CapUrn(self._in_urn, self._out_urn, self._tags)
