"""Unified cap-based manifest interface

This module defines the unified manifest interface with standardized cap-based declarations.
"""

import json
from typing import List, Optional, Dict, Any
from capns.cap.definition import Cap


class CapManifest:
    """Unified cap manifest for component output

    A manifest includes:
    - Component metadata (name, version, description)
    - List of capabilities
    - Optional author and page URL
    """

    def __init__(self, name: str, version: str, description: str, caps: List[Cap]):
        self.name = name
        self.version = version
        self.description = description
        self.caps = caps
        self.author: Optional[str] = None
        self.page_url: Optional[str] = None

    def with_author(self, author: str) -> "CapManifest":
        """Set the author of the component"""
        self.author = author
        return self

    def with_page_url(self, page_url: str) -> "CapManifest":
        """Set the page URL for the component"""
        self.page_url = page_url
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        result = {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "caps": [cap.to_dict() for cap in self.caps],
        }

        if self.author is not None:
            result["author"] = self.author

        if self.page_url is not None:
            result["page_url"] = self.page_url

        return result

    def to_json(self) -> str:
        """Serialize to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapManifest":
        """Parse from dict"""
        manifest = cls(
            name=data["name"],
            version=data["version"],
            description=data["description"],
            caps=[Cap.from_dict(c) for c in data["caps"]],
        )

        if "author" in data:
            manifest.author = data["author"]

        if "page_url" in data:
            manifest.page_url = data["page_url"]

        return manifest

    @classmethod
    def from_json(cls, json_str: str) -> "CapManifest":
        """Parse from JSON string"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> None:
        """Validate that this manifest has CAP_IDENTITY.

        Raises ValueError if identity cap is missing.
        """
        from capns.urn.cap_urn import CapUrn
        from capns.standard.caps import CAP_IDENTITY

        identity_urn = CapUrn.from_string(CAP_IDENTITY)
        has_identity = any(identity_urn.conforms_to(cap.urn) for cap in self.caps)
        if not has_identity:
            raise ValueError(f"Manifest missing required CAP_IDENTITY ({CAP_IDENTITY})")

    def ensure_identity(self) -> "CapManifest":
        """Ensure CAP_IDENTITY is present in this manifest. Adds it if missing.

        Returns self for method chaining.
        """
        from capns.urn.cap_urn import CapUrn
        from capns.standard.caps import CAP_IDENTITY

        identity_urn = CapUrn.from_string(CAP_IDENTITY)
        has_identity = any(identity_urn.conforms_to(cap.urn) for cap in self.caps)

        if not has_identity:
            identity_cap = Cap(
                urn=identity_urn,
                title="Identity",
                command="identity"
            )
            self.caps.insert(0, identity_cap)

        return self
