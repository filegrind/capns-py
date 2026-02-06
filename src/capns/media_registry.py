"""Media URN Registry - Remote lookup and caching for media specs

This module provides the `MediaUrnRegistry` which handles:
- Remote lookup of media specs via `https://capns.org/media:xxx`
- Two-level caching (in-memory dict + disk with TTL)
- Bundled standard media specs

## Resolution Order
1. In-memory cache (fastest)
2. Disk cache (if not expired)
3. Remote registry fetch

## Usage
```python
registry = await MediaUrnRegistry.new()
spec = await registry.get_media_spec("media:pdf;bytes")
print(f"Title: {spec.title}")
```
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import quote as url_encode
import threading

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from capns.media_urn import MediaUrn
from capns.registry import RegistryConfig


CACHE_DURATION_HOURS = 24


def normalize_media_urn(urn: str) -> str:
    """Normalize a media URN for consistent lookups and caching"""
    try:
        parsed = MediaUrn.from_string(urn)
        return parsed.to_string()
    except Exception:
        # If parsing fails, return original URN
        return urn


class StoredMediaSpec:
    """Stored media spec format (matches registry API response)"""

    def __init__(
        self,
        urn: str,
        media_type: str,
        title: str,
        profile_uri: Optional[str] = None,
        schema: Optional[Any] = None,
        description: Optional[str] = None,
        validation: Optional[Dict] = None,
        metadata: Optional[Any] = None,
        extensions: Optional[List[str]] = None,
    ):
        self.urn = urn
        self.media_type = media_type
        self.title = title
        self.profile_uri = profile_uri
        self.schema = schema
        self.description = description
        self.validation = validation
        self.metadata = metadata
        self.extensions = extensions or []

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
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
    def from_dict(cls, data: Dict) -> "StoredMediaSpec":
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


class MediaCacheEntry:
    """Cache entry with TTL"""

    def __init__(self, spec: StoredMediaSpec, cached_at: int, ttl_hours: int):
        self.spec = spec
        self.cached_at = cached_at
        self.ttl_hours = ttl_hours

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        now = int(time.time())
        return now > self.cached_at + (self.ttl_hours * 3600)

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        return {
            "spec": self.spec.to_dict(),
            "cached_at": self.cached_at,
            "ttl_hours": self.ttl_hours,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "MediaCacheEntry":
        """Parse from dict"""
        return cls(
            spec=StoredMediaSpec.from_dict(data["spec"]),
            cached_at=data["cached_at"],
            ttl_hours=data["ttl_hours"],
        )


class MediaRegistryError(Exception):
    """Base exception for media registry errors"""
    pass


class HttpError(MediaRegistryError):
    """HTTP request error"""
    pass


class NotFoundError(MediaRegistryError):
    """Media spec not found in registry"""
    pass


class ParseError(MediaRegistryError):
    """Failed to parse registry response"""
    pass


class CacheError(MediaRegistryError):
    """Cache operation error"""
    pass


class ExtensionNotFoundError(MediaRegistryError):
    """Extension not found in registry"""
    pass


class MediaUrnRegistry:
    """Media URN Registry for looking up and caching media specs"""

    def __init__(
        self,
        cache_dir: Path,
        config: RegistryConfig,
        client: Optional["httpx.AsyncClient"] = None,
    ):
        """Internal constructor - use new() or with_config() instead"""
        if not HTTPX_AVAILABLE and client is None:
            raise ImportError("httpx is required for registry operations. Install with: pip install httpx")

        self.cache_dir = cache_dir
        self.config = config
        self.client = client
        self.cached_specs: Dict[str, StoredMediaSpec] = {}
        self.extension_index: Dict[str, List[str]] = {}
        self.cache_lock = threading.Lock()

    @classmethod
    async def new(cls) -> "MediaUrnRegistry":
        """Create a new MediaUrnRegistry with standard media specs bundled

        Uses configuration from environment variables or defaults:
        - `CAPNS_REGISTRY_URL`: Base URL for the registry (default: https://capns.org)
        - `CAPNS_SCHEMA_BASE_URL`: Base URL for schemas (default: {registry_url}/schema)
        """
        return await cls.with_config(RegistryConfig())

    @classmethod
    async def with_config(cls, config: RegistryConfig) -> "MediaUrnRegistry":
        """Create a new MediaUrnRegistry with custom configuration"""
        cache_dir = cls._get_cache_dir()
        cache_dir.mkdir(parents=True, exist_ok=True)

        if HTTPX_AVAILABLE:
            client = httpx.AsyncClient(timeout=10.0)
        else:
            client = None

        registry = cls(cache_dir, config, client)

        # Load all cached specs into memory
        registry._load_all_cached_specs()

        # Install bundled standard media specs
        await registry._install_standard_specs()

        return registry

    @staticmethod
    def _get_cache_dir() -> Path:
        """Get the cache directory path"""
        if os.name == 'nt':  # Windows
            cache_base = Path(os.getenv('LOCALAPPDATA', os.path.expanduser('~/.cache')))
        elif os.name == 'posix':  # Unix-like
            cache_base = Path(os.getenv('XDG_CACHE_HOME', os.path.expanduser('~/.cache')))
        else:
            cache_base = Path.home() / '.cache'

        return cache_base / 'capns' / 'media'

    def _load_all_cached_specs(self) -> None:
        """Load all cached specs from disk into memory"""
        if not self.cache_dir.exists():
            return

        for cache_file in self.cache_dir.glob('*.json'):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)

                cache_entry = MediaCacheEntry.from_dict(data)

                if cache_entry.is_expired():
                    # Remove expired cache file
                    cache_file.unlink(missing_ok=True)
                    continue

                normalized_urn = normalize_media_urn(cache_entry.spec.urn)

                with self.cache_lock:
                    self.cached_specs[normalized_urn] = cache_entry.spec
                    self._update_extension_index(cache_entry.spec)

            except Exception as e:
                print(f"[WARN] Failed to load cache file {cache_file}: {e}")
                # Try to remove invalid cache file
                cache_file.unlink(missing_ok=True)

    def _build_extension_index(self, specs: Dict[str, StoredMediaSpec]) -> Dict[str, List[str]]:
        """Build extension index from a map of specs"""
        index: Dict[str, List[str]] = {}
        for spec in specs.values():
            for ext in spec.extensions:
                ext_lower = ext.lower()
                if ext_lower not in index:
                    index[ext_lower] = []
                index[ext_lower].append(spec.urn)
        return index

    def _update_extension_index(self, spec: StoredMediaSpec) -> None:
        """Update the extension index with a single spec"""
        for ext in spec.extensions:
            ext_lower = ext.lower()
            if ext_lower not in self.extension_index:
                self.extension_index[ext_lower] = []
            if spec.urn not in self.extension_index[ext_lower]:
                self.extension_index[ext_lower].append(spec.urn)

    async def _install_standard_specs(self) -> None:
        """Install bundled standard media specs to cache if they don't exist

        In Python, we load standard specs from the bundled data directory
        adjacent to the Rust implementation.
        """
        # Try to find standard media specs directory
        standard_dir = Path(__file__).parent.parent.parent.parent.parent / "capns" / "standard" / "media"

        if not standard_dir.exists():
            # Alternative: look in sibling directory
            standard_dir = Path(__file__).parent.parent.parent.parent / "standard" / "media"

        if not standard_dir.exists():
            # No bundled specs available, skip
            return

        for spec_file in standard_dir.glob("*.json"):
            try:
                with open(spec_file, 'r') as f:
                    data = json.load(f)

                spec = StoredMediaSpec.from_dict(data)
                normalized_urn = normalize_media_urn(spec.urn)

                # Check if this spec is already cached
                cache_file = self._cache_file_path(normalized_urn)
                if not cache_file.exists():
                    # Create cache entry
                    cache_entry = MediaCacheEntry(
                        spec=spec,
                        cached_at=int(time.time()),
                        ttl_hours=CACHE_DURATION_HOURS,
                    )

                    with open(cache_file, 'w') as f:
                        json.dump(cache_entry.to_dict(), f, indent=2)

                    # Update extension index
                    with self.cache_lock:
                        self._update_extension_index(spec)
                        self.cached_specs[normalized_urn] = spec
                else:
                    # Spec already cached, ensure extension index is up to date
                    with self.cache_lock:
                        if normalized_urn in self.cached_specs:
                            self._update_extension_index(self.cached_specs[normalized_urn])

            except Exception as e:
                print(f"[WARN] Failed to install media spec {spec_file.name}: {e}")
                continue

    def get_standard_specs(self) -> List[StoredMediaSpec]:
        """Get all bundled standard media specs without network access"""
        standard_dir = Path(__file__).parent.parent.parent.parent.parent / "capns" / "standard" / "media"

        if not standard_dir.exists():
            standard_dir = Path(__file__).parent.parent.parent.parent / "standard" / "media"

        if not standard_dir.exists():
            return []

        specs = []
        for spec_file in standard_dir.glob("*.json"):
            try:
                with open(spec_file, 'r') as f:
                    data = json.load(f)
                spec = StoredMediaSpec.from_dict(data)
                specs.append(spec)
            except Exception as e:
                print(f"[WARN] Failed to load media spec {spec_file.name}: {e}")
                continue

        return specs

    async def get_media_spec(self, urn: str) -> StoredMediaSpec:
        """Get a media spec from cache or fetch from registry

        Args:
            urn: The media URN string

        Returns:
            The media spec

        Raises:
            NotFoundError: If the media spec is not found
            HttpError: If network request fails
            ParseError: If response parsing fails
        """
        normalized_urn = normalize_media_urn(urn)

        # Check in-memory cache first
        with self.cache_lock:
            if normalized_urn in self.cached_specs:
                return self.cached_specs[normalized_urn]

        # Not in cache, fetch from registry
        spec = await self._fetch_from_registry(urn)

        # Update extension index
        with self.cache_lock:
            self._update_extension_index(spec)
            self.cached_specs[normalized_urn] = spec

        return spec

    async def get_media_specs(self, urns: List[str]) -> List[StoredMediaSpec]:
        """Get multiple media specs at once

        Args:
            urns: List of media URN strings

        Returns:
            List of media specs in the same order

        Raises:
            NotFoundError: If any media spec is not found
        """
        specs = []
        for urn in urns:
            spec = await self.get_media_spec(urn)
            specs.append(spec)
        return specs

    async def get_cached_specs(self) -> List[StoredMediaSpec]:
        """Get all currently cached media specs

        Returns:
            List of all cached media specs
        """
        with self.cache_lock:
            return list(self.cached_specs.values())

    def get_cached_spec(self, urn: str) -> Optional[StoredMediaSpec]:
        """Check if a media spec exists in the in-memory cache only (synchronous, no network)

        Returns Some(spec) if found in cache, None otherwise.
        This is useful for validation when network is unavailable.

        Args:
            urn: The media URN string

        Returns:
            The media spec if found in cache, None otherwise
        """
        normalized_urn = normalize_media_urn(urn)
        with self.cache_lock:
            return self.cached_specs.get(normalized_urn)

    def media_urns_for_extension(self, extension: str) -> List[str]:
        """Look up all media URNs that match a file extension (synchronous, no network)

        Returns all media URNs registered for the given file extension.
        Multiple URNs may match the same extension (e.g., with different form= parameters).

        The extension should NOT include the leading dot (e.g., "pdf" not ".pdf").
        Lookup is case-insensitive.

        Args:
            extension: File extension without leading dot

        Returns:
            List of media URN strings

        Raises:
            ExtensionNotFoundError: If no media spec is registered for the extension
        """
        ext_lower = extension.lower()
        with self.cache_lock:
            if ext_lower not in self.extension_index:
                raise ExtensionNotFoundError(
                    f"No media spec registered for extension '{extension}'. "
                    f"Ensure the media spec is defined in capns_dot_org/standard/media/ with an 'extension' field."
                )
            return self.extension_index[ext_lower].copy()

    def get_extension_mappings(self) -> List[tuple]:
        """Get all registered extensions and their corresponding media URNs (synchronous)

        Returns a list of (extension, urns) tuples for debugging and introspection.

        Returns:
            List of (extension, urns) tuples
        """
        with self.cache_lock:
            return [(k, v.copy()) for k, v in self.extension_index.items()]

    def _cache_key(self, urn: str) -> str:
        """Generate a cache key for a media URN"""
        normalized_urn = normalize_media_urn(urn)
        hasher = hashlib.sha256()
        hasher.update(normalized_urn.encode('utf-8'))
        return hasher.hexdigest()

    def _cache_file_path(self, urn: str) -> Path:
        """Get the cache file path for a URN"""
        key = self._cache_key(urn)
        return self.cache_dir / f"{key}.json"

    def _save_to_cache(self, spec: StoredMediaSpec) -> None:
        """Save a media spec to the filesystem cache"""
        cache_file = self._cache_file_path(spec.urn)

        cache_entry = MediaCacheEntry(
            spec=spec,
            cached_at=int(time.time()),
            ttl_hours=CACHE_DURATION_HOURS,
        )

        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_entry.to_dict(), f, indent=2)
        except Exception as e:
            raise CacheError(f"Failed to write cache file: {e}")

    async def _fetch_from_registry(self, urn: str) -> StoredMediaSpec:
        """Fetch a media spec from the remote registry"""
        if not HTTPX_AVAILABLE or self.client is None:
            raise HttpError("httpx not available - cannot fetch from registry")

        normalized_urn = normalize_media_urn(urn)

        # URL-encode only the tags part (after "media:")
        tags_part = normalized_urn[6:] if normalized_urn.startswith("media:") else normalized_urn
        encoded_tags = url_encode(tags_part, safe='')
        url = f"{self.config.registry_base_url}/media:{encoded_tags}"

        try:
            response = await self.client.get(url)

            if not response.is_success:
                raise NotFoundError(
                    f"Media spec '{urn}' not found in registry (HTTP {response.status_code})"
                )

            spec_data = response.json()
            spec = StoredMediaSpec.from_dict(spec_data)

            # Cache the result
            self._save_to_cache(spec)

            return spec

        except httpx.HTTPError as e:
            raise HttpError(f"Failed to fetch from registry: {e}")
        except (json.JSONDecodeError, KeyError) as e:
            raise ParseError(f"Failed to parse registry response for '{urn}': {e}")

    async def media_spec_exists(self, urn: str) -> bool:
        """Check if a media URN exists in registry (cached or online)

        Args:
            urn: The media URN string

        Returns:
            True if the media spec exists, False otherwise
        """
        try:
            await self.get_media_spec(urn)
            return True
        except (NotFoundError, HttpError, ParseError):
            return False

    def clear_cache(self) -> None:
        """Clear all cached media specs and extension index

        Raises:
            CacheError: If clearing fails
        """
        # Clear in-memory cache
        with self.cache_lock:
            self.cached_specs.clear()
            self.extension_index.clear()

        # Clear filesystem cache
        if self.cache_dir.exists():
            import shutil
            try:
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise CacheError(f"Failed to clear cache directory: {e}")

    @classmethod
    def new_for_test(cls, cache_dir: Path) -> "MediaUrnRegistry":
        """Create a lightweight MediaUrnRegistry for testing purposes

        This skips the standard spec installation and uses a provided cache directory.
        Available for downstream tests as well.

        Args:
            cache_dir: Directory to use for caching

        Returns:
            MediaUrnRegistry instance
        """
        cache_dir.mkdir(parents=True, exist_ok=True)

        client = httpx.AsyncClient(timeout=10.0) if HTTPX_AVAILABLE else None

        return cls(cache_dir, RegistryConfig(), client)
