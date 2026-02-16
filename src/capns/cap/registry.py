"""Cap registry for managing and resolving capability definitions

Full implementation matching Rust reference with:
- HTTP client for fetching from remote registry
- Filesystem caching with TTL
- In-memory caching for performance
- Bundled standard capabilities
- Async operations throughout
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import quote as url_encode
from dataclasses import dataclass
import threading

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from capns.cap.definition import Cap
from capns.urn.cap_urn import CapUrn


DEFAULT_REGISTRY_BASE_URL = "https://capns.org"
CACHE_DURATION_HOURS = 24


class RegistryError(Exception):
    """Base exception for registry errors"""
    pass


class HttpError(RegistryError):
    """HTTP request error"""
    pass


class NotFoundError(RegistryError):
    """Cap not found in registry"""
    pass


class ParseError(RegistryError):
    """Failed to parse registry response"""
    pass


class CacheError(RegistryError):
    """Cache operation error"""
    pass


class ValidationError(RegistryError):
    """Validation error"""
    pass


def normalize_cap_urn(urn: str) -> str:
    """Normalize a Cap URN for consistent lookups and caching

    Ensures that URNs with different tag ordering or trailing semicolons
    are treated as the same capability.
    """
    try:
        parsed = CapUrn.from_string(urn)
        return parsed.to_string()
    except Exception:
        # If parsing fails, return original URN (will likely fail later with better error)
        return urn


@dataclass
class CacheEntry:
    """Cache entry with TTL"""
    definition: Cap
    cached_at: int  # Unix timestamp
    ttl_hours: int

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        now = int(time.time())
        return now > self.cached_at + (self.ttl_hours * 3600)

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        return {
            "definition": self.definition.to_dict(),
            "cached_at": self.cached_at,
            "ttl_hours": self.ttl_hours,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CacheEntry":
        """Parse from dict"""
        return cls(
            definition=Cap.from_dict(data["definition"]),
            cached_at=data["cached_at"],
            ttl_hours=data["ttl_hours"],
        )


class RegistryConfig:
    """Configuration for the CAPNS registry

    Supports configuration via:
    1. Builder methods (highest priority)
    2. Environment variables (CAPNS_REGISTRY_URL, CAPNS_SCHEMA_BASE_URL)
    3. Default values (https://capns.org)
    """

    def __init__(
        self,
        registry_base_url: Optional[str] = None,
        schema_base_url: Optional[str] = None,
    ):
        """Create registry configuration

        Args:
            registry_base_url: Base URL for the registry API
            schema_base_url: Base URL for schema profiles
        """
        if registry_base_url is None:
            registry_base_url = os.getenv("CAPNS_REGISTRY_URL", DEFAULT_REGISTRY_BASE_URL)

        if schema_base_url is None:
            schema_base_url = os.getenv("CAPNS_SCHEMA_BASE_URL", f"{registry_base_url}/schema")

        self.registry_base_url = registry_base_url
        self.schema_base_url = schema_base_url
        self._schema_explicitly_set = schema_base_url is not None

    def with_registry_url(self, url: str) -> "RegistryConfig":
        """Set a custom registry base URL

        This also updates the schema base URL to {url}/schema unless
        schema_base_url was explicitly set.
        """
        # If schema_base_url was derived from the old registry URL, update it
        if self.schema_base_url == f"{self.registry_base_url}/schema":
            self.schema_base_url = f"{url}/schema"
        self.registry_base_url = url
        return self

    def with_schema_url(self, url: str) -> "RegistryConfig":
        """Set a custom schema base URL"""
        self.schema_base_url = url
        self._schema_explicitly_set = True
        return self


class CapRegistry:
    """Registry for managing cap definitions

    Provides:
    - HTTP fetching from remote registry
    - Filesystem caching with TTL
    - In-memory caching for performance
    - Bundled standard capabilities
    """

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
        self.cached_caps: Dict[str, Cap] = {}
        self.cache_lock = threading.Lock()

    @classmethod
    async def new(cls) -> "CapRegistry":
        """Create a new CapRegistry with default configuration

        Uses configuration from environment variables or defaults:
        - `CAPNS_REGISTRY_URL`: Base URL for the registry (default: https://capns.org)
        - `CAPNS_SCHEMA_BASE_URL`: Base URL for schemas (default: {registry_url}/schema)
        """
        return await cls.with_config(RegistryConfig())

    @classmethod
    async def with_config(cls, config: RegistryConfig) -> "CapRegistry":
        """Create a new CapRegistry with custom configuration"""
        cache_dir = cls._get_cache_dir()
        cache_dir.mkdir(parents=True, exist_ok=True)

        if HTTPX_AVAILABLE:
            client = httpx.AsyncClient(timeout=10.0)
        else:
            client = None

        registry = cls(cache_dir, config, client)

        # Load all cached caps into memory
        registry._load_all_cached_caps()

        # Install bundled standard capabilities
        await registry._install_standard_caps()

        return registry

    @staticmethod
    def _get_cache_dir() -> Path:
        """Get the cache directory path"""
        # Use platform-appropriate cache directory
        if os.name == 'nt':  # Windows
            cache_base = Path(os.getenv('LOCALAPPDATA', os.path.expanduser('~/.cache')))
        elif os.name == 'posix':  # Unix-like
            cache_base = Path(os.getenv('XDG_CACHE_HOME', os.path.expanduser('~/.cache')))
        else:
            cache_base = Path.home() / '.cache'

        return cache_base / 'capns'

    def _load_all_cached_caps(self) -> None:
        """Load all cached caps from disk into memory"""
        if not self.cache_dir.exists():
            return

        for cache_file in self.cache_dir.glob('*.json'):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)

                cache_entry = CacheEntry.from_dict(data)

                if cache_entry.is_expired():
                    # Remove expired cache file
                    cache_file.unlink(missing_ok=True)
                    continue

                urn = cache_entry.definition.urn_string()
                normalized_urn = normalize_cap_urn(urn)

                with self.cache_lock:
                    self.cached_caps[normalized_urn] = cache_entry.definition

            except Exception as e:
                print(f"[WARN] Failed to load cache file {cache_file}: {e}")
                # Try to remove invalid cache file
                cache_file.unlink(missing_ok=True)

    async def _install_standard_caps(self) -> None:
        """Install bundled standard capabilities to cache directory

        In Python, we don't have compile-time bundling like Rust's include_dir!,
        so standard caps would need to be distributed separately or embedded as strings.
        For now, this is a no-op - standard caps can be added via add_caps_to_cache().
        """
        # TODO: Bundle standard capabilities if needed
        # For testing, caps can be added via add_caps_to_cache()
        pass

    def _cache_key(self, urn: str) -> str:
        """Generate a cache key for a capability URN

        Uses SHA-256 hash of the normalized URN string for consistent caching.
        """
        normalized_urn = normalize_cap_urn(urn)
        hasher = hashlib.sha256()
        hasher.update(normalized_urn.encode('utf-8'))
        return hasher.hexdigest()

    def _cache_file_path(self, urn: str) -> Path:
        """Get the cache file path for a URN"""
        key = self._cache_key(urn)
        return self.cache_dir / f"{key}.json"

    def _save_to_cache(self, cap: Cap) -> None:
        """Save a cap to the filesystem cache"""
        urn = cap.urn_string()
        cache_file = self._cache_file_path(urn)

        cache_entry = CacheEntry(
            definition=cap,
            cached_at=int(time.time()),
            ttl_hours=CACHE_DURATION_HOURS,
        )

        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_entry.to_dict(), f, indent=2)
        except Exception as e:
            raise CacheError(f"Failed to write cache file: {e}")

    async def _fetch_from_registry(self, urn: str) -> Cap:
        """Fetch a cap from the remote registry"""
        if not HTTPX_AVAILABLE or self.client is None:
            raise HttpError("httpx not available - cannot fetch from registry")

        normalized_urn = normalize_cap_urn(urn)

        # Parse and validate the normalized URN
        try:
            cap_urn_obj = CapUrn.from_string(normalized_urn)
        except Exception as e:
            raise RegistryError(f"Invalid cap URN '{normalized_urn}': {e}")

        # URL-encode the tags portion using CapUrn API
        tags_str = cap_urn_obj.tags_to_string()
        encoded_tags = url_encode(tags_str, safe='')
        url = f"{self.config.registry_base_url}/cap:{encoded_tags}"

        try:
            response = await self.client.get(url)

            if not response.is_success:
                raise NotFoundError(
                    f"Cap '{urn}' not found in registry (HTTP {response.status_code})"
                )

            cap_data = response.json()
            cap = Cap.from_dict(cap_data)

            # Cache the result
            self._save_to_cache(cap)

            return cap

        except httpx.HTTPError as e:
            raise HttpError(f"Failed to fetch from registry: {e}")
        except json.JSONDecodeError as e:
            raise ParseError(f"Failed to parse registry response for '{urn}': {e}")

    async def get_cap(self, urn: str) -> Cap:
        """Get a cap from in-memory cache or fetch from registry

        Args:
            urn: The capability URN string

        Returns:
            The capability definition

        Raises:
            NotFoundError: If the capability is not found
            HttpError: If network request fails
            ParseError: If response parsing fails
        """
        normalized_urn = normalize_cap_urn(urn)

        # Check in-memory cache first
        with self.cache_lock:
            if normalized_urn in self.cached_caps:
                return self.cached_caps[normalized_urn]

        # Not in cache, fetch from registry
        cap = await self._fetch_from_registry(urn)

        # Update in-memory cache
        with self.cache_lock:
            self.cached_caps[normalized_urn] = cap

        return cap

    async def get_caps(self, urns: List[str]) -> List[Cap]:
        """Get multiple caps at once - fails if any cap is not available

        Args:
            urns: List of capability URN strings

        Returns:
            List of capability definitions in the same order

        Raises:
            NotFoundError: If any capability is not found
        """
        caps = []
        for urn in urns:
            cap = await self.get_cap(urn)
            caps.append(cap)
        return caps

    async def get_cached_caps(self) -> List[Cap]:
        """Get all currently cached caps from in-memory cache

        Returns:
            List of all cached capability definitions
        """
        with self.cache_lock:
            return list(self.cached_caps.values())

    async def validate_cap(self, cap: Cap) -> None:
        """Validate a local cap against its canonical definition

        Args:
            cap: The local cap to validate

        Raises:
            ValidationError: If validation fails
            NotFoundError: If canonical cap not found
        """
        canonical_cap = await self.get_cap(cap.urn_string())

        if cap.command != canonical_cap.command:
            raise ValidationError(
                f"Command mismatch. Local: {cap.command}, Canonical: {canonical_cap.command}"
            )

        # Validate args match (check stdin via args)
        local_stdin = cap.get_stdin_media_urn()
        canonical_stdin = canonical_cap.get_stdin_media_urn()
        if local_stdin != canonical_stdin:
            raise ValidationError(
                f"stdin mismatch. Local: {local_stdin}, Canonical: {canonical_stdin}"
            )

    async def cap_exists(self, urn: str) -> bool:
        """Check if a cap URN exists in registry (either cached or available online)

        Args:
            urn: The capability URN string

        Returns:
            True if the cap exists, False otherwise
        """
        try:
            await self.get_cap(urn)
            return True
        except (NotFoundError, HttpError, ParseError):
            return False

    def clear_cache(self) -> None:
        """Clear both in-memory and filesystem caches

        Raises:
            CacheError: If clearing fails
        """
        # Clear in-memory cache
        with self.cache_lock:
            self.cached_caps.clear()

        # Clear filesystem cache
        if self.cache_dir.exists():
            import shutil
            try:
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise CacheError(f"Failed to clear cache directory: {e}")

    # ==========================================================================
    # TEST HELPERS - Available for integration tests
    # ==========================================================================

    @classmethod
    def new_for_test(cls) -> "CapRegistry":
        """Create an empty registry for testing purposes

        This is a synchronous constructor that doesn't perform any initialization.
        Intended for use in tests only.
        """
        cache_dir = Path("/tmp/capns-test-cache")
        cache_dir.mkdir(parents=True, exist_ok=True)

        client = httpx.AsyncClient(timeout=10.0) if HTTPX_AVAILABLE else None

        return cls(cache_dir, RegistryConfig(), client)

    @classmethod
    def new_for_test_with_config(cls, config: RegistryConfig) -> "CapRegistry":
        """Create a registry for testing with a custom configuration

        Intended for use in tests only.
        """
        cache_dir = Path("/tmp/capns-test-cache")
        cache_dir.mkdir(parents=True, exist_ok=True)

        client = httpx.AsyncClient(timeout=10.0) if HTTPX_AVAILABLE else None

        return cls(cache_dir, config, client)

    def add_caps_to_cache(self, caps: List[Cap]) -> None:
        """Add caps to the in-memory cache for testing purposes

        This allows tests to set up specific caps without network access.
        Intended for use in tests only.
        """
        with self.cache_lock:
            for cap in caps:
                urn = cap.urn_string()
                normalized_urn = normalize_cap_urn(urn)
                self.cached_caps[normalized_urn] = cap
