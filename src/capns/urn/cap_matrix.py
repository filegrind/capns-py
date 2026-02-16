"""CapSet registry for unified capability host discovery

Provides unified interface for finding cap sets (both providers and plugins)
that can satisfy capability requests using subset matching.

Also provides CapGraph for representing capabilities as a directed graph
where nodes are MediaSpec IDs and edges are capabilities that convert
from one spec to another.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import deque

from capns.cap.definition import Cap
from capns.urn.cap_urn import CapUrn
from capns.urn.media_urn import MediaUrn
from capns.cap.caller import CapSet


class CapMatrixError(Exception):
    """Base error for CapMatrix operations"""
    pass


class NoSetsFoundError(CapMatrixError):
    """No cap sets found for capability"""
    def __init__(self, cap_urn: str):
        super().__init__(f"No cap sets found for capability: {cap_urn}")
        self.cap_urn = cap_urn


class InvalidUrnError(CapMatrixError):
    """Invalid capability URN"""
    def __init__(self, urn: str):
        super().__init__(f"Invalid capability URN: {urn}")
        self.urn = urn


class RegistryError(CapMatrixError):
    """Registry error"""
    pass


# ==============================================================================
# CapGraph - Directed graph of capability conversions
# ==============================================================================

@dataclass
class CapGraphEdge:
    """An edge in the capability graph representing a conversion from one MediaSpec to another.

    Each edge corresponds to a capability that can transform data from `from_spec` format
    to `to_spec` format. The edge stores the full Cap definition for execution.
    """
    from_spec: str  # The input MediaSpec ID (e.g., "media:binary")
    to_spec: str  # The output MediaSpec ID (e.g., "media:string")
    cap: Cap  # The capability that performs this conversion
    registry_name: str  # The registry that provided this capability
    specificity: int  # Specificity score for ranking multiple paths


class CapGraph:
    """A directed graph where nodes are MediaSpec IDs and edges are capabilities.

    This graph enables discovering conversion paths between different media formats.
    For example, finding how to convert from "media:binary" to "media:string" through
    intermediate transformations.

    The graph is built from capabilities in registries, where each cap's `in_spec`
    and `out_spec` define the edge direction.
    """

    def __init__(self):
        """Create a new empty capability graph"""
        self.edges: List[CapGraphEdge] = []
        self.outgoing: Dict[str, List[int]] = {}  # from_spec -> indices into edges
        self.incoming: Dict[str, List[int]] = {}  # to_spec -> indices into edges
        self.nodes: Set[str] = set()  # All unique spec IDs

    def add_cap(self, cap: Cap, registry_name: str) -> None:
        """Add a capability as an edge in the graph.

        The cap's `in_spec` becomes the source node and `out_spec` becomes the target node.
        """
        from_spec = cap.urn.in_spec()
        to_spec = cap.urn.out_spec()
        specificity = cap.urn.specificity()

        # Add nodes
        self.nodes.add(from_spec)
        self.nodes.add(to_spec)

        # Create edge
        edge_index = len(self.edges)
        edge = CapGraphEdge(
            from_spec=from_spec,
            to_spec=to_spec,
            cap=cap,
            registry_name=registry_name,
            specificity=specificity,
        )
        self.edges.append(edge)

        # Update indices
        if from_spec not in self.outgoing:
            self.outgoing[from_spec] = []
        self.outgoing[from_spec].append(edge_index)

        if to_spec not in self.incoming:
            self.incoming[to_spec] = []
        self.incoming[to_spec].append(edge_index)

    def get_nodes(self) -> Set[str]:
        """Get all nodes (MediaSpec IDs) in the graph."""
        return self.nodes.copy()

    def get_edges(self) -> List[CapGraphEdge]:
        """Get all edges in the graph."""
        return self.edges.copy()

    def get_outgoing(self, spec: str) -> List[CapGraphEdge]:
        """Get all edges originating from a spec (all caps that take this spec as input).

        Uses MediaUrn.conforms_to() matching: returns edges where the provided spec
        conforms to the edge's from_spec requirement. This allows a specific media URN
        like "media:pdf;bytes" to match caps that accept "media:pdf".
        """
        try:
            provided_urn = MediaUrn.from_string(spec)
        except Exception:
            return []

        result = []
        for edge in self.edges:
            try:
                requirement_urn = MediaUrn.from_string(edge.from_spec)
                if provided_urn.conforms_to(requirement_urn):
                    result.append(edge)
            except Exception:
                continue

        return result

    def get_incoming(self, spec: str) -> List[CapGraphEdge]:
        """Get all edges targeting a spec (all caps that produce this spec as output).

        Uses MediaUrn.conforms_to() matching: returns edges where the edge's to_spec
        (produced output) conforms to the requested spec requirement.
        """
        try:
            requirement_urn = MediaUrn.from_string(spec)
        except Exception:
            return []

        result = []
        for edge in self.edges:
            try:
                produced_urn = MediaUrn.from_string(edge.to_spec)
                if produced_urn.conforms_to(requirement_urn):
                    result.append(edge)
            except Exception:
                continue

        return result

    def has_direct_edge(self, from_spec: str, to_spec: str) -> bool:
        """Check if there's any direct edge from one spec to another.

        Uses conforms_to() matching: from_spec must satisfy edge input, edge output must conform to to_spec.
        """
        try:
            to_requirement = MediaUrn.from_string(to_spec)
        except Exception:
            return False

        for edge in self.get_outgoing(from_spec):
            try:
                produced_urn = MediaUrn.from_string(edge.to_spec)
                if produced_urn.conforms_to(to_requirement):
                    return True
            except Exception:
                continue

        return False

    def get_direct_edges(self, from_spec: str, to_spec: str) -> List[CapGraphEdge]:
        """Get all direct edges from one spec to another.

        Returns all capabilities that can directly convert from `from_spec` to `to_spec`.
        Uses conforms_to() matching for both input and output specs.
        Sorted by specificity (highest first).
        """
        try:
            to_requirement = MediaUrn.from_string(to_spec)
        except Exception:
            return []

        edges = []
        for edge in self.get_outgoing(from_spec):
            try:
                produced_urn = MediaUrn.from_string(edge.to_spec)
                if produced_urn.conforms_to(to_requirement):
                    edges.append(edge)
            except Exception:
                continue

        # Sort by specificity (highest first)
        edges.sort(key=lambda e: e.specificity, reverse=True)
        return edges

    def can_convert(self, from_spec: str, to_spec: str) -> bool:
        """Check if a conversion path exists from one spec to another.

        Uses BFS to find if there's any path (direct or through intermediates).
        Uses conforms_to() matching for both input and output specs.
        """
        if from_spec == to_spec:
            return True

        try:
            to_requirement = MediaUrn.from_string(to_spec)
        except Exception:
            return False

        # Check if from_spec can satisfy any edge's input
        initial_edges = self.get_outgoing(from_spec)
        if not initial_edges:
            return False

        visited = set()
        queue = deque()

        # Start by checking edges from the initial spec
        for edge in initial_edges:
            try:
                produced_urn = MediaUrn.from_string(edge.to_spec)
                if produced_urn.conforms_to(to_requirement):
                    return True
            except Exception:
                pass

            if edge.to_spec not in visited:
                visited.add(edge.to_spec)
                queue.append(edge.to_spec)

        # BFS through the graph using actual node specs
        while queue:
            current = queue.popleft()
            for edge in self.get_outgoing(current):
                try:
                    produced_urn = MediaUrn.from_string(edge.to_spec)
                    if produced_urn.conforms_to(to_requirement):
                        return True
                except Exception:
                    pass

                if edge.to_spec not in visited:
                    visited.add(edge.to_spec)
                    queue.append(edge.to_spec)

        return False

    def find_path(self, from_spec: str, to_spec: str) -> Optional[List[CapGraphEdge]]:
        """Find the shortest conversion path from one spec to another.

        Returns a sequence of edges representing the conversion chain.
        Uses conforms_to() matching for both input and output specs.
        Returns None if no path exists.
        """
        if from_spec == to_spec:
            return []

        try:
            to_requirement = MediaUrn.from_string(to_spec)
        except Exception:
            return None

        # Track visited nodes and parent edges for path reconstruction
        # Key: node spec, Value: (parent node spec, edge index)
        visited: Dict[str, Optional[Tuple[str, int]]] = {}
        queue = deque()

        # Find edges that the input spec satisfies
        initial_edges = self.get_outgoing(from_spec)
        if not initial_edges:
            return None

        # Process initial edges
        for edge in initial_edges:
            edge_idx = self.edges.index(edge)

            try:
                produced_urn = MediaUrn.from_string(edge.to_spec)
                if produced_urn.conforms_to(to_requirement):
                    # Direct path found
                    return [self.edges[edge_idx]]
            except Exception:
                pass

            if edge.to_spec not in visited:
                visited[edge.to_spec] = (from_spec, edge_idx)
                queue.append(edge.to_spec)

        # BFS through the graph
        while queue:
            current = queue.popleft()
            for edge in self.get_outgoing(current):
                edge_idx = self.edges.index(edge)

                try:
                    produced_urn = MediaUrn.from_string(edge.to_spec)
                    if produced_urn.conforms_to(to_requirement):
                        # Found target - reconstruct path
                        path_indices = [edge_idx]
                        backtrack = current

                        while backtrack in visited and visited[backtrack] is not None:
                            prev, prev_edge_idx = visited[backtrack]
                            path_indices.append(prev_edge_idx)
                            backtrack = prev

                        path_indices.reverse()
                        return [self.edges[i] for i in path_indices]
                except Exception:
                    pass

                if edge.to_spec not in visited:
                    visited[edge.to_spec] = (current, edge_idx)
                    queue.append(edge.to_spec)

        return None

    def find_all_paths(
        self,
        from_spec: str,
        to_spec: str,
        max_depth: int,
    ) -> List[List[CapGraphEdge]]:
        """Find all conversion paths from one spec to another (up to a maximum depth).

        Returns all possible paths, sorted by total path length (shortest first).
        Uses conforms_to() matching for both input and output specs.
        Limits search to `max_depth` edges to prevent infinite loops in cyclic graphs.
        """
        try:
            to_requirement = MediaUrn.from_string(to_spec)
        except Exception:
            return []

        # Check if from_spec can satisfy any edge's input
        initial_edges = self.get_outgoing(from_spec)
        if not initial_edges:
            return []

        all_paths = []
        current_path: List[int] = []
        visited = set()

        self._dfs_find_paths(
            from_spec,
            to_requirement,
            max_depth,
            current_path,
            visited,
            all_paths,
        )

        # Sort by path length (shortest first)
        all_paths.sort(key=len)

        # Convert indices to edge references
        return [[self.edges[i] for i in indices] for indices in all_paths]

    def _dfs_find_paths(
        self,
        current: str,
        target: MediaUrn,
        remaining_depth: int,
        current_path: List[int],
        visited: Set[str],
        all_paths: List[List[int]],
    ) -> None:
        """DFS helper for finding all paths.

        Uses conforms_to() matching for output spec comparison.
        """
        if remaining_depth == 0:
            return

        for edge in self.get_outgoing(current):
            # Find edge index
            try:
                edge_idx = self.edges.index(edge)
            except ValueError:
                continue

            # Check if edge output conforms to target
            try:
                produced = MediaUrn.from_string(edge.to_spec)
                output_satisfies = produced.conforms_to(target)
            except Exception:
                output_satisfies = False

            if output_satisfies:
                # Found a path
                path = current_path.copy()
                path.append(edge_idx)
                all_paths.append(path)
            elif edge.to_spec not in visited:
                # Continue searching
                visited.add(edge.to_spec)
                current_path.append(edge_idx)

                self._dfs_find_paths(
                    edge.to_spec,
                    target,
                    remaining_depth - 1,
                    current_path,
                    visited,
                    all_paths,
                )

                current_path.pop()
                visited.remove(edge.to_spec)


# ==============================================================================
# CapMatrix - Registry of CapSet providers
# ==============================================================================

@dataclass
class CapSetEntry:
    """Entry for a registered capability host"""
    name: str
    host: CapSet
    capabilities: List[Cap]


class CapMatrix:
    """Registry for managing cap sets with capability discovery"""

    def __init__(self):
        """Create a new capability host registry"""
        self.sets: Dict[str, CapSetEntry] = {}

    def register_cap_set(
        self,
        name: str,
        host: CapSet,
        capabilities: List[Cap],
    ) -> None:
        """Register a capability host with its supported capabilities

        Args:
            name: Name of the cap set
            host: CapSet implementation
            capabilities: List of capabilities this set provides
        """
        entry = CapSetEntry(
            name=name,
            host=host,
            capabilities=capabilities,
        )
        self.sets[name] = entry

    def find_cap_sets(self, request_urn: str) -> List[CapSet]:
        """Find cap sets that can handle the requested capability.

        Uses subset matching: host capabilities must be a subset of or match the request.

        Args:
            request_urn: The requested capability URN

        Returns:
            List of matching CapSet implementations

        Raises:
            InvalidUrnError: If URN is invalid
            NoSetsFoundError: If no matching sets found
        """
        try:
            request = CapUrn.from_string(request_urn)
        except Exception as e:
            raise InvalidUrnError(f"{request_urn}: {e}")

        matching_sets = []

        for entry in self.sets.values():
            for cap in entry.capabilities:
                # Routing direction: request.accepts(registered_cap)
                # request is pattern, cap is instance
                if request.accepts(cap.urn):
                    matching_sets.append(entry.host)
                    break  # Found a matching capability for this host

        if not matching_sets:
            raise NoSetsFoundError(request_urn)

        return matching_sets

    def find_best_cap_set(self, request_urn: str) -> Tuple[CapSet, Cap]:
        """Find the best capability host for the request using specificity ranking.

        Returns the CapSet and the Cap definition that matched.

        Args:
            request_urn: The requested capability URN

        Returns:
            Tuple of (CapSet, Cap)

        Raises:
            InvalidUrnError: If URN is invalid
            NoSetsFoundError: If no matching sets found
        """
        try:
            request = CapUrn.from_string(request_urn)
        except Exception as e:
            raise InvalidUrnError(f"{request_urn}: {e}")

        best_match: Optional[Tuple[CapSet, Cap, int]] = None

        for entry in self.sets.values():
            for cap in entry.capabilities:
                # Routing direction: request.accepts(registered_cap)
                # request is pattern, cap is instance
                if request.accepts(cap.urn):
                    specificity = cap.urn.specificity()
                    if best_match is None or specificity > best_match[2]:
                        best_match = (entry.host, cap, specificity)
                    break  # Check next host

        if best_match is None:
            raise NoSetsFoundError(request_urn)

        return (best_match[0], best_match[1])

    def get_host_names(self) -> List[str]:
        """Get all registered capability host names"""
        return list(self.sets.keys())

    def get_all_capabilities(self) -> List[Cap]:
        """Get all capabilities from all registered sets"""
        result = []
        for entry in self.sets.values():
            result.extend(entry.capabilities)
        return result

    def get_capabilities_for_host(self, host_name: str) -> Optional[List[Cap]]:
        """Get capabilities for a specific host"""
        entry = self.sets.get(host_name)
        return entry.capabilities.copy() if entry else None

    def accepts_request(self, request_urn: str) -> bool:
        """Check if any host can accept the specified capability request"""
        try:
            self.find_cap_sets(request_urn)
            return True
        except (InvalidUrnError, NoSetsFoundError):
            return False

    def unregister_cap_set(self, name: str) -> bool:
        """Unregister a capability host

        Returns:
            True if the host was unregistered, False if not found
        """
        if name in self.sets:
            del self.sets[name]
            return True
        return False

    def clear(self) -> None:
        """Clear all registered sets"""
        self.sets.clear()


# ==============================================================================
# CapBlock - Composite registry manager
# ==============================================================================


@dataclass
class BestCapSetMatch:
    """Best match result from CapBlock"""
    cap: Cap
    specificity: int
    registry_name: str


class CompositeCapSet(CapSet):
    """Wrapper that implements CapSet for CapBlock

    This allows the composite to be used with CapCaller
    """

    def __init__(self, registries: List[Tuple[str, CapMatrix]]):
        self.registries = registries

    def execute_cap(self, cap_urn: str, arguments: List["CapArgumentValue"]) -> bytes:
        """Execute capability on the appropriate registry"""
        # Find the registry that has this cap
        for registry_name, registry in self.registries:
            try:
                host, cap = registry.find_best_cap_set(cap_urn)
                return host.execute_cap(cap_urn, arguments)
            except NoSetsFoundError:
                continue

        raise NoSetsFoundError(cap_urn)

    def graph(self) -> CapGraph:
        """Build a directed graph from all capabilities in the registries

        The graph represents all possible conversions where:
        - Nodes are MediaSpec IDs (e.g., "media:string", "media:binary")
        - Edges are capabilities that convert from one spec to another

        This enables discovering conversion paths between different media formats.
        """
        graph = CapGraph()

        for registry_name, registry in self.registries:
            for host_name in registry.get_host_names():
                caps = registry.get_capabilities_for_host(host_name)
                if caps:
                    for cap in caps:
                        graph.add_cap(cap, registry_name)

        return graph


class CapBlock:
    """Composite registry that aggregates multiple CapMatrix instances

    CapBlock allows managing multiple registries (e.g., providers and plugins)
    and selecting capabilities based on specificity across all registries.

    On specificity ties, the first registered registry wins (priority order).
    """

    def __init__(self):
        """Create a new composite registry"""
        self.registries: List[Tuple[str, CapMatrix]] = []

    def add_registry(self, name: str, registry: CapMatrix) -> None:
        """Add a child registry with a name

        Registries are checked in order of addition for tie-breaking.

        Args:
            name: Name of the registry
            registry: CapMatrix instance
        """
        self.registries.append((name, registry))

    def remove_registry(self, name: str) -> Optional[CapMatrix]:
        """Remove a child registry by name

        Args:
            name: Name of the registry to remove

        Returns:
            The removed CapMatrix if found, None otherwise
        """
        for i, (reg_name, registry) in enumerate(self.registries):
            if reg_name == name:
                return self.registries.pop(i)[1]
        return None

    def get_registry(self, name: str) -> Optional[CapMatrix]:
        """Get a child registry by name

        Args:
            name: Name of the registry

        Returns:
            The CapMatrix if found, None otherwise
        """
        for reg_name, registry in self.registries:
            if reg_name == name:
                return registry
        return None

    def find_best_cap_set(self, request_urn: str) -> BestCapSetMatch:
        """Find the best capability host across ALL child registries

        This method polls all registries and compares their best matches
        by specificity. Returns the cap definition and specificity of the best match.
        On specificity tie, returns the match from the first registry (priority order).

        Args:
            request_urn: The requested capability URN

        Returns:
            BestCapSetMatch with cap, specificity, and registry name

        Raises:
            InvalidUrnError: If URN is invalid
            NoSetsFoundError: If no matching sets found
        """
        try:
            request = CapUrn.from_string(request_urn)
        except Exception as e:
            raise InvalidUrnError(f"{request_urn}: {e}")

        best_overall: Optional[BestCapSetMatch] = None

        for registry_name, registry in self.registries:
            # Find the best match within this registry
            try:
                host, cap = registry.find_best_cap_set(request_urn)
                specificity = cap.urn.specificity()

                candidate = BestCapSetMatch(
                    cap=cap,
                    specificity=specificity,
                    registry_name=registry_name,
                )

                if best_overall is None:
                    best_overall = candidate
                elif specificity > best_overall.specificity:
                    # Only replace if strictly more specific
                    # On tie, keep the first one (priority order)
                    best_overall = candidate

            except (InvalidUrnError, NoSetsFoundError):
                # This registry doesn't have a match, continue to next
                continue

        if best_overall is None:
            raise NoSetsFoundError(request_urn)

        return best_overall

    def accepts_request(self, request_urn: str) -> bool:
        """Check if any registry can accept the specified capability request

        Args:
            request_urn: The requested capability URN

        Returns:
            True if any registry can accept it, False otherwise
        """
        try:
            self.find_best_cap_set(request_urn)
            return True
        except (InvalidUrnError, NoSetsFoundError):
            return False

    def get_registry_names(self) -> List[str]:
        """Get names of all child registries

        Returns:
            List of registry names
        """
        return [name for name, _ in self.registries]

    def graph(self) -> CapGraph:
        """Build a directed graph from all capabilities in all registries

        Returns:
            CapGraph instance with all capabilities
        """
        composite = CompositeCapSet(self.registries)
        return composite.graph()
