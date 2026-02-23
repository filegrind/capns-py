"""Tests for cap_matrix - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns import (
    Cap, CapUrn, CapOutput, CapSet, CapArgumentValue,
    CapGraph, CapGraphEdge, CapMatrix, CapBlock, BestCapSetMatch,
    CapMatrixError, NoSetsFoundError, InvalidUrnError,
    MEDIA_STRING, MEDIA_VOID,
)


class MockCapSet(CapSet):
    """Mock CapSet for testing"""

    def __init__(self, name: str):
        self.name = name

    def execute_cap(self, cap_urn: str, arguments: list[CapArgumentValue]) -> bytes:
        """Mock execute - not used in these tests"""
        return b"mock result"


def make_test_urn(tags: str) -> str:
    """Helper to create test cap URNs"""
    return f'cap:in="media:void";{tags};out="media:string"'


def make_cap(urn_str: str, title: str, output_media: str = MEDIA_STRING) -> Cap:
    """Helper to create Cap with proper constructor"""
    cap = Cap(urn=CapUrn.from_string(urn_str), title=title, command="test")
    cap.output = CapOutput(output_media, f"{title} output")
    return cap


# TEST117: Test registering cap set and finding by exact and subset matching
def test_117_register_and_find_cap_set():
    registry = CapMatrix()

    host = MockCapSet("test-host")
    cap = make_cap(make_test_urn("op=test;basic"), "Test Basic Capability")

    registry.register_cap_set("test-host", host, [cap])

    # Test exact match
    sets = registry.find_cap_sets(make_test_urn("op=test;basic"))
    assert len(sets) == 1

    # Test no match: request has extra requirements (model=gpt-4) that registered cap doesn't satisfy
    # Routing direction: request.accepts(registered_cap) — request pattern requires "model", cap missing it → reject
    with pytest.raises(NoSetsFoundError):
        registry.find_cap_sets(make_test_urn("op=test;basic;model=gpt-4"))

    # Test no match: different op value
    with pytest.raises(NoSetsFoundError):
        registry.find_cap_sets(make_test_urn("op=different"))


# TEST118: Test selecting best cap set based on specificity ranking
def test_118_best_cap_set_selection():
    registry = CapMatrix()

    # Register general host
    general_host = MockCapSet("general")
    general_cap = make_cap(make_test_urn("op=generate"), "General Generation Capability")

    # Register specific host
    specific_host = MockCapSet("specific")
    specific_cap = make_cap(make_test_urn("op=generate;text;model=gpt-4"), "Specific Text Generation Capability")

    registry.register_cap_set("general", general_host, [general_cap])
    registry.register_cap_set("specific", specific_host, [specific_cap])

    # Request with minimal requirements should match both, but pick the more specific one
    # Routing: request(op=generate) accepts both caps (both have "op")
    best_host, best_cap = registry.find_best_cap_set(make_test_urn("op=generate"))

    # Verify it's the specific one (higher specificity wins)
    assert best_cap.title == "Specific Text Generation Capability"

    # Both sets should match the minimal request
    all_sets = registry.find_cap_sets(make_test_urn("op=generate"))
    assert len(all_sets) == 2


# TEST119: Test invalid URN returns InvalidUrn error
def test_119_invalid_urn_handling():
    registry = CapMatrix()

    with pytest.raises(InvalidUrnError):
        registry.find_cap_sets("invalid-urn")


# TEST120: Test accepts_request checks if registry can accept a capability request
def test_120_accepts_request():
    registry = CapMatrix()

    host = MockCapSet("test-host")
    cap = make_cap(make_test_urn("op=process"), "Process Capability")

    registry.register_cap_set("test-host", host, [cap])

    # Should accept matching capability (exact match)
    assert registry.accepts_request(make_test_urn("op=process"))

    # Should NOT accept request with extra requirements that registered cap doesn't satisfy
    # Routing: request(op,advanced) requires "advanced", cap(op) doesn't have it → reject
    assert not registry.accepts_request(make_test_urn("op=process;advanced"))

    # Should not accept non-matching capability
    assert not registry.accepts_request(make_test_urn("op=different"))

    # Should not crash on invalid URN
    assert not registry.accepts_request("invalid-urn")


# TEST127: Test CapGraph adds nodes and edges from capability definitions
def test_127_cap_graph_adds_nodes_and_edges():
    graph = CapGraph()

    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:string";op=parse;out="media:json"', "String to JSON", "media:json")

    graph.add_cap(cap1, "registry1")
    graph.add_cap(cap2, "registry2")

    # Check nodes
    nodes = graph.get_nodes()
    assert "media:binary" in nodes
    assert "media:string" in nodes
    assert "media:json" in nodes

    # Check edges
    edges = graph.get_edges()
    assert len(edges) == 2
    assert edges[0].from_spec == "media:binary"
    assert edges[0].to_spec == "media:string"
    assert edges[1].from_spec == "media:string"
    assert edges[1].to_spec == "media:json"


# TEST128: Test CapGraph tracks outgoing and incoming edges for spec conversions
def test_128_cap_graph_tracks_outgoing_and_incoming():
    graph = CapGraph()

    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:binary";op=parse;out="media:json"', "Binary to JSON", "media:json")
    cap3 = make_cap('cap:in="media:string";op=validate;out="media:string"', "String Validate", MEDIA_STRING)

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")
    graph.add_cap(cap3, "reg1")

    # Get outgoing from binary
    outgoing = graph.get_outgoing("media:binary")
    assert len(outgoing) == 2  # Two conversions from binary

    # Get incoming to string
    incoming = graph.get_incoming("media:string")
    assert len(incoming) == 2  # decode produces string, validate produces string


# TEST129: Test CapGraph detects direct and indirect conversion paths between specs
def test_129_cap_graph_detects_conversion_paths():
    graph = CapGraph()

    # Create conversion chain: binary -> string -> json
    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:string";op=parse;out="media:json"', "String to JSON", "media:json")

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")

    # Direct path exists
    assert graph.has_direct_edge("media:binary", "media:string")
    assert graph.has_direct_edge("media:string", "media:json")

    # Direct path doesn't exist
    assert not graph.has_direct_edge("media:binary", "media:json")

    # But conversion path exists
    assert graph.can_convert("media:binary", "media:json")
    assert graph.can_convert("media:binary", "media:string")
    assert graph.can_convert("media:string", "media:json")

    # No path backwards
    assert not graph.can_convert("media:json", "media:binary")


# TEST130: Test CapGraph finds shortest path for spec conversion chain
def test_130_cap_graph_finds_shortest_path():
    graph = CapGraph()

    # Create conversion chain: binary -> string -> json
    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:string";op=parse;out="media:json"', "String to JSON", "media:json")

    # Direct path
    cap3 = make_cap('cap:in="media:binary";op=direct;out="media:json"', "Binary to JSON Direct", "media:json")

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")
    graph.add_cap(cap3, "reg1")

    # Should find the direct path (shortest)
    path = graph.find_path("media:binary", "media:json")
    assert path is not None
    assert len(path) == 1  # Direct path
    assert path[0].cap.title == "Binary to JSON Direct"


# TEST131: Test CapGraph finds all conversion paths sorted by length
def test_131_cap_graph_finds_all_paths():
    graph = CapGraph()

    # Create multiple paths: binary -> string -> json
    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:string";op=parse;out="media:json"', "String to JSON", "media:json")

    # Direct path
    cap3 = make_cap('cap:in="media:binary";op=direct;out="media:json"', "Binary to JSON Direct", "media:json")

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")
    graph.add_cap(cap3, "reg1")

    # Find all paths
    paths = graph.find_all_paths("media:binary", "media:json", max_depth=3)
    assert len(paths) == 2  # Direct and indirect

    # Sorted by length (shortest first)
    assert len(paths[0]) == 1  # Direct path
    assert len(paths[1]) == 2  # Binary -> String -> JSON


# TEST132: Test CapGraph returns direct edges sorted by specificity
def test_132_cap_graph_direct_edges_sorted_by_specificity():
    graph = CapGraph()

    # General capability
    cap1 = make_cap('cap:in="media:binary";op=convert;out="media:string"', "General Convert", MEDIA_STRING)

    # Specific capability (requires more specific input)
    cap2 = make_cap('cap:in="media:binary;utf8";op=convert;optimized;out="media:string;text"', "Specific Convert", "media:string;text")

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")

    # Get direct edges - query with input that satisfies both (binary;utf8 satisfies both binary and binary;utf8)
    edges = graph.get_direct_edges("media:binary;utf8", "media:string")
    assert len(edges) == 2

    # Should be sorted by specificity (highest first)
    assert edges[0].cap.title == "Specific Convert"  # More specific
    assert edges[1].cap.title == "General Convert"  # Less specific


# TEST134: Test CapGraph stats provides counts of nodes and edges
def test_134_cap_graph_stats():
    graph = CapGraph()

    cap1 = make_cap('cap:in="media:binary";op=decode;out="media:string"', "Binary to String", MEDIA_STRING)
    cap2 = make_cap('cap:in="media:string";op=parse;out="media:json"', "String to JSON", "media:json")
    cap3 = make_cap('cap:in="media:json";op=validate;out="media:json"', "JSON Validate", "media:json")

    graph.add_cap(cap1, "reg1")
    graph.add_cap(cap2, "reg1")
    graph.add_cap(cap3, "reg1")

    # Check stats
    nodes = graph.get_nodes()
    edges = graph.get_edges()

    assert len(nodes) == 3  # binary, string, json
    assert len(edges) == 3  # 3 capabilities


# Additional tests for CapMatrix methods


# TEST576: CapBlock::get_registry_names returns names in insertion order
def test_576_cap_matrix_get_host_names():
    registry = CapMatrix()

    host1 = MockCapSet("host1")
    host2 = MockCapSet("host2")

    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")
    cap2 = make_cap(make_test_urn("op=test2"), "Test 2")

    registry.register_cap_set("host1", host1, [cap1])
    registry.register_cap_set("host2", host2, [cap2])

    names = registry.get_host_names()
    assert len(names) == 2
    assert "host1" in names
    assert "host2" in names


# TEST571: get_all_capabilities returns caps from all hosts
def test_571_cap_matrix_get_all_capabilities():
    registry = CapMatrix()

    host = MockCapSet("host")

    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")
    cap2 = make_cap(make_test_urn("op=test2"), "Test 2")

    registry.register_cap_set("host", host, [cap1, cap2])

    caps = registry.get_all_capabilities()
    assert len(caps) == 2


# TEST572: get_capabilities_for_host returns caps for specific host, None for unknown
def test_572_cap_matrix_get_capabilities_for_host():
    registry = CapMatrix()

    host = MockCapSet("host")

    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")

    registry.register_cap_set("host", host, [cap1])

    # Existing host
    caps = registry.get_capabilities_for_host("host")
    assert caps is not None
    assert len(caps) == 1

    # Non-existing host
    caps = registry.get_capabilities_for_host("nonexistent")
    assert caps is None


# TEST569: unregister_cap_set removes a host and returns true, false if not found
def test_569_cap_matrix_unregister_cap_set():
    registry = CapMatrix()

    host = MockCapSet("host")
    cap = make_cap(make_test_urn("op=test"), "Test")

    registry.register_cap_set("host", host, [cap])

    # Unregister existing
    assert registry.unregister_cap_set("host") == True
    assert registry.get_capabilities_for_host("host") is None

    # Unregister non-existing
    assert registry.unregister_cap_set("nonexistent") == False


# TEST570: clear removes all registered sets
def test_570_cap_matrix_clear():
    registry = CapMatrix()

    host1 = MockCapSet("host1")
    host2 = MockCapSet("host2")

    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")
    cap2 = make_cap(make_test_urn("op=test2"), "Test 2")

    registry.register_cap_set("host1", host1, [cap1])
    registry.register_cap_set("host2", host2, [cap2])

    assert len(registry.get_host_names()) == 2

    registry.clear()

    assert len(registry.get_host_names()) == 0


# =============================================================================
# CapBlock Tests (Multi-Registry Composite)
# =============================================================================


# TEST121: Test CapBlock selects more specific cap over less specific regardless of registry order
def test_121_cap_block_more_specific_wins():
    # This is the key test: provider has less specific cap, plugin has more specific
    # The more specific one should win regardless of registry order

    provider_registry = CapMatrix()
    plugin_registry = CapMatrix()

    # Provider: less specific cap
    provider_host = MockCapSet("provider")
    provider_cap = make_cap(
        'cap:in="media:";op=generate_thumbnail;out="media:"',
        "Provider Thumbnail Generator (generic)"
    )
    provider_registry.register_cap_set("provider", provider_host, [provider_cap])

    # Plugin: more specific cap (has ext=pdf)
    plugin_host = MockCapSet("plugin")
    plugin_cap = make_cap(
        'cap:ext=pdf;in="media:";op=generate_thumbnail;out="media:"',
        "Plugin PDF Thumbnail Generator (specific)"
    )
    plugin_registry.register_cap_set("plugin", plugin_host, [plugin_cap])

    # Create composite with provider first (normally would have priority on ties)
    composite = CapBlock()
    composite.add_registry("providers", provider_registry)
    composite.add_registry("plugins", plugin_registry)

    # Request for PDF thumbnails - plugin's more specific cap should win
    request = 'cap:ext=pdf;in="media:";op=generate_thumbnail;out="media:"'
    best = composite.find_best_cap_set(request)

    # Plugin registry has specificity 2 (ext=pdf, op=generate_thumbnail; in/out="media:" are wildcards, contribute 0)
    # Provider registry has specificity 1 (op=generate_thumbnail only)
    # Plugin should win even though providers were added first
    assert best.registry_name == "plugins", "More specific plugin should win over less specific provider"
    assert best.specificity == 2, "Plugin cap has 2 specific tags (ext=pdf, op=generate_thumbnail)"
    assert best.cap.title == "Plugin PDF Thumbnail Generator (specific)"


# TEST122: Test CapBlock breaks specificity ties by first registered registry
def test_122_cap_block_tie_goes_to_first():
    # When specificity is equal, first registry wins

    registry1 = CapMatrix()
    registry2 = CapMatrix()

    # Both have same specificity
    host1 = MockCapSet("host1")
    cap1 = make_cap(make_test_urn("ext=pdf;op=generate"), "Registry 1 Cap")
    registry1.register_cap_set("host1", host1, [cap1])

    host2 = MockCapSet("host2")
    cap2 = make_cap(make_test_urn("ext=pdf;op=generate"), "Registry 2 Cap")
    registry2.register_cap_set("host2", host2, [cap2])

    composite = CapBlock()
    composite.add_registry("first", registry1)
    composite.add_registry("second", registry2)

    best = composite.find_best_cap_set(make_test_urn("ext=pdf;op=generate"))

    # Both have same specificity, first registry should win
    assert best.registry_name == "first", "On tie, first registry should win"
    assert best.cap.title == "Registry 1 Cap"


# TEST123: Test CapBlock polls all registries to find most specific match
def test_123_cap_block_polls_all():
    # Test that all registries are polled

    registry1 = CapMatrix()
    registry2 = CapMatrix()
    registry3 = CapMatrix()

    # Registry 1: doesn't match
    host1 = MockCapSet("host1")
    cap1 = make_cap(make_test_urn("op=different"), "Registry 1")
    registry1.register_cap_set("host1", host1, [cap1])

    # Registry 2: matches but less specific
    host2 = MockCapSet("host2")
    cap2 = make_cap(make_test_urn("op=generate"), "Registry 2")
    registry2.register_cap_set("host2", host2, [cap2])

    # Registry 3: matches and most specific
    host3 = MockCapSet("host3")
    cap3 = make_cap(make_test_urn("ext=pdf;format=thumbnail;op=generate"), "Registry 3")
    registry3.register_cap_set("host3", host3, [cap3])

    composite = CapBlock()
    composite.add_registry("r1", registry1)
    composite.add_registry("r2", registry2)
    composite.add_registry("r3", registry3)

    best = composite.find_best_cap_set(make_test_urn("ext=pdf;format=thumbnail;op=generate"))

    # Registry 3 has more specific tags
    assert best.registry_name == "r3", "Most specific registry should win"


# TEST124: Test CapBlock returns error when no registries match the request
def test_124_cap_block_no_match():
    registry = CapMatrix()

    composite = CapBlock()
    composite.add_registry("empty", registry)

    try:
        composite.find_best_cap_set(make_test_urn("op=nonexistent"))
        assert False, "Should have raised NoSetsFoundError"
    except NoSetsFoundError:
        pass  # Expected


# TEST125: Test CapBlock prefers specific plugin over generic provider fallback
def test_125_cap_block_fallback_scenario():
    # Test the exact scenario from the user's issue:
    # Provider: generic fallback (can handle any file type)
    # Plugin:   PDF-specific handler
    # Request:  PDF thumbnail
    # Expected: Plugin wins (more specific)

    provider_registry = CapMatrix()
    plugin_registry = CapMatrix()

    # Provider with generic fallback (can handle any file type)
    provider_host = MockCapSet("provider_fallback")
    provider_cap = make_cap(
        'cap:in="media:";op=generate_thumbnail;out="media:"',
        "Generic Thumbnail Provider"
    )
    provider_registry.register_cap_set("provider_fallback", provider_host, [provider_cap])

    # Plugin with PDF-specific handler
    plugin_host = MockCapSet("pdf_plugin")
    plugin_cap = make_cap(
        'cap:ext=pdf;in="media:";op=generate_thumbnail;out="media:"',
        "PDF Thumbnail Plugin"
    )
    plugin_registry.register_cap_set("pdf_plugin", plugin_host, [plugin_cap])

    # Providers first (would win on tie)
    composite = CapBlock()
    composite.add_registry("providers", provider_registry)
    composite.add_registry("plugins", plugin_registry)

    # Request for PDF thumbnail
    request = 'cap:ext=pdf;in="media:";op=generate_thumbnail;out="media:"'
    best = composite.find_best_cap_set(request)

    # Plugin (specificity 4) should beat provider (specificity 3)
    assert best.registry_name == "plugins"


# TEST126: Test CapBlock accepts_request method checks if any registry can accept the capability
def test_126_cap_block_accepts_request():
    # Test the accepts_request() method

    provider_registry = CapMatrix()

    provider_host = MockCapSet("test_provider")
    provider_cap = make_cap(
        make_test_urn("ext=pdf;op=generate"),
        "Test Provider"
    )
    provider_registry.register_cap_set("test_provider", provider_host, [provider_cap])

    composite = CapBlock()
    composite.add_registry("providers", provider_registry)

    # Test accepts_request
    assert composite.accepts_request(make_test_urn("ext=pdf;op=generate"))
    assert not composite.accepts_request(make_test_urn("op=nonexistent"))


# TEST133: Test CapBlock graph integration with multiple registries and conversion paths
def test_133_cap_block_graph_integration():
    # Test that CapBlock.graph() works correctly

    provider_registry = CapMatrix()
    plugin_registry = CapMatrix()

    # Provider: binary -> str
    provider_host = MockCapSet("provider")
    provider_cap = Cap(
        urn=CapUrn.from_string('cap:in="media:";op=extract;out="media:textable;form=scalar"'),
        title="Provider Text Extractor",
        command="extract"
    )
    provider_cap.output = CapOutput("media:textable;form=scalar", "output")
    provider_registry.register_cap_set("provider", provider_host, [provider_cap])

    # Plugin: str -> obj
    plugin_host = MockCapSet("plugin")
    plugin_cap = Cap(
        urn=CapUrn.from_string('cap:in="media:textable;form=scalar";op=parse;out="media:form=map;textable"'),
        title="Plugin JSON Parser",
        command="parse"
    )
    plugin_cap.output = CapOutput("media:form=map;textable", "output")
    plugin_registry.register_cap_set("plugin", plugin_host, [plugin_cap])

    cube = CapBlock()
    cube.add_registry("providers", provider_registry)
    cube.add_registry("plugins", plugin_registry)

    # Build graph
    graph = cube.graph()

    # Check nodes (exact spec strings - alphabetically canonicalized)
    nodes = graph.get_nodes()
    assert 'media:' in nodes
    assert 'media:textable;form=scalar' in nodes  # Canonicalized (alphabetical)
    assert 'media:form=map;textable' in nodes  # Canonicalized (alphabetical)

    # Check edges
    edges = graph.get_edges()
    assert len(edges) == 2

    # Check that we have appropriate edges
    # Edge 1: media: (base binary) -> media:textable;form=scalar
    # Edge 2: media:textable;form=scalar -> media:form=map;textable
    edge_pairs = [(e.from_spec, e.to_spec) for e in edges]
    assert any(from_spec == 'media:' and ('scalar' in to_spec or 'textable' in to_spec) for from_spec, to_spec in edge_pairs)
    assert any(('scalar' in from_spec or 'textable' in from_spec) and 'map' in to_spec for from_spec, to_spec in edge_pairs)


# TEST574: CapBlock::remove_registry removes by name, returns the registry object; None for missing
def test_574_cap_block_remove_registry():
    registry1 = CapMatrix()
    registry2 = CapMatrix()

    host1 = MockCapSet("host1")
    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")
    registry1.register_cap_set("host1", host1, [cap1])

    composite = CapBlock()
    composite.add_registry("first", registry1)
    composite.add_registry("second", registry2)

    assert len(composite.get_registry_names()) == 2

    # Remove existing
    removed = composite.remove_registry("first")
    assert removed is not None, "remove_registry must return the registry for existing name"
    assert len(composite.get_registry_names()) == 1
    assert "first" not in composite.get_registry_names()

    # Removing non-existent returns None
    assert composite.remove_registry("nonexistent") is None


# TEST575: CapBlock::get_registry returns registry by name, None for unknown
def test_575_cap_block_get_registry():
    registry = CapMatrix()

    composite = CapBlock()
    composite.add_registry("alpha", registry)

    retrieved = composite.get_registry("alpha")
    assert retrieved is not None, "get_registry must return the registry for existing name"

    assert composite.get_registry("nonexistent") is None


# TEST568: CapGraph::find_best_path returns highest-specificity path over shortest
def test_568_cap_graph_find_best_path():
    from capns.urn.cap_matrix import CapGraph
    graph = CapGraph()

    # Direct path: binary -> obj (low specificity, just op)
    cap_direct = make_cap(
        'cap:in="media:binary";op=direct;out="media:object"',
        "Direct Low Spec",
        "media:object",
    )

    # Two-hop path: binary -> string -> obj (high specificity, ext=pdf on first hop)
    cap_hop1 = make_cap(
        'cap:ext=pdf;in="media:binary";op=extract;out="media:string"',
        "Hop1 High Spec",
        "media:string",
    )
    cap_hop2 = make_cap(
        'cap:ext=json;in="media:string";op=parse;out="media:object"',
        "Hop2 High Spec",
        "media:object",
    )

    graph.add_cap(cap_direct, "r1")
    graph.add_cap(cap_hop1, "r2")
    graph.add_cap(cap_hop2, "r2")

    # find_path returns shortest (1 hop)
    shortest = graph.find_path("media:binary", "media:object")
    assert shortest is not None
    assert len(shortest) == 1

    # find_best_path returns highest total specificity (2 hops, each with ext tag)
    best = graph.find_best_path("media:binary", "media:object", 5)
    assert best is not None
    total_spec = sum(e.specificity for e in best)
    direct_spec = shortest[0].specificity
    assert total_spec > direct_spec, (
        f"Best path total specificity {total_spec} must exceed direct path {direct_spec}"
    )
    assert len(best) == 2


# TEST573: iter_hosts_and_caps iterates all hosts with their capabilities
def test_573_cap_matrix_iter_hosts_and_caps():
    registry = CapMatrix()

    host1 = MockCapSet("h1")
    host2 = MockCapSet("h2")
    cap_a = make_cap(make_test_urn("op=a"), "Cap A")
    cap_b = make_cap(make_test_urn("op=b"), "Cap B")

    registry.register_cap_set("h1", host1, [cap_a])
    registry.register_cap_set("h2", host2, [cap_b])

    entries = list(registry.iter_hosts_and_caps())
    assert len(entries) == 2
    for name, caps in entries:
        assert name in ("h1", "h2")
        assert len(caps) == 1


# TEST577: CapGraph::get_input_specs and get_output_specs return correct sets
def test_577_cap_graph_input_output_specs():
    from capns.urn.cap_matrix import CapGraph
    graph = CapGraph()

    cap = make_cap(
        'cap:in="media:binary";op=x;out="media:string"',
        "X",
        "media:string",
    )
    graph.add_cap(cap, "r")

    inputs = graph.get_input_specs()
    assert "media:binary" in inputs, "binary should be an input spec"

    outputs = graph.get_output_specs()
    assert "media:string" in outputs, "string should be an output spec"

    # binary is only an input (no edges pointing TO it)
    assert "media:binary" not in outputs
    # string is only an output (no edges FROM it)
    assert "media:string" not in inputs
