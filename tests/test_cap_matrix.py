"""Tests for cap_matrix - mirroring capns Rust tests

Tests use // TEST###: comments matching the Rust implementation for cross-tracking.
"""

import pytest
from capns import Cap, CapUrn, CapOutput, CapSet, CapArgumentValue
from capns.cap_matrix import (
    CapGraph,
    CapGraphEdge,
    CapMatrix,
    CapMatrixError,
    NoSetsFoundError,
    InvalidUrnError,
)
from capns.media_urn import MEDIA_STRING, MEDIA_VOID


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
def test_register_and_find_cap_set():
    registry = CapMatrix()

    host = MockCapSet("test-host")
    cap = make_cap(make_test_urn("op=test;basic"), "Test Basic Capability")

    registry.register_cap_set("test-host", host, [cap])

    # Test exact match
    sets = registry.find_cap_sets(make_test_urn("op=test;basic"))
    assert len(sets) == 1

    # Test subset match (request has more specific requirements)
    sets = registry.find_cap_sets(make_test_urn("op=test;basic;model=gpt-4"))
    assert len(sets) == 1

    # Test no match
    with pytest.raises(NoSetsFoundError):
        registry.find_cap_sets(make_test_urn("op=different"))


# TEST118: Test selecting best cap set based on specificity ranking
def test_best_cap_set_selection():
    registry = CapMatrix()

    # Register general host
    general_host = MockCapSet("general")
    general_cap = make_cap(make_test_urn("op=generate"), "General Generation Capability")

    # Register specific host
    specific_host = MockCapSet("specific")
    specific_cap = make_cap(make_test_urn("op=generate;text;model=gpt-4"), "Specific Text Generation Capability")

    registry.register_cap_set("general", general_host, [general_cap])
    registry.register_cap_set("specific", specific_host, [specific_cap])

    # Request should match the more specific host
    best_host, best_cap = registry.find_best_cap_set(make_test_urn("op=generate;text;model=gpt-4;temperature=low"))

    # Verify it's the specific one (higher specificity)
    assert best_cap.title == "Specific Text Generation Capability"

    # Both sets should match
    all_sets = registry.find_cap_sets(make_test_urn("op=generate;text;model=gpt-4;temperature=low"))
    assert len(all_sets) == 2


# TEST119: Test invalid URN returns InvalidUrn error
def test_invalid_urn_handling():
    registry = CapMatrix()

    with pytest.raises(InvalidUrnError):
        registry.find_cap_sets("invalid-urn")


# TEST120: Test can_handle checks if registry can handle a capability request
def test_can_handle():
    registry = CapMatrix()

    host = MockCapSet("test-host")
    cap = make_cap(make_test_urn("op=process"), "Process Capability")

    registry.register_cap_set("test-host", host, [cap])

    # Should handle matching capability
    assert registry.can_handle(make_test_urn("op=process"))
    assert registry.can_handle(make_test_urn("op=process;advanced"))

    # Should not handle non-matching capability
    assert not registry.can_handle(make_test_urn("op=different"))

    # Should not crash on invalid URN
    assert not registry.can_handle("invalid-urn")


# TEST127: Test CapGraph adds nodes and edges from capability definitions
def test_cap_graph_adds_nodes_and_edges():
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
def test_cap_graph_tracks_outgoing_and_incoming():
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
def test_cap_graph_detects_conversion_paths():
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
def test_cap_graph_finds_shortest_path():
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
def test_cap_graph_finds_all_paths():
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
def test_cap_graph_direct_edges_sorted_by_specificity():
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
def test_cap_graph_stats():
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

def test_cap_matrix_get_host_names():
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


def test_cap_matrix_get_all_capabilities():
    registry = CapMatrix()

    host = MockCapSet("host")

    cap1 = make_cap(make_test_urn("op=test1"), "Test 1")
    cap2 = make_cap(make_test_urn("op=test2"), "Test 2")

    registry.register_cap_set("host", host, [cap1, cap2])

    caps = registry.get_all_capabilities()
    assert len(caps) == 2


def test_cap_matrix_get_capabilities_for_host():
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


def test_cap_matrix_unregister_cap_set():
    registry = CapMatrix()

    host = MockCapSet("host")
    cap = make_cap(make_test_urn("op=test"), "Test")

    registry.register_cap_set("host", host, [cap])

    # Unregister existing
    assert registry.unregister_cap_set("host") == True
    assert registry.get_capabilities_for_host("host") is None

    # Unregister non-existing
    assert registry.unregister_cap_set("nonexistent") == False


def test_cap_matrix_clear():
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
