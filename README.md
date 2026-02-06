# capns-py

Python implementation of the capns (Cap SDK) - Core cap URN and definition system for FGND plugins.

This library provides the fundamental cap URN system used across all FGND plugins and providers. It defines the formal structure for cap identifiers with flat tag-based naming, wildcard support, and specificity comparison.

## Features

- **MediaUrn**: Media type specification using tagged URN format with "media" prefix
- **CapUrn**: Cap identifiers with required `in` and `out` direction specs
- Semantic matching with wildcard support
- Specificity-based selection for finding best matching capabilities
- Full compatibility with the Rust reference implementation

## Installation

```bash
# Install in development mode
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

## Dependencies

- **tagged-urn**: Flat tag-based URN system (Python implementation)

## Usage

```python
from capns import (
    MediaUrn,
    CapUrn,
    CapUrnBuilder,
    MEDIA_STRING,
    MEDIA_OBJECT,
    MEDIA_VOID,
)

# Create media URNs
string_urn = MediaUrn.from_string(MEDIA_STRING)
print(string_urn.is_text())  # True
print(string_urn.is_scalar())  # True

# Create cap URNs
cap = CapUrnBuilder() \
    .in_spec(MEDIA_STRING) \
    .out_spec(MEDIA_OBJECT) \
    .tag("op", "generate") \
    .tag("ext", "pdf") \
    .build()

print(cap.to_string())  # cap:ext=pdf;in="media:textable;form=scalar";op=generate;out="media:form=map;textable"

# Matching semantics
request = CapUrn.from_string('cap:in="media:textable;form=scalar";out="media:form=map;textable";op=generate')
print(cap.matches(request))  # True

# Specificity
print(cap.specificity())  # Higher score = more specific
```

## Testing

Tests mirror the Rust implementation with matching TEST### numbers for cross-tracking:

```bash
# Run all tests
pytest tests/

# Run specific test files
pytest tests/test_cap_urn.py
pytest tests/test_media_urn.py

# Run with coverage
pytest --cov=capns tests/
```

### Test Coverage

The implementation includes comprehensive tests covering:

#### CapUrn Tests (TEST001-TEST052)
- TEST001-TEST039: Core CapUrn functionality, parsing, serialization, matching
- TEST040-TEST052: Advanced matching semantics and direction handling

#### MediaUrn Tests (TEST057-TEST078, TEST304-TEST306)
- TEST057-TEST078: MediaUrn parsing, type checking, matching, specificity
- TEST304-TEST306: Additional media URN constant validation

**Total: 77 passing tests**

## Architecture

### MediaUrn

Media URNs use the "media" prefix and describe data types using tags:

```
media:<markers>[;key=value]*
```

Examples:
- `media:bytes` - Binary data
- `media:textable;form=scalar` - Text, single value
- `media:pdf;bytes` - PDF document (binary)

### CapUrn

Cap URNs use the "cap" prefix and require `in` and `out` direction specs:

```
cap:in="<media-urn>";out="<media-urn>"[;key=value]*
```

Examples:
- `cap:in="media:void";op=test;out="media:void"` - No-op test capability
- `cap:in="media:pdf;bytes";op=generate_thumbnail;out="media:image;png;bytes;thumbnail"` - PDF thumbnail generator

### Matching Semantics

Matching follows tagged URN semantics with direction-aware rules:

- **Input matching**: `request_input.matches(cap_input)` - Does request's data satisfy cap's requirement?
- **Output matching**: `cap_output.matches(request_output)` - Does cap's output satisfy request's expectation?
- **Missing tags** are treated as wildcards (less specific, can handle any value)
- **Specificity**: Direction specs contribute their MediaUrn tag count; more tags = more specific

## Development

The Python implementation follows these principles:

1. **Production code only** - No placeholders, TODOs, or stopgaps
2. **Root cause fixes** - Issues are fixed at their source, not worked around
3. **Python conventions** - Follows Pythonic patterns while maintaining semantic compatibility
4. **Test-driven** - Tests expose issues and track completion
5. **Cross-language compatibility** - Tests numbered to match Rust reference implementation

## License

MIT

## Reference

- Rust reference implementation: [capns](../capns)
- Tagged URN Python: [tagged-urn-py](../tagged-urn-py)
- Tagged URN Rust: [tagged-urn-rs](https://github.com/tagged-urn-rs)
