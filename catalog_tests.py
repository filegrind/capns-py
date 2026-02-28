#!/usr/bin/env python3
"""
Test Catalog Generator for Capns-Py

Scans all Python test files and generates a markdown table cataloging all numbered tests
with their descriptions.
"""

import os
import re
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class TestInfo:
    """Information about a single test"""
    number: str
    function_name: str
    description: str
    file_path: str
    line_number: int


def extract_test_info(file_path: Path) -> List[TestInfo]:
    """
    Extract test information from a Python test file.

    Returns a list of TestInfo objects for all numbered tests found.
    """
    tests = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}")
        return tests

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for test function definitions: def test_123_something():
        test_match = re.match(r'\s*def\s+(test_(\d+)_\w+)\s*\(', line)

        if test_match:
            function_name = test_match.group(1)
            test_number = test_match.group(2)

            # Look backwards for comment lines
            description_lines = []
            j = i - 1

            # Skip empty lines
            while j >= 0 and lines[j].strip() == '':
                j -= 1

            # Collect comment lines (# TEST###: description)
            while j >= 0 and lines[j].strip().startswith('#'):
                comment_line = lines[j].strip()
                # Remove the '#' prefix and leading/trailing whitespace
                comment_text = comment_line[1:].strip()
                description_lines.insert(0, comment_text)
                j -= 1

            # Join description lines with space
            description = ' '.join(description_lines)

            # Get relative path from capns-py root
            try:
                relative_path = file_path.relative_to(file_path.parents[0].parent)
            except ValueError:
                relative_path = file_path

            test_info = TestInfo(
                number=test_number,
                function_name=function_name,
                description=description,
                file_path=str(relative_path),
                line_number=i + 1
            )
            tests.append(test_info)

        i += 1

    return tests


def scan_directory(root_dir: Path) -> List[TestInfo]:
    """
    Recursively scan a directory for Python test files and extract test information.
    """
    all_tests = []

    for py_file in root_dir.rglob('test_*.py'):
        tests = extract_test_info(py_file)
        all_tests.extend(tests)

    return all_tests


def generate_markdown_table(tests: List[TestInfo], output_file: str):
    """
    Generate a markdown table cataloging all tests.
    """
    # Sort tests by test number (numerically)
    tests_sorted = sorted(tests, key=lambda t: int(t.number))

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Capns-Py Test Catalog\n\n")
        f.write(f"**Total Tests:** {len(tests_sorted)}\n\n")
        f.write("This catalog lists all numbered tests in the capns-py codebase.\n\n")

        # Table header
        f.write("| Test # | Function Name | Description | Location |\n")
        f.write("|--------|---------------|-------------|----------|\n")

        # Table rows
        for test in tests_sorted:
            # Escape pipe characters in description
            description = test.description.replace('|', '\\|')

            # Create a shortened function name
            short_name = test.function_name

            # Create file location link
            location = f"{test.file_path}:{test.line_number}"

            f.write(f"| test{test.number} | `{short_name}` | {description} | {location} |\n")

        f.write("\n---\n\n")
        f.write(f"*Generated from capns-py source tree*\n")
        f.write(f"*Total numbered tests: {len(tests_sorted)}*\n")


def main():
    """Main entry point"""
    # Determine the capns-py root directory (where this script is located)
    script_dir = Path(__file__).parent

    print("Scanning for tests in capns-py codebase...")

    # Scan tests/ directory
    tests_dir = script_dir / 'tests'
    if tests_dir.exists():
        print(f"  Scanning {tests_dir}...")
        all_tests = scan_directory(tests_dir)
        print(f"    Found {len(all_tests)} tests in tests/")
    else:
        print(f"  Warning: {tests_dir} not found")
        all_tests = []

    print(f"\nTotal tests found: {len(all_tests)}")

    # Generate markdown table
    output_file = script_dir / 'TEST_CATALOG.md'
    print(f"\nGenerating catalog: {output_file}")
    generate_markdown_table(all_tests, str(output_file))

    print(f"✓ Catalog generated successfully!")
    print(f"  File: {output_file}")

    # Print some statistics
    test_ranges = {}
    for test in all_tests:
        century = (int(test.number) // 100) * 100
        range_key = f"{century:03d}-{century+99:03d}"
        test_ranges[range_key] = test_ranges.get(range_key, 0) + 1

    print("\nTest distribution by range:")
    for range_key in sorted(test_ranges.keys()):
        count = test_ranges[range_key]
        print(f"  {range_key}: {count} tests")


if __name__ == '__main__':
    main()
