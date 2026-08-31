"""Test suite for python decompiler library."""

import os.path
import unittest
import datetime

import xdis.magics

from azul_plugin_python.decompiler.python_decompiler import (
    extract_metadata,
    DecompileErrors,
)

test_precompiled_py12_valid = os.path.join("bytecode", "hello312.cpython-312.pyc")
test_precompiled_py05_valid = os.path.join("bytecode", "hello.cpython-35.pyc")
test_precompiled_py12_valid_header = os.path.join("bytecode", "hello312_header_only.cpython-312.pyc")
test_precompiled_py05_valid_header = os.path.join("bytecode", "out.pyc")
test_precompiled_py12_random_bytes = os.path.join("bytecode", "random_bytes.cpython-312.pyc")


class PyDecTest(unittest.TestCase):
    """Test class for python_decompiler."""

    @classmethod
    def setUpClass(cls):
        """Set up data required for testing."""
        cls.pyc312_valid = os.path.join(os.path.dirname(__file__), test_precompiled_py12_valid)
        cls.pyc312_valid_header_only = os.path.join(os.path.dirname(__file__), test_precompiled_py12_valid_header)

        cls.pyc305_valid = os.path.join(os.path.dirname(__file__), test_precompiled_py05_valid)
        cls.pyc305_valid_header_only = os.path.join(os.path.dirname(__file__), test_precompiled_py05_valid_header)
        cls.pyc_random_bytes = os.path.join(os.path.dirname(__file__), test_precompiled_py12_random_bytes)

    def test_metadata_valid_pyc(self):
        """Test decompilers extract_metadata against a valid file."""
        metadata = extract_metadata(self.pyc312_valid)

        # 6 values
        self.assertEqual(len(metadata), 6)

        # valid magic int
        self.assertTrue(
            metadata["magic"] in xdis.magics.magicint2version,
            f"{metadata['magic']} not in xdis.magics.magicint2version",
        )

        # filesize
        self.assertEqual(metadata["filesize"], 23)

        # timestamp
        self.assertEqual(metadata["timestamp"], datetime.datetime(2026, 7, 30, 4, 21, 5))

        # version
        self.assertEqual(metadata["version"], "3.12")

        # Need to parse load_code to get this info, so should be None
        # somewhat suspicious that if present path will always just be the filename, will investigate
        self.assertTrue("hello312.py" in metadata["path"], "hello312.py not in metadata['path']")
        self.assertEqual(metadata["filename"], "hello312.py")

    def test_metadata_valid_pyc_header_only_py312(self):
        """Test decompilers extract_metadata against an invalid python 3.12 file, with correct headers."""
        metadata = extract_metadata(self.pyc312_valid_header_only)

        self.assertEqual(metadata["error_type"], DecompileErrors.XdisPy312MagicByteCollection)
        self.assertEqual(metadata["error_msg"], DecompileErrors.XdisPy312MagicByteCollectionMsg)
        self.assertEqual(len(metadata), 2)

    def test_metadata_valid_pyc_header_only_py305(self):
        """Test decompilers extract_metadata against an invalid file python 3.05, with correct headers."""
        metadata = extract_metadata(self.pyc305_valid_header_only)

        self.assertEqual(metadata["error_type"], DecompileErrors.PycHeader)
        self.assertEqual(metadata["error_msg"], DecompileErrors.PycHeaderMsg)
        self.assertEqual(len(metadata), 2)

    def test_metadata_valid_pyc305_timestamp(self):
        """Validating above issue where filesize is filesize and timestamp is timestamp (correct)"""
        metadata = extract_metadata(self.pyc305_valid)

        self.assertEqual(metadata["filesize"], 22)
        self.assertEqual(metadata["timestamp"], datetime.datetime(2026, 7, 24, 1, 49, 29))

    def test_metadata_invalid_pyc(self):
        """Test decompilers extract_metadata against file with invalid bytes."""
        metadata = extract_metadata(self.pyc_random_bytes)

        # throws input error and should only return these two values
        self.assertEqual(metadata["error_type"], DecompileErrors.PycHeader)
        self.assertEqual(metadata["error_msg"], DecompileErrors.PycHeaderMsg)
        self.assertEqual(len(metadata), 2)
