import os
import tempfile
import unittest

from azul_runner.test_utils import FileManager

from azul_plugin_python.py2exe_unpacker import (
    Py2ExeUnpacker,
    Py2ExeUnpackError,
)


class Py2ExeTest(unittest.TestCase):
    """Test Suite for Py2Exe unpacking."""

    def test_py2exe(self):
        """Test unpacking the executable."""
        fm = FileManager()
        # Malicious Windows 32 EXE, malware family redcap.
        pe = Py2ExeUnpacker(
            str(fm.download_file_path("5cf8e07fb186ca108d5006f138c1f3477c7cac4e138728d0739075f38d129c1c"))
        )
        contents = pe.get_results()
        self.assertEqual("Python 2.7", contents.get("python_version"))
        self.assertEqual(1487054280, contents.get("build_time"))

        self.assertTrue("scripts" in contents)
        self.assertEqual(3, len(contents["scripts"]))
        # user script
        self.assertTrue("st_main.pyc" in contents["scripts"])
        self.assertEqual(3742, len(contents["scripts"]["st_main.pyc"]))
        # py2exe artifacts
        self.assertTrue(r"C:\Python27\lib\site-packages\py2exe\boot_common.pyc" in contents["scripts"])
        self.assertEqual(2358, len(contents["scripts"][r"C:\Python27\lib\site-packages\py2exe\boot_common.pyc"]))
        self.assertTrue("<install zipextimporter>.pyc" in contents["scripts"])
        self.assertEqual(162, len(contents["scripts"]["<install zipextimporter>.pyc"]))

    def test_py2exe_bad_exe(self):
        fm = FileManager()
        # Malicious Windows 32EXE, RAT.
        file_path = str(fm.download_file_path("b5324ae4cec7bd7b837a726eccf140c1f0ebde82479db919546fe35f4b9439c7"))
        self.assertRaises(Py2ExeUnpackError, Py2ExeUnpacker, file_path)

    def test_non_py2exe(self):
        """Test unpacking non-executable."""
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"random_content_that_is_not_a_valid_exe")
            f.flush()
            f.seek(0)
            self.assertRaises(Py2ExeUnpackError, Py2ExeUnpacker, f.name)
