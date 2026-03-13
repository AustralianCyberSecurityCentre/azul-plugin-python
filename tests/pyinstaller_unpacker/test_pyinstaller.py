import os
import tempfile
import unittest

from azul_runner.test_utils import FileManager

from azul_plugin_python.pyinstaller_unpacker import pyi, pyz


class PyInstallerTestMalware(unittest.TestCase):
    """Verify against malicious files."""

    # Malicious Windows 32EXE
    testpath = "96af443ff7f9370622537ed3484577016d89fd6af9ce23674469934625655d2d"

    @classmethod
    def setUpClass(cls):
        """Initialise some real data to test with."""
        cls.file_manager = FileManager()
        cls.malware_file_path = str(cls.file_manager.download_file_path(PyInstallerTestMalware.testpath))
        super().setUpClass()

    def test_pyinstaller(self):
        """Test unpacking the executable."""
        contents = pyi.process_pyinstaller(PyInstallerTestMalware.malware_file_path)

        self.assertEqual((2, 7), contents.get("python_version"))
        self.assertEqual("Windows", contents.get("build_platform"))
        self.assertTrue("scripts" in contents)
        self.assertEqual(1, len(contents["scripts"]))
        fname, fcontent = contents["scripts"][0]
        # keylogger script
        self.assertEqual("keylogger.pyc", fname)
        self.assertEqual(2815, len(fcontent))

    def test_non_pyinstaller(self):
        """Test unpacking non-executable."""
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"not_a_valid_py_installer")
            f.flush()
            f.seek(0)
            self.assertRaises(pyi.InvalidFile, pyi.process_pyinstaller, f.name)


class PyInstallerTestVersions(unittest.TestCase):
    """Test Suite for regression across versions.

    Test files have been generated using the "generate-test.py" script, using a common
    script compiled using different versions of pyinstaller under different python versions.
    """

    @classmethod
    def setUpClass(cls):
        """Initialise class for shared tests."""
        cls.py3_9_13_pyc_version = 3425
        cls.py3_10_6_pyc_version = 3439
        super().setUpClass()

    def _run_common_tests(self, contents):
        """Run the common output tests using the given file."""

        self.assertEqual(len(contents.get("scripts", [])), 1)
        fname, _ = contents["scripts"][0]
        self.assertEqual(fname, "テスト.pyc")
        self.assertEqual(contents.get("build_platform"), "Linux")
        self.assertEqual(contents.get("cookie_size"), 88)

    def _run_common_tests_39(self, contents):
        """Run the tests with common output for python version 3.9."""
        _, fcontent = contents["scripts"][0]
        self.assertEqual(contents.get("python_version"), (3, 9))
        self.assertEqual(len(fcontent), 249)

    def _run_common_tests_310(self, contents):
        """Run the tests with common output for python version 3.10."""
        _, fcontent = contents["scripts"][0]
        self.assertEqual(contents.get("python_version"), (3, 10))
        self.assertEqual(len(fcontent), 251)

    def test_pyinstaller36_py39(self):
        """Test binary compiled with Pyinstaller 3.6 on py3.9"""
        path = os.path.join(os.path.dirname(__file__), "data", "py39-pyi36")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_39(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_9_13_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)

    def test_pyinstaller40_py39(self):
        """Test binary compiled with Pyinstaller 4.0 on py3.9"""
        path = os.path.join(os.path.dirname(__file__), "data", "py39-pyi40")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_39(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_9_13_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)

    def test_pyinstaller46_py39(self):
        """Test binary compiled with Pyinstaller 4.6 on py3.9"""
        path = os.path.join(os.path.dirname(__file__), "data", "py39-pyi46")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_39(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_9_13_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)

    def test_pyinstaller50_py39(self):
        """Test binary compiled with Pyinstaller 5.0 on py3.9"""
        path = os.path.join(os.path.dirname(__file__), "data", "py39-pyi50")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_39(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_9_13_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), 1661906124)
        self.assertEqual(contents.get("compile_time_gmt"), "Wed Aug 31 00:35:24 2022")

    def test_pyinstaller57_py39(self):
        """Test binary compiled with Pyinstaller 5.7 on py3.9"""
        path = os.path.join(os.path.dirname(__file__), "data", "py39-pyi57")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_39(contents)
        # zeroed header from 5.3 onwards, but we can get bytecode magic from the PYZ now!
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_9_13_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)

    def test_pyinstaller46_py310(self):
        """Test binary compiled with Pyinstaller 4.6 on py3.10"""
        path = os.path.join(os.path.dirname(__file__), "data", "py310-pyi46")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_310(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_10_6_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)

    def test_pyinstaller50_py310(self):
        """Test binary compiled with Pyinstaller 5.0 on py3.10"""
        path = os.path.join(os.path.dirname(__file__), "data", "py310-pyi50")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_310(contents)
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_10_6_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), 1674773248)
        self.assertEqual(contents.get("compile_time_gmt"), "Thu Jan 26 22:47:28 2023")

    def test_pyinstaller57_py310(self):
        """Test binary compiled with Pyinstaller 5.7 on py3.10"""
        path = os.path.join(os.path.dirname(__file__), "data", "py310-pyi57")
        contents = pyi.process_pyinstaller(path)
        self._run_common_tests(contents)
        self._run_common_tests_310(contents)
        # zeroed header from 5.3 onwards, but we can extract bytecode magic from PYZ now!
        self.assertEqual(contents.get("python_magic_pyc_version"), self.py3_10_6_pyc_version)
        self.assertEqual(contents.get("compile_time_unix"), None)
        self.assertEqual(contents.get("compile_time_gmt"), None)
