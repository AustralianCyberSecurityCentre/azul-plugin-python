"""Test the unpacker section of the plugin."""

import datetime

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    Filepath,
    JobResult,
    State,
    test_template,
)

from azul_plugin_python.main import AzulPluginPythonDecompiler


class TestExecute(test_template.TestPlugin):
    """Test decompiling various pyc files.

    - test on .pyc with path
    - test on .pyc with timestamp
    - test on .pyc that partially decompiles (now fixed)
    - test on fake .pyc (bytecode header + random data)
    - test on random data
    """

    PLUGIN_TO_TEST = AzulPluginPythonDecompiler
    MULTI_PLUGIN_KEY = "unpacker"
    FILE_FORMAT_OVERRIDE = "executable/windows/pe64"

    def _get_result_from_cart(self, loaded_cart: bytes) -> JobResult:
        """Helper function to run tests and get the appropriate key from the result."""
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[("content", loaded_cart)],
            verify_input_content=False,
        )
        return result.get(self.MULTI_PLUGIN_KEY)

    def test_invalid_file(self):
        result = self._get_result_from_cart(
            self.load_test_file_bytes(
                "fb5757c13b6be5ddfcc5df34110bd742ec39d572fc12090af877b842e6569026",
                "Benign PDF appended with additional data.",
            )
        )
        self.assertEqual(result.state.label, State.Label.OPT_OUT)

    def test_invalid_exe(self):
        """
        Test on exe that isn't a py2exe file
        """
        result = self._get_result_from_cart(
            self.load_test_file_bytes(
                "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                "Benign WIN32 EXE, python library executable python_mcp.exe",
            )
        )
        self.assertEqual(result.state.label, State.Label.OPT_OUT)

    def test_py2exe_1(self):
        """
        Test on py2exe file stitch (ec993ff561cbc175953502452bfa554a)
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "5cf8e07fb186ca108d5006f138c1f3477c7cac4e138728d0739075f38d129c1c",
                    "Malicious Windows 32 EXE, malware family redcap.",
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="5cf8e07fb186ca108d5006f138c1f3477c7cac4e138728d0739075f38d129c1c",
                        features={
                            "build_time": [FV("2017-02-14T06:38:00+00:00")],
                            "python_library": [
                                FV("Cookie"),
                                FV("Crypto"),
                                FV("PIL"),
                                FV("Queue"),
                                FV("StringIO"),
                                FV("UserDict"),
                                FV("_LWPCookieJar"),
                                FV("_MozillaCookieJar"),
                                FV("__future__"),
                                FV("_abcoll"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("_weakrefset"),
                                FV("abc"),
                                FV("atexit"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("calendar"),
                                FV("cgi"),
                                FV("cmd"),
                                FV("codecs"),
                                FV("collections"),
                                FV("colorsys"),
                                FV("contextlib"),
                                FV("cookielib"),
                                FV("copy"),
                                FV("copy_reg"),
                                FV("creddump"),
                                FV("ctypes"),
                                FV("decimal"),
                                FV("difflib"),
                                FV("dis"),
                                FV("distutils"),
                                FV("doctest"),
                                FV("dummy_thread"),
                                FV("dummy_threading"),
                                FV("email"),
                                FV("encodings"),
                                FV("fnmatch"),
                                FV("fractions"),
                                FV("ftplib"),
                                FV("functools"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("glob"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("heapq"),
                                FV("hmac"),
                                FV("httplib"),
                                FV("inspect"),
                                FV("io"),
                                FV("json"),
                                FV("keyword"),
                                FV("linecache"),
                                FV("locale"),
                                FV("logging"),
                                FV("md5"),
                                FV("mimetools"),
                                FV("mimetypes"),
                                FV("mss"),
                                FV("netbios"),
                                FV("netrc"),
                                FV("new"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("numbers"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("os2emxpath"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("pipes"),
                                FV("platform"),
                                FV("plistlib"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("pyHook"),
                                FV("py_compile"),
                                FV("pyreadline"),
                                FV("quopri"),
                                FV("random"),
                                FV("re"),
                                FV("readline"),
                                FV("repr"),
                                FV("requests"),
                                FV("rfc822"),
                                FV("sets"),
                                FV("shlex"),
                                FV("shutil"),
                                FV("smtplib"),
                                FV("socket"),
                                FV("sre"),
                                FV("sre_compile"),
                                FV("sre_constants"),
                                FV("sre_parse"),
                                FV("ssl"),
                                FV("st_encryption"),
                                FV("st_protocol"),
                                FV("st_utils"),
                                FV("st_win_keylogger"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("struct"),
                                FV("subprocess"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("traceback"),
                                FV("types"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("urllib2"),
                                FV("urlparse"),
                                FV("uu"),
                                FV("uuid"),
                                FV("warnings"),
                                FV("weakref"),
                                FV("win32con"),
                                FV("win32evtlogutil"),
                                FV("winerror"),
                                FV("xml"),
                                FV("zipextimporter"),
                                FV("zipfile"),
                            ],
                            "python_version": [FV("Python 2.7")],
                        },
                    ),
                    Event(
                        sha256="dcfda9fa44c91e8567d81e224f30dc373e07043bd9a32c0f127f5b065dcc3572",
                        parent=EventParent(sha256="5cf8e07fb186ca108d5006f138c1f3477c7cac4e138728d0739075f38d129c1c"),
                        relationship={"action": "unpacked_py2exe"},
                        data=[
                            EventData(
                                hash="dcfda9fa44c91e8567d81e224f30dc373e07043bd9a32c0f127f5b065dcc3572",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("st_main.pyc")]},
                    ),
                ],
                data={"dcfda9fa44c91e8567d81e224f30dc373e07043bd9a32c0f127f5b065dcc3572": b""},
            ),
        )

    def test_py2exe_2(self):
        """
        Test on py2exe file zjrm (8e469a3c88968a7790a4b74c1ce56f80)
        :return:
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "0565ead1f29f6ee0ee0cdb3d355b4e65d779cca8e5cf244cae169a61bb6b8a0e",
                    "Malicious Windows 32EXE Python based.",
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="0565ead1f29f6ee0ee0cdb3d355b4e65d779cca8e5cf244cae169a61bb6b8a0e",
                        features={"python_version": [FV("Python 2.7")]},
                    ),
                    Event(
                        sha256="f13fa6cf3cd72187030e47025344820bd55b2c7d8cb78268e91beeb20168a94e",
                        parent=EventParent(sha256="0565ead1f29f6ee0ee0cdb3d355b4e65d779cca8e5cf244cae169a61bb6b8a0e"),
                        relationship={"action": "unpacked_py2exe"},
                        data=[
                            EventData(
                                hash="f13fa6cf3cd72187030e47025344820bd55b2c7d8cb78268e91beeb20168a94e",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("ZJRM.pyc")]},
                    ),
                ],
                data={"f13fa6cf3cd72187030e47025344820bd55b2c7d8cb78268e91beeb20168a94e": b""},
            ),
        )

    def test_py2exe_3(self):
        """
        Test on py2exe file proxy (297d8962ce0881a6ed086be53184d7b4)
        :return:
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "dbc0c1b3c94b36d47510af7ad3e6f72133917e8f02c569a02533cbea60989b3d",
                    "Malicious Windows 32EXE Python based.",
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="dbc0c1b3c94b36d47510af7ad3e6f72133917e8f02c569a02533cbea60989b3d",
                        features={
                            "build_time": [FV("2010-05-01T12:45:30+00:00")],
                            "python_library": [
                                FV("BaseHTTPServer"),
                                FV("SocketServer"),
                                FV("StringIO"),
                                FV("UserDict"),
                                FV("_LWPCookieJar"),
                                FV("_MozillaCookieJar"),
                                FV("__future__"),
                                FV("_abcoll"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("abc"),
                                FV("atexit"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("calendar"),
                                FV("cmd"),
                                FV("codecs"),
                                FV("collections"),
                                FV("common"),
                                FV("cookielib"),
                                FV("copy"),
                                FV("copy_reg"),
                                FV("difflib"),
                                FV("dis"),
                                FV("doctest"),
                                FV("dummy_thread"),
                                FV("dummy_threading"),
                                FV("email"),
                                FV("encodings"),
                                FV("fnmatch"),
                                FV("ftplib"),
                                FV("functools"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("hashlib"),
                                FV("heapq"),
                                FV("httplib"),
                                FV("inspect"),
                                FV("keyword"),
                                FV("linecache"),
                                FV("locale"),
                                FV("logging"),
                                FV("macurl2path"),
                                FV("mainform_ui"),
                                FV("mimetools"),
                                FV("mimetypes"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("os2emxpath"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("quopri"),
                                FV("random"),
                                FV("re"),
                                FV("repr"),
                                FV("rfc822"),
                                FV("shlex"),
                                FV("socket"),
                                FV("sre"),
                                FV("sre_compile"),
                                FV("sre_constants"),
                                FV("sre_parse"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("struct"),
                                FV("subprocess"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("traceback"),
                                FV("types"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("urllib2"),
                                FV("urlparse"),
                                FV("uu"),
                                FV("warnings"),
                                FV("zipextimporter"),
                            ],
                            "python_version": [FV("Python 2.6")],
                        },
                    ),
                    Event(
                        sha256="6c1d9c1084def7141ad31ce082fd910e5463f80516a48a3ca112381b7904c197",
                        parent=EventParent(sha256="dbc0c1b3c94b36d47510af7ad3e6f72133917e8f02c569a02533cbea60989b3d"),
                        relationship={"action": "unpacked_py2exe"},
                        data=[
                            EventData(
                                hash="6c1d9c1084def7141ad31ce082fd910e5463f80516a48a3ca112381b7904c197",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("proxy.pyc")]},
                    ),
                ],
                data={"6c1d9c1084def7141ad31ce082fd910e5463f80516a48a3ca112381b7904c197": b""},
            ),
        )

    def test_py2exe_bad_exe_case(self):
        """Test on py2exe file (b5324ae4cec7bd7b837a726eccf140c1f0ebde82479db919546fe35f4b9439c7).

        The executable doesn't have DIRECTORY_ENTRY_RESOURCE's which causes a fail during extraction.
        """
        result = self._get_result_from_cart(
            self.load_test_file_bytes(
                "b5324ae4cec7bd7b837a726eccf140c1f0ebde82479db919546fe35f4b9439c7", "Malicious Windows 32EXE, RAT."
            )
        )
        self.assertEqual(result.state.label, State.Label.OPT_OUT)

    def test_invalid_zlib_file(self):
        """
        Test on zlib data that is not a pyinstaller pkg
        """
        result = self._get_result_from_cart(
            self.load_test_file_bytes(
                "df6f396a6c91b1206633633580ee1f233bc2188a3a00bf64158f9e6693d2b615", "zlib archive."
            )
        )
        self.assertEqual(result.state.label, State.Label.OPT_OUT)

    def test_pyinstaller_linux(self):
        """
        Test on Linux PyInstaller file
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "6ef0430c4a4de1dec14f27275e14f853ac51f3022613e0539f78afc310794c96",
                    "Malicious ELF64, RAT, malware family eobix.",
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="6ef0430c4a4de1dec14f27275e14f853ac51f3022613e0539f78afc310794c96",
                        features={
                            "build_time": [FV("2016-06-28T08:37:25+00:00")],
                            "pyinstaller_build_platform": [FV("Linux")],
                            "python_library": [
                                FV("Crypto"),
                                FV("StringIO"),
                                FV("UserDict"),
                                FV("__future__"),
                                FV("_abcoll"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("_weakrefset"),
                                FV("abc"),
                                FV("atexit"),
                                FV("base64"),
                                FV("bdb"),
                                FV("calendar"),
                                FV("cmd"),
                                FV("codecs"),
                                FV("collections"),
                                FV("contextlib"),
                                FV("copy"),
                                FV("copy_reg"),
                                FV("difflib"),
                                FV("dis"),
                                FV("doctest"),
                                FV("dummy_thread"),
                                FV("encodings"),
                                FV("fnmatch"),
                                FV("functools"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("gettext"),
                                FV("hashlib"),
                                FV("heapq"),
                                FV("inspect"),
                                FV("io"),
                                FV("keyword"),
                                FV("linecache"),
                                FV("locale"),
                                FV("logging"),
                                FV("ntpath"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("os2emxpath"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("quopri"),
                                FV("random"),
                                FV("re"),
                                FV("repr"),
                                FV("shlex"),
                                FV("socket"),
                                FV("sre"),
                                FV("sre_compile"),
                                FV("sre_constants"),
                                FV("sre_parse"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("traceback"),
                                FV("types"),
                                FV("unittest"),
                                FV("warnings"),
                                FV("weakref"),
                            ],
                            "python_version": [FV("Python 2.7")],
                        },
                    ),
                    Event(
                        sha256="c5aafcf2d2c7c55ee6f774e40bf0d6b6358ef1ae2b5b428d5a2ee9f1927b9187",
                        parent=EventParent(sha256="6ef0430c4a4de1dec14f27275e14f853ac51f3022613e0539f78afc310794c96"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="c5aafcf2d2c7c55ee6f774e40bf0d6b6358ef1ae2b5b428d5a2ee9f1927b9187",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("basicRAT_client.pyc")]},
                    ),
                    Event(
                        sha256="5a96cd1360c28721ef7e9038812cd1ec5e635573794667a6a74c25f7a509d756",
                        parent=EventParent(sha256="6ef0430c4a4de1dec14f27275e14f853ac51f3022613e0539f78afc310794c96"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="5a96cd1360c28721ef7e9038812cd1ec5e635573794667a6a74c25f7a509d756",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("out00-PYZ.pyz")]},
                    ),
                ],
                data={
                    "c5aafcf2d2c7c55ee6f774e40bf0d6b6358ef1ae2b5b428d5a2ee9f1927b9187": b"",
                    "5a96cd1360c28721ef7e9038812cd1ec5e635573794667a6a74c25f7a509d756": b"",
                },
            ),
        )

    def test_pyinstaller_mac_new(self):
        """
        Test on Mac PyInstaller file
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "31ef2ffab99e25a3674aaeee81037ae701bdaddc6dbda68de91c732df122cc03", "Mach-O EXE64"
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="31ef2ffab99e25a3674aaeee81037ae701bdaddc6dbda68de91c732df122cc03",
                        features={
                            "pyinstaller_build_platform": [FV("Mac")],
                            "python_library": [
                                FV("__future__"),
                                FV("_compat_pickle"),
                                FV("_compression"),
                                FV("_dummy_thread"),
                                FV("_pydecimal"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("aYaml"),
                                FV("appdirs"),
                                FV("argparse"),
                                FV("ast"),
                                FV("asyncio"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("bz2"),
                                FV("calendar"),
                                FV("cmd"),
                                FV("code"),
                                FV("codeop"),
                                FV("concurrent"),
                                FV("configVar"),
                                FV("contextlib"),
                                FV("copy"),
                                FV("csv"),
                                FV("ctypes"),
                                FV("datetime"),
                                FV("db"),
                                FV("decimal"),
                                FV("difflib"),
                                FV("dis"),
                                FV("distutils"),
                                FV("doctest"),
                                FV("dummy_threading"),
                                FV("email"),
                                FV("filecmp"),
                                FV("fnmatch"),
                                FV("ftplib"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("glob"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("hmac"),
                                FV("html"),
                                FV("http"),
                                FV("importlib"),
                                FV("inspect"),
                                FV("ipaddress"),
                                FV("json"),
                                FV("logging"),
                                FV("lxml"),
                                FV("lzma"),
                                FV("mimetypes"),
                                FV("multiprocessing"),
                                FV("netrc"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("numbers"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("pathlib"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("pipes"),
                                FV("pkgutil"),
                                FV("platform"),
                                FV("plistlib"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("psutil"),
                                FV("py_compile"),
                                FV("pybatch"),
                                FV("pydoc"),
                                FV("pydoc_data"),
                                FV("pyinstl"),
                                FV("queue"),
                                FV("quopri"),
                                FV("random"),
                                FV("redis"),
                                FV("runpy"),
                                FV("selectors"),
                                FV("shlex"),
                                FV("shutil"),
                                FV("signal"),
                                FV("smtplib"),
                                FV("socket"),
                                FV("socketserver"),
                                FV("sqlite3"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("svnTree"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("timeit"),
                                FV("token"),
                                FV("tokenize"),
                                FV("tracemalloc"),
                                FV("tty"),
                                FV("typing"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("utils"),
                                FV("uu"),
                                FV("uuid"),
                                FV("webbrowser"),
                                FV("xml"),
                                FV("xmlrpc"),
                                FV("yaml"),
                                FV("zipfile"),
                            ],
                            "python_version": [FV("Python 3.6")],
                        },
                    ),
                    Event(
                        sha256="3329a2579f8595fcae5d0a054cfa84ba6323dd19d1bde9255ebdc1d14928622e",
                        parent=EventParent(sha256="31ef2ffab99e25a3674aaeee81037ae701bdaddc6dbda68de91c732df122cc03"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="3329a2579f8595fcae5d0a054cfa84ba6323dd19d1bde9255ebdc1d14928622e",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("cofix.pyc")]},
                    ),
                    Event(
                        sha256="cbba89ee8d76b7d7881d6c142b834236d16ff0935edf89fab397c600e7416c79",
                        parent=EventParent(sha256="31ef2ffab99e25a3674aaeee81037ae701bdaddc6dbda68de91c732df122cc03"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="cbba89ee8d76b7d7881d6c142b834236d16ff0935edf89fab397c600e7416c79",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("PYZ-00.pyz")]},
                    ),
                ],
                data={
                    "3329a2579f8595fcae5d0a054cfa84ba6323dd19d1bde9255ebdc1d14928622e": b"",
                    "cbba89ee8d76b7d7881d6c142b834236d16ff0935edf89fab397c600e7416c79": b"",
                },
            ),
        )

    def test_pyinstaller_mac_old(self):
        """
        Test on Mac Pyinstaller file
        """
        # alter unbox to determine platform from file header, in such cases
        result = self.do_execution(
            entity_attrs={"file_format": "executable/linux/elf32"},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "3d9795054c9d17301a603cb067cf2b72918700f88bbab21184dc267bd5c51e8f",
                        "Benign Mach-O i386 Executable.",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="3d9795054c9d17301a603cb067cf2b72918700f88bbab21184dc267bd5c51e8f",
                        features={
                            "build_time": [FV("2011-06-11T21:15:48+00:00")],
                            "pyinstaller_build_platform": [FV("Mac")],
                            "python_library": [
                                FV("Carbon"),
                                FV("ConfigParser"),
                                FV("Crypto"),
                                FV("EasyDialogs"),
                                FV("Finder"),
                                FV("HTMLParser"),
                                FV("Queue"),
                                FV("StdSuites"),
                                FV("StringIO"),
                                FV("UserDict"),
                                FV("_LWPCookieJar"),
                                FV("_MozillaCookieJar"),
                                FV("__future__"),
                                FV("_abcoll"),
                                FV("_builtinSuites"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("_weakrefset"),
                                FV("abc"),
                                FV("aepack"),
                                FV("aetools"),
                                FV("aetypes"),
                                FV("aifc"),
                                FV("applesingle"),
                                FV("atexit"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("cProfile"),
                                FV("calendar"),
                                FV("chunk"),
                                FV("cmd"),
                                FV("code"),
                                FV("codecs"),
                                FV("codeop"),
                                FV("collections"),
                                FV("cookielib"),
                                FV("copy"),
                                FV("copy_reg"),
                                FV("ctypes"),
                                FV("difflib"),
                                FV("dis"),
                                FV("doctest"),
                                FV("dummy_thread"),
                                FV("dummy_threading"),
                                FV("email"),
                                FV("encodings"),
                                FV("fnmatch"),
                                FV("ftplib"),
                                FV("functools"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("glob"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("heapq"),
                                FV("hmac"),
                                FV("htmlentitydefs"),
                                FV("httplib"),
                                FV("imghdr"),
                                FV("inspect"),
                                FV("io"),
                                FV("keyword"),
                                FV("linecache"),
                                FV("locale"),
                                FV("logging"),
                                FV("macostools"),
                                FV("macresource"),
                                FV("markupbase"),
                                FV("md5"),
                                FV("mimetools"),
                                FV("mimetypes"),
                                FV("mmfparser"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("os2emxpath"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("pkgutil"),
                                FV("platform"),
                                FV("plistlib"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("pstats"),
                                FV("pty"),
                                FV("py_compile"),
                                FV("pyglet"),
                                FV("quopri"),
                                FV("random"),
                                FV("re"),
                                FV("repr"),
                                FV("rfc822"),
                                FV("sets"),
                                FV("sha"),
                                FV("shlex"),
                                FV("shutil"),
                                FV("snakesound"),
                                FV("sndhdr"),
                                FV("socket"),
                                FV("sre_compile"),
                                FV("sre_constants"),
                                FV("sre_parse"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("traceback"),
                                FV("tty"),
                                FV("twisted"),
                                FV("types"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("urllib2"),
                                FV("urlparse"),
                                FV("uu"),
                                FV("warnings"),
                                FV("weakref"),
                                FV("webbrowser"),
                                FV("xml"),
                                FV("zipfile"),
                                FV("zope"),
                            ],
                            "python_version": [FV("Python 2.7")],
                        },
                    ),
                    Event(
                        sha256="7058d4279ba9504227c4ff30a583ff9e2f7565a58091888cb4b7c317979da059",
                        parent=EventParent(sha256="3d9795054c9d17301a603cb067cf2b72918700f88bbab21184dc267bd5c51e8f"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="7058d4279ba9504227c4ff30a583ff9e2f7565a58091888cb4b7c317979da059",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("useUnicode.py")]},
                    ),
                    Event(
                        sha256="7b864503af40cb16e0267d42370bb1b508e59543a0b6fc04e316dd9c37d3869f",
                        parent=EventParent(sha256="3d9795054c9d17301a603cb067cf2b72918700f88bbab21184dc267bd5c51e8f"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="7b864503af40cb16e0267d42370bb1b508e59543a0b6fc04e316dd9c37d3869f",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("runtime.py")]},
                    ),
                    Event(
                        sha256="685a37b222edece8618c7aeed8b7053dd9932d78b87f8c1ea48a1cf57267ff0e",
                        parent=EventParent(sha256="3d9795054c9d17301a603cb067cf2b72918700f88bbab21184dc267bd5c51e8f"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="685a37b222edece8618c7aeed8b7053dd9932d78b87f8c1ea48a1cf57267ff0e",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("outPYZ1.pyz")]},
                    ),
                ],
                data={
                    "7058d4279ba9504227c4ff30a583ff9e2f7565a58091888cb4b7c317979da059": b"",
                    "7b864503af40cb16e0267d42370bb1b508e59543a0b6fc04e316dd9c37d3869f": b"",
                    "685a37b222edece8618c7aeed8b7053dd9932d78b87f8c1ea48a1cf57267ff0e": b"",
                },
            ),
        )

    def test_pyinstaller_win(self):
        """
        Test on Windows PyInstaller file
        """
        result = self.do_execution(
            entity_attrs={"file_format": "executable/linux/elf32"},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "233a763b12983c799c7aa3eff3085ed10bdc49fb84a73ac58f0e71f757db9e52", "Malicious Windows 32EXE."
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="233a763b12983c799c7aa3eff3085ed10bdc49fb84a73ac58f0e71f757db9e52",
                        features={
                            "pyinstaller_build_platform": [FV("Windows")],
                            "python_library": [
                                FV("__future__"),
                                FV("_compat_pickle"),
                                FV("_compression"),
                                FV("_py_abc"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("argparse"),
                                FV("ast"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("bz2"),
                                FV("calendar"),
                                FV("cmd"),
                                FV("code"),
                                FV("codeop"),
                                FV("contextlib"),
                                FV("copy"),
                                FV("ctypes"),
                                FV("datetime"),
                                FV("difflib"),
                                FV("dis"),
                                FV("doctest"),
                                FV("email"),
                                FV("fnmatch"),
                                FV("ftplib"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("glob"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("hmac"),
                                FV("html"),
                                FV("http"),
                                FV("importlib"),
                                FV("inspect"),
                                FV("logging"),
                                FV("lzma"),
                                FV("mimetypes"),
                                FV("netrc"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("pkgutil"),
                                FV("platform"),
                                FV("plistlib"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("py_compile"),
                                FV("pydoc"),
                                FV("pydoc_data"),
                                FV("quopri"),
                                FV("random"),
                                FV("runpy"),
                                FV("selectors"),
                                FV("shlex"),
                                FV("shutil"),
                                FV("signal"),
                                FV("smtplib"),
                                FV("socket"),
                                FV("socketserver"),
                                FV("sqlite3"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("tracemalloc"),
                                FV("tty"),
                                FV("typing"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("uu"),
                                FV("webbrowser"),
                                FV("xml"),
                                FV("zipfile"),
                            ],
                            "python_version": [FV("Python 3.7")],
                        },
                    ),
                    Event(
                        sha256="bea51c445789c60e92096ab6f49a2f38edeb1d6fd406de1e48746919df5249e3",
                        parent=EventParent(sha256="233a763b12983c799c7aa3eff3085ed10bdc49fb84a73ac58f0e71f757db9e52"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="bea51c445789c60e92096ab6f49a2f38edeb1d6fd406de1e48746919df5249e3",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("secret.pyc")]},
                    ),
                    Event(
                        sha256="821254775783f5b70c7d8ff8d0ab2f537cea61275dd27f250dd05ea61f589cef",
                        parent=EventParent(sha256="233a763b12983c799c7aa3eff3085ed10bdc49fb84a73ac58f0e71f757db9e52"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="821254775783f5b70c7d8ff8d0ab2f537cea61275dd27f250dd05ea61f589cef",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("PYZ-00.pyz")]},
                    ),
                ],
                data={
                    "bea51c445789c60e92096ab6f49a2f38edeb1d6fd406de1e48746919df5249e3": b"",
                    "821254775783f5b70c7d8ff8d0ab2f537cea61275dd27f250dd05ea61f589cef": b"",
                },
            ),
        )

    def test_pyinstaller_pkg(self):
        """
        Test on PyInstaller package lacking installer binary
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "bf8521a1ccdfa08a1c8b4586f04aecedf8f0adbd18a14fbbc93abc74bf676547",
                    "PyInstaller package lacking installer binary.",
                ),
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="bf8521a1ccdfa08a1c8b4586f04aecedf8f0adbd18a14fbbc93abc74bf676547",
                        features={
                            "pyinstaller_build_platform": [FV("Windows")],
                            "python_library": [
                                FV("__future__"),
                                FV("_compat_pickle"),
                                FV("_compression"),
                                FV("_dummy_thread"),
                                FV("_osx_support"),
                                FV("_py_abc"),
                                FV("_pydecimal"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("argparse"),
                                FV("ast"),
                                FV("asyncio"),
                                FV("base64"),
                                FV("bdb"),
                                FV("bisect"),
                                FV("bz2"),
                                FV("calendar"),
                                FV("certifi"),
                                FV("chardet"),
                                FV("cmd"),
                                FV("code"),
                                FV("codeop"),
                                FV("concurrent"),
                                FV("configparser"),
                                FV("contextlib"),
                                FV("contextvars"),
                                FV("copy"),
                                FV("csv"),
                                FV("ctypes"),
                                FV("datetime"),
                                FV("decimal"),
                                FV("difflib"),
                                FV("dis"),
                                FV("distutils"),
                                FV("doctest"),
                                FV("dummy_threading"),
                                FV("email"),
                                FV("fnmatch"),
                                FV("ftplib"),
                                FV("genericpath"),
                                FV("getopt"),
                                FV("getpass"),
                                FV("gettext"),
                                FV("glob"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("hmac"),
                                FV("html"),
                                FV("http"),
                                FV("idna"),
                                FV("importlib"),
                                FV("inspect"),
                                FV("ipaddress"),
                                FV("json"),
                                FV("lib2to3"),
                                FV("logging"),
                                FV("lzma"),
                                FV("mimetypes"),
                                FV("multiprocessing"),
                                FV("netrc"),
                                FV("nntplib"),
                                FV("ntpath"),
                                FV("nturl2path"),
                                FV("numbers"),
                                FV("opcode"),
                                FV("optparse"),
                                FV("os"),
                                FV("pathlib"),
                                FV("pdb"),
                                FV("pickle"),
                                FV("pkgutil"),
                                FV("platform"),
                                FV("plistlib"),
                                FV("posixpath"),
                                FV("pprint"),
                                FV("py_compile"),
                                FV("pydoc"),
                                FV("pydoc_data"),
                                FV("queue"),
                                FV("quopri"),
                                FV("random"),
                                FV("requests"),
                                FV("runpy"),
                                FV("secrets"),
                                FV("selectors"),
                                FV("shlex"),
                                FV("shutil"),
                                FV("signal"),
                                FV("smtplib"),
                                FV("socket"),
                                FV("socketserver"),
                                FV("ssl"),
                                FV("stat"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("sysconfig"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("test"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("tkinter"),
                                FV("token"),
                                FV("tokenize"),
                                FV("tracemalloc"),
                                FV("tty"),
                                FV("typing"),
                                FV("unittest"),
                                FV("urllib"),
                                FV("urllib3"),
                                FV("uu"),
                                FV("webbrowser"),
                                FV("xml"),
                                FV("xmlrpc"),
                                FV("zipfile"),
                                FV("zipimport"),
                            ],
                            "python_version": [FV("Python 3.8")],
                        },
                    ),
                    Event(
                        sha256="d1d6f009f131784abc513b06a319b540ae7bd6a0490c0071ce4f1953b58fa524",
                        parent=EventParent(sha256="bf8521a1ccdfa08a1c8b4586f04aecedf8f0adbd18a14fbbc93abc74bf676547"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="d1d6f009f131784abc513b06a319b540ae7bd6a0490c0071ce4f1953b58fa524",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("Paypal.pyc")]},
                    ),
                    Event(
                        sha256="a01fc433b2f13ca41f89207b38fb9a10cce49155857836a400064c17d6fa06a3",
                        parent=EventParent(sha256="bf8521a1ccdfa08a1c8b4586f04aecedf8f0adbd18a14fbbc93abc74bf676547"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="a01fc433b2f13ca41f89207b38fb9a10cce49155857836a400064c17d6fa06a3",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("PYZ-00.pyz")]},
                    ),
                ],
                data={
                    "d1d6f009f131784abc513b06a319b540ae7bd6a0490c0071ce4f1953b58fa524": b"",
                    "a01fc433b2f13ca41f89207b38fb9a10cce49155857836a400064c17d6fa06a3": b"",
                },
            ),
        )

    def test_pyinstaller_unicode(self):
        """
        Test on newer PyInstaller file that seems to use unicode script filename
        """
        self.assertJobResult(
            self._get_result_from_cart(
                self.load_test_file_bytes(
                    "12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af", "Malicious Windows EXE32."
                )
            ),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af",
                        features={
                            "pyinstaller_build_platform": [FV("Windows")],
                            "python_library": [
                                FV("__future__"),
                                FV("_compat_pickle"),
                                FV("_compression"),
                                FV("_py_abc"),
                                FV("_pydatetime"),
                                FV("_pydecimal"),
                                FV("_strptime"),
                                FV("_threading_local"),
                                FV("argparse"),
                                FV("ast"),
                                FV("base64"),
                                FV("bisect"),
                                FV("bz2"),
                                FV("calendar"),
                                FV("code"),
                                FV("codeop"),
                                FV("contextlib"),
                                FV("contextvars"),
                                FV("copy"),
                                FV("csv"),
                                FV("ctypes"),
                                FV("dataclasses"),
                                FV("datetime"),
                                FV("decimal"),
                                FV("dis"),
                                FV("email"),
                                FV("fnmatch"),
                                FV("fractions"),
                                FV("getopt"),
                                FV("gettext"),
                                FV("gzip"),
                                FV("hashlib"),
                                FV("hmac"),
                                FV("http"),
                                FV("importlib"),
                                FV("inspect"),
                                FV("ipaddress"),
                                FV("json"),
                                FV("logging"),
                                FV("lzma"),
                                FV("mimetypes"),
                                FV("numbers"),
                                FV("opcode"),
                                FV("pathlib"),
                                FV("pickle"),
                                FV("pprint"),
                                FV("py_compile"),
                                FV("pyaes"),
                                FV("queue"),
                                FV("quopri"),
                                FV("random"),
                                FV("selectors"),
                                FV("shutil"),
                                FV("signal"),
                                FV("socket"),
                                FV("sqlite3"),
                                FV("ssl"),
                                FV("statistics"),
                                FV("string"),
                                FV("stringprep"),
                                FV("subprocess"),
                                FV("tarfile"),
                                FV("tempfile"),
                                FV("textwrap"),
                                FV("threading"),
                                FV("token"),
                                FV("tokenize"),
                                FV("tracemalloc"),
                                FV("typing"),
                                FV("urllib"),
                                FV("urllib3"),
                                FV("zipfile"),
                            ],
                            "python_version": [FV("Python 3.12")],
                        },
                    ),
                    Event(
                        sha256="f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4",
                        parent=EventParent(sha256="12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("unknown_unicode_filename.pyc")]},
                    ),
                    Event(
                        sha256="95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995",
                        parent=EventParent(sha256="12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af"),
                        relationship={"action": "unpacked_pyinstaller"},
                        data=[
                            EventData(
                                hash="95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("PYZ-00.pyz")]},
                    ),
                ],
                data={
                    "f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4": b"",
                    "95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995": b"",
                },
            ),
        )
