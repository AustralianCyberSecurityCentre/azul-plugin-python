"""Unpacks compiled python scripts from binaries built with py2exe.

This produces output such as the following:

    Wrote 2434 bytes to boot_common.pyc (f7731039620f4f6303f6cad40babd81e)
    Wrote 173 bytes to <install zipextimporter>.pyc (ed6468a411e99bbaeb36135a0ddaeaba)
    Wrote 3845 bytes to st_main.pyc (17e322c796f88bfa34cd7b42e7113e93)
    python_version: Python 2.7
    build_time: 2017-02-14T17:38:00
    Wrote 4726161 bytes to st_main.zip (650c2c7221a4dc6ec1e8dc01fa48a1c1)
    Wrote import_report_short.txt
    Wrote import_report_long.txt


All the compiled Python scripts from within the py2exe binary are extracted as compiled Python bytecode files
(*.pyc).  These can be decompiled with uncompyle6.  Typically two or three compiled scripts will be unpacked,
with one being the main script and the others being required by the py2exe binary to load the Python environment
in preparation for the main script.

Metadata that can be produced during unpacking includes:
- The version of Python included or required by the py2exe binary
- The build time of the py2exe binary, as found in the compiled Python bytecode
- The name of the zip file that contains the required Python libraries, if this is not packed
within the py2exe binary

If the py2exe binary contains a zip file of compiled Python libraries used by the packaged script, then
these imported libraries are listed in the two import report text files.  The shorter report lists each
top-level package, while the longer report lists all the modules used within the package.

The categorisation of the imports within these reports is also not completely accurate, but should be
good enough to identify which libraries are likely user code and which are likely standard Python libraries
or common third party libraries.


## Miscellaneous

### xdis

py2exe-unpacker relies upon xdis to extract the compiled bytecode and cannot extract script files if this fails.
If you find that py2exe-unpacker cannot unpack a binary with the currently installed version of xdis, try
switching to a newer or older version.


### Python 2 support

The script does work on Python 2.7, but it will likely have difficulties with some versions of xdis.  Version
4.2.4 was found to work, so start there.


### NSIS

Py2Exe can produce NSIS installer exes, which is well documented on their website.  This cannot be unpacked by
this tool.  However, 7-Zip can open these archives and be used to extract .pyc files that can be decompiled.
"""

import hashlib
import logging
import ntpath
import re
import struct
import sys
import zipfile
from binascii import hexlify
from datetime import datetime
from io import BytesIO
from typing import Any

import pefile
import xdis.bytecode
import xdis.marsh
import xdis.version

from azul_plugin_python_decompiler.pylib_classifier.pylib_classifier import (
    PyLibClassifier,
)


def xdis_version():
    """Return the xdis version from new and old releases."""
    # xdis < 5.0.5
    if hasattr(xdis.version, "VERSION"):
        return xdis.version.VERSION
    return xdis.version.__version__


class Py2ExeUnpackError(Exception):
    """The Py2Exe file failed to unpack."""


class Py2ExeUnpacker:
    """Unpacker for python scripts packaged into executables using py2exe."""

    MARKER = b"\x12\x34\x56\x78"

    # extract_zip flag is used control when zip archives within py2exe are unpacked
    # unbox or azul_unbox won't set it, so they don't get zips
    def __init__(self, data=None, extract_zip=False):
        """Create a new unpacker for the specified data."""
        self.py_version_int = 0
        self.py_version_string = ""
        self.pyc_header = b""
        self.overlay = None
        self.pycs = []
        self.pyc_filenames = []
        self.zip_name = ""
        self.py2exe_version = ""
        self.all_libraries = []
        self.hash = ""
        self._extract_zip = extract_zip

        # process data if given
        if data is not None:
            self.unpack(data)

    def _extract_resource(self, contents):
        """Extract the script resource from the py2exe.

        :param contents: the contents of a py2exe binary in a bytes object
        :return: the extracted resource
        :raises: Py2ExeUnpackError
        """
        try:
            pe = pefile.PE(data=contents, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        except pefile.PEFormatError:
            raise Py2ExeUnpackError("Not a PE file!")

        resource = None

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            raise Py2ExeUnpackError("No directory entry resources were found, not a python executable!")

        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if rsrc.name is not None:
                if rsrc.name.string == b"PYTHONSCRIPT":
                    logging.info("Found Python script resource - {}".format(rsrc.name.string))
                    offset = rsrc.directory.entries[0].directory.entries[0].data.struct.OffsetToData
                    size = rsrc.directory.entries[0].directory.entries[0].data.struct.Size
                    resource = pe.get_memory_mapped_image()[offset : offset + size]

                elif rsrc.name.string.lower().startswith(b"python"):
                    logging.info("Found Python dll resource - {}".format(rsrc.name.string.decode("utf-8")))
                    # determine the python version from the dll
                    # the dll might not be present, depending on how the file was packed
                    offset = rsrc.directory.entries[0].directory.entries[0].data.struct.OffsetToData
                    size = rsrc.directory.entries[0].directory.entries[0].data.struct.Size
                    try:
                        dll = pe.get_memory_mapped_image()[offset : offset + size]
                        self._set_python_version_from_dll(dll)
                    except pefile.PEFormatError:
                        raise Py2ExeUnpackError("Invalid Python DLL resource!")

        if resource is None:
            raise Py2ExeUnpackError("No PYTHONSCRIPT resource found!")

        # try to set the python version from the exe
        if self.py_version_int == 0:
            self._set_python_version_from_exe(contents)

        # the resource should start with the correct marker
        if resource.find(self.MARKER) != 0:
            raise Py2ExeUnpackError("Invalid PYTHONSCRIPT resource!")

        # check if zip exists
        offset = pe.get_overlay_data_start_offset()
        self.overlay = contents[offset:]

        return resource

    def _set_python_version_from_dll(self, py_dll):
        """Set the python version from the python dll that was packaged within it.

        :param py_dll: a Python dll that will contain version information
        """
        try:
            py_pe = pefile.PE(data=py_dll, fast_load=True)
            py_pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

            major = (py_pe.VS_FIXEDFILEINFO[0].ProductVersionMS & 0xFFFF0000) >> 16
            minor = py_pe.VS_FIXEDFILEINFO[0].ProductVersionMS & 0x0000FFFF

            self.py_version_string = "Python {}.{}".format(major, minor)
            self.py_version_int = major * 10 + minor
            logging.info("Python dll version is {}".format(self.py_version_string))
        except pefile.PEFormatError as e:
            # either the dll is corrupt or missing?
            raise e
        except AttributeError:
            # pe doesn't have version set?
            logging.info("Could not determine Python version from dll")
            pass

    def _set_python_version_from_scripts(self, scripts):
        """Set the python version using a path string that should be in the bytecode scripts.

        :param scripts: the bytecode scripts resource extracted from a py2exe binary
        """
        matches = re.search(b"Python(..)\\\\lib\\\\site-packages\\\\py2exe", scripts)
        if matches is not None:
            self.py_version_int = int(matches.group(1))
            self.py_version_string = "Python {}.{}".format(self.py_version_int // 10, self.py_version_int % 10)
            logging.info("Detected {} within boot_common.pyc".format(self.py_version_string))

    def _set_python_version_from_exe(self, content):
        """Set the python version from a string hardcoded into the exe.

        :param content: the contents of the file
        """
        matches = re.search(b"PYTHON(..)\\.DLL", content)
        if matches is not None:
            self.py_version_int = int(matches.group(1))
            self.py_version_string = "Python {}.{}".format(self.py_version_int // 10, self.py_version_int % 10)
            logging.info("Detected {} within exe".format(self.py_version_string))

    def _set_header(self):
        """Determine what the header for any compiled python scripts should be."""
        if self.overlay is not None and self.overlay[:4] == b"PK\x03\x04":
            #
            z = BytesIO(self.overlay)
            try:
                zipped_pyc = zipfile.ZipFile(z)

                for info in zipped_pyc.filelist:
                    # got pyo files here?
                    if info.filename.lower().endswith(".pyc") or info.filename.lower().endswith(".pyo"):
                        # store python packages used by the packaged py2exe application
                        self.all_libraries.append(info.filename[:-4].replace("/", "."))

                        # determine header length
                        if self.py_version_int > 0 and len(self.pyc_header) == 0:
                            pyc_file = zipped_pyc.open(info.filename)
                            hl = self._determine_header_length()
                            self.pyc_header = pyc_file.read(256)[:hl]
                            logging.info("Header set to {}".format(hexlify(self.pyc_header).decode("utf-8")))
                logging.info(
                    "Internal zip file contains {} compiled python library files".format(len(self.all_libraries))
                )
            except zipfile.BadZipFile:
                logging.info("Could not open zip file!")
                pass

        # we can forge a header because we know the python version
        if self.py_version_int > 0 and len(self.pyc_header) == 0:
            ver = self.py_version_string.split(" ")[1]
            self.pyc_header = xdis.magics.magics[ver] + (self._determine_header_length() - 4) * b"\x00"
            logging.info("Forged header {} for {}".format(hexlify(self.pyc_header), self.py_version_string))

    def _determine_header_length(self):
        """Calculate how long a .pyc header should be for a specific python version.

        :return: the length of the header
        """
        if self.py_version_int <= 32:
            return 8
        # py 3.4 actually 12 bytes?
        elif 32 < self.py_version_int < 37:
            return 12
        elif self.py_version_int >= 37 or self.py_version_int == 34:
            return 16
        else:
            # not good
            return 0

    @staticmethod
    def _test_byte_is_not_null(b):
        """Test a single byte for null in both Python 2 and 3.

        :param b: an int or a str, depending on python version
        :return: True if b is not a null byte, False otherwise
        """
        if isinstance(b, int):
            # py3 safe check
            return b != 0

        elif isinstance(b, str):
            # py2 safe check
            return b != b"\x00"

    def _process_resource(self, py_resource):
        """Process the resource within a Py2Exe binary to extract the compiled scripts.

        :param py_resource: resource containing python scripts compiled into a sequence object
        :raises: Py2ExeUnpackError if marshalling bytecode fails
        """
        # struct scriptinfo {
        # 	int tag;
        # 	int optimize;
        # 	int unbuffered;
        # 	int data_bytes;
        #
        # 	char zippath[0];
        # };

        # get useful values
        (size,) = struct.unpack("<L", py_resource[0xC:0x10])
        logging.info("Scripts bytecode is {} bytes".format(size))
        # check for filename
        start = 0x10
        name = bytearray()

        if self._test_byte_is_not_null(py_resource[start]):
            # filename exists, read it
            while self._test_byte_is_not_null(py_resource[start]):
                name.append(py_resource[start])
                start += 1

            # skip over null byte
            start += 1
            self.zip_name = name.decode("utf-8")
            logging.info("External zipfile is {}".format(self.zip_name))
        else:
            # no filename
            logging.info("No external zipfile")
            start += 1

        # actual resource is from start to start + size
        py_scripts = py_resource[start : start + size]

        # marshal the bytecode, giving a list of Code objects
        # no obvious way to get a list of byte arrays, where each array is a compiled script
        try:
            bytecodes = xdis.marsh.loads(py_scripts)
            logging.info("Found {} scripts within marshalled bytecode resource".format(len(bytecodes)))
        except (ValueError, TypeError, AttributeError):
            # could we instead
            raise Py2ExeUnpackError("Failed to marshal script bytecode with xdis {}!".format(xdis_version()))

        for bytecode in bytecodes:
            if bytecode.co_filename.endswith(".py"):
                filename = bytecode.co_filename + "c"
            else:
                filename = bytecode.co_filename

            if not filename.endswith(".pyc"):
                filename = filename + ".pyc"

            logging.info(" - {}".format(filename))

            # dump and dumps produced slightly different bytecode
            # the wrapper class around BytesIO could have also been responsible
            # just use dumps to avoid problems
            try:
                pyc = xdis.marsh.dumps(bytecode)

                # append complete bytecode with header to list
                self.pycs.append(bytes(self.pyc_header + pyc))
                self.pyc_filenames.append(filename)
            except (AttributeError, UnicodeDecodeError):
                raise Py2ExeUnpackError(
                    "Failed to dump marshalled bytecode with xdis {}!".format(xdis.version.VERSION)
                )

    def _set_timestamp(self):
        """Set timestamp if one found in .pyc header."""
        if len(self.pyc_header) == 16:
            start = 8
            end = 12
            self.compile_time = struct.unpack("<i", self.pyc_header[start:end])[0]
        elif len(self.pyc_header) == 12 or len(self.pyc_header) == 8:
            start = 4
            end = 8
            self.compile_time = struct.unpack("<i", self.pyc_header[start:end])[0]
        else:
            self.compile_time = 0

    def unpack(self, contents):
        """Unpack a Py2Exe binary.

        :param contents: a bytes object containing a py2exe binary file
        """
        # extract the resource
        script_resource = self._extract_resource(contents)

        self.hash = hashlib.md5(contents).hexdigest()  # noqa: S303 # nosec B303 B324

        # if no zip, then get the python version from the scripts
        if self.py_version_int == 0:
            self._set_python_version_from_scripts(script_resource)

        self._set_header()

        self._process_resource(script_resource)

        self._set_timestamp()

    def get_results(self) -> dict[str, Any]:
        """Return a dict of all the unpacked metadata.

        Optionally include zip content if unpacker flag set.
        :return: dict of results
        """
        results = {"scripts": dict(zip(self.pyc_filenames, self.pycs))}

        if len(self.py_version_string) > 0:
            results["python_version"] = self.py_version_string

        if self.compile_time > 0:
            results["build_time"] = self.compile_time

        if len(self.zip_name) > 0:
            results["zipfile_name"] = self.zip_name

        if len(self.py2exe_version) > 0:
            results["py2exe_version"] = self.py2exe_version

        # only store zip if flag says to and one exists
        if self._extract_zip and self.overlay is not None and self.overlay[:4] == b"PK\x03\x04":
            if len(self.zip_name) > 0:
                x = self.zip_name
            else:
                x = self.pyc_filenames[-1].split(".")[0] + ".zip"

            results[x] = self.overlay

        if len(self.all_libraries) > 0:
            libs = PyLibClassifier(self.all_libraries, self.hash)
            results["imports_short"], results["imports_long"] = libs.get_imports()

        return results


def write_imports(imports, filename):
    """Write the supplied categorised imports to file."""
    with open(filename, "w") as f:
        f.write("# Standard Python Libraries\n")
        for lib in imports["standard"]:
            f.write(lib)
            f.write("\n")
        f.write("\n")
        f.write("# External Python Libraries\n")
        for lib in imports["external"]:
            f.write(lib)
            f.write("\n")


def main():
    """Unpack Py2Exe from command-line."""
    if len(sys.argv) != 2:
        print("Usage: {} PY2EXE_FILE_TO_UNPACK".format(sys.argv[0]))
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        content = f.read()

    logging.basicConfig(level=logging.WARNING)

    try:
        # we want zips here, so pass the flag
        res = Py2ExeUnpacker(content, extract_zip=True).get_results()

        for k in res.keys():
            if k == "scripts":
                for filename in res["scripts"].keys():
                    # write out each script, dropping any windows paths
                    bn = ntpath.basename(filename)
                    with open(bn, "wb") as f:
                        fc = res["scripts"][filename]
                        f.write(fc)
                        digest = hashlib.md5(fc).hexdigest()  # noqa: S303 # nosec B303 B324
                        print("Wrote {} bytes to {} ({})".format(len(fc), bn, digest))
            elif k == "build_time":
                print("{}: {}".format(k, datetime.fromtimestamp(res[k]).isoformat()))
            elif k.endswith(".zip"):
                with open(k, "wb") as f:
                    f.write(res[k])
                    digest = hashlib.md5(res[k]).hexdigest()  # noqa: S303 # nosec B303 B324
                    print("Wrote {} bytes to {} ({})".format(len(res[k]), k, digest))
            elif k == "import_report_short" or k == "import_report_long":
                fn = k + ".txt"
                with open(fn, "w") as f:
                    f.write(res[k])
                    print("Wrote {}".format(fn))
            elif k == "imports_short" or k == "imports_long":
                fn = k + ".txt"
                write_imports(res[k], fn)
                print("Wrote {}".format(fn))
            else:
                print("{}: {}".format(k, res[k]))

    except Py2ExeUnpackError as e:
        print(e.args[0])


if __name__ == "__main__":
    main()
