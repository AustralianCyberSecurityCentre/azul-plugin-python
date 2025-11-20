"""Script to list all the files in a .pyz archive.

Attempts to read the compiled Python bytecode that contains the filenames and will break
between Python versions.  Currently works, but is somewhat fragile.
"""

import binascii
import logging
import os
import re
import struct
import sys
from typing import Optional

import xdis.magics
import xdis.marsh
import xdis.version

from azul_plugin_python_decompiler.pylib_classifier.pylib_classifier import (
    PyLibClassifier,
)


def xdis_version() -> str:
    """Return the xdis version from new and old releases."""
    # xdis < 5.0.5
    if hasattr(xdis.version, "VERSION"):
        return xdis.version.VERSION
    return xdis.version.__version__


class PyzUnpackError(Exception):
    """Something went wrong during unpacking."""


def _list_files_in_pyz_2(pyz: bytes) -> list:
    """Parse out the list of names from a python 2 bytecode list.

    :param pyz: Python 2 dict() bytecode
    :return: A list of filenames from the TOC in the dict, empty if parsing fails
    """
    filenames = []

    # might need to add support for older PyInstaller dict structure,
    # only required if xdis fails to marshal Py2.7 code
    for match in re.finditer(b"\\x28\x02\x00\x00\x00.(....)", pyz, flags=re.DOTALL):
        (length,) = struct.unpack("<i", match.group(1))
        index = match.end(0)
        f = "{}s".format(length)

        name = struct.unpack(f, pyz[index : index + length])[0].decode("utf-8")
        filenames.append(name)

    return filenames


def _list_files_in_pyz_3(pyz: bytes) -> list:
    """Parse out the list of names from a python 3 bytecode dict.

    Works on 3.6, 3.7, 3.3,
    :param pyz: Python 3 dict() bytecode
    :return: A list of filenames from the TOC in the dict, empty if parsing fails
    """
    filenames = []
    # could determine what this byte combo means, then build it for each python version.
    # name_markers = [b"\x29\x02\xfa", b"\x29\x02\xda"]
    # we can regex these.
    for match in re.finditer(b"\\x29\x02[\xfa\xda](.)", pyz, flags=re.DOTALL):
        (length,) = struct.unpack("B", match.group(1))
        index = match.end(0)
        f = "{}s".format(length)

        name = struct.unpack(f, pyz[index : index + length])[0].decode("utf-8")
        filenames.append(name)

    return filenames


def list_pyz_files(contents: bytes) -> tuple[str, str]:
    """Parse out the filenames contained within the PYZ archive content.

    :param contents: Byte string containing PYZ archive
    :return: Tuple of short form and long form, categorised imports
    """
    # check header
    if contents[:4] != b"PYZ\x00":
        raise PyzUnpackError("Not a PYZ archive!")

    (toc_index,) = struct.unpack(">i", contents[8:12])
    logging.info("toc starts @{}".format(hex(toc_index)))

    if toc_index > len(contents):
        raise PyzUnpackError("Invalid TOC in PYZ archive")

    filenames = []

    try:
        # this should work and give us a dict
        toc = xdis.marsh.loads(contents[toc_index:])
        logging.info("Found {} scripts within marshalled bytecode resource".format(len(toc)))

        # check for older PYZ (dict) or newer (list)
        if isinstance(toc, dict):
            for fn in toc.keys():
                if isinstance(fn, bytes):
                    f = fn.decode("utf-8")
                else:
                    f = fn
                filenames.append(f)

        elif isinstance(toc, list):
            for fn in toc:
                if isinstance(fn[0], bytes):
                    f = fn[0].decode("utf-8")
                else:
                    f = fn[0]
                filenames.append(f)

    except (ValueError, TypeError, AttributeError):
        logging.info("Failed to marshal script bytecode with xdis {}!".format(xdis_version()))

    if not filenames:
        # xdis has failed us, so we'll manually parse the dict badly
        list2 = _list_files_in_pyz_2(contents[toc_index:])
        list3 = _list_files_in_pyz_3(contents[toc_index:])

        if len(list2) > len(list3):
            filenames = list2
            logging.info("Used Python 2 bytecode decoding")
        else:
            filenames = list3
            logging.info("Used Python 3 bytecode decoding")

    if not filenames:
        raise PyzUnpackError("TOC is empty?")

    logging.info("Found {} files in TOC".format(len(filenames)))
    libs = PyLibClassifier(filenames)
    imports_short, imports_long = libs.get_imports()

    return imports_short, imports_long


def get_python_version(pyz: bytes) -> Optional[int]:
    """Get the Python version of a PYZ file from its header."""
    if py_ver := xdis.magics.magicint2version.get(xdis.magics.magic2int(pyz[4:8])):
        logging.info(f"Python version found in PYZ header is {py_ver}")
    else:
        logging.info("Unknown Python version in PYZ header, is it too old or does xdis need updating?")
    return py_ver


def get_python_magic(pyz: bytes) -> bytes:
    """Get the Python magic of a PYZ file from its header."""
    # magic seems to be second dword within PYZ file
    logging.info(f"Python magic found in PYZ: {binascii.hexlify(pyz[4:8], ' ').decode()}")
    return pyz[4:8]


def main():
    """Scan pyz file from the command-line, printing to stdout."""
    if len(sys.argv) != 2:
        print("No input file specified!")
        sys.exit(1)

    # check that file is a file?
    if os.path.isfile(sys.argv[1]) is not True:
        print("[-] {} is not a file!".format(sys.argv[1]))
        sys.exit(1)

    logging.basicConfig(level=logging.ERROR)

    # read size
    with open(sys.argv[1], "rb") as f:
        contents = f.read()

    short, long = list_pyz_files(contents)

    # write Python magic and show version
    print(f"[+] Python magic in PYZ: {binascii.hexlify(get_python_magic(contents), ' ').decode()}")
    print(f"[+] Python version is {get_python_version(contents)}")

    # write import lists
    sf = "# Standard Libraries\n"
    for lib in short["standard"]:
        sf += "{}\n".format(lib)
    sf += "\n# External Libraries\n"
    for lib in short["external"]:
        sf += "{}\n".format(lib)
    fn = sys.argv[1] + "_short"
    print("[+] Writing short imports to {}".format(fn))
    with open(fn, "w") as f:
        f.write(sf)

    lf = "# Standard Libraries\n"
    for lib in long["standard"]:
        lf += "{}\n".format(lib)
    lf += "\n# External Libraries\n"
    for lib in long["external"]:
        lf += "{}\n".format(lib)
    fn = sys.argv[1] + "_long"
    print("[+] Writing long imports to {}".format(fn))
    with open(fn, "w") as f:
        f.write(lf)


if __name__ == "__main__":
    main()
