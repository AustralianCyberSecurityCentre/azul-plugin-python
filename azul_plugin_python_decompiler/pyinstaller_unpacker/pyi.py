"""Extracts files and metadata from PyInstaller executables and packages.

Works on Linux, Mac and Windows executables.
"""

import hashlib
import os
import struct
import sys
import time
import zlib
from typing import Any, Optional

from azul_plugin_python_decompiler.pyinstaller_unpacker.pyz import (
    get_python_magic,
    get_python_version,
    list_pyz_files,
)


# exceptions
class NoPackage(Exception):
    """No PyInstaller Package Found."""


class InvalidFile(Exception):
    """Is not a valid PyInstaller file."""


class UnsupportedFile(Exception):
    """This file type/version is not supported."""


# magic string used to mark the structure at the end of a PyInstaller file
PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
ZLIB_HEADERS = [b"\x78\xda", b"\x78\x9c"]


def process_pyinstaller(contents: bytes) -> Optional[dict]:
    """Extract all the interesting elements of a pyinstaller file.

    :param contents: A PyInstaller file
    :return: A dict containing contents and metadata, None otherwise
    """
    # get the package and size of the cookie at the end
    package, cookie_size = find_package(contents)
    cookie = package[-cookie_size:]

    d = parse_cookie(cookie)

    # list the contents
    toc = parse_toc(package[d["toc_index"] : d["toc_index"] + d["toc_length"]])
    if toc is None:
        raise InvalidFile

    results = {}

    if "py_version" in d:
        # python version is saved as an int of the string repr.
        # eg: 2.7 = 27, 3.9 = 39, 3.10 = 310
        vers = str(d["py_version"])
        results["python_version"] = (int(vers[0]), int(vers[1:]))

    # pull out struct to get a correct header
    pyc_header = get_pyc_header(package, toc)
    if pyc_header is None:
        # pyinstaller>=5.3 removes pyc headers: https://github.com/pyinstaller/pyinstaller/commit/a97fdf
        pyc_header = build_pyc_header(results["python_version"])
    else:
        # get the python pyc version from the header
        results["python_magic_pyc_version"] = struct.unpack("<H", pyc_header[:2])[0]
        # try to get compile time, if it exists
        unix, gmt = get_compile_time(pyc_header)
        if unix is not None and gmt is not None:
            results["compile_time_unix"] = unix
            results["compile_time_gmt"] = gmt

    # get archive of other files
    pyz_archives = get_pyz_contents(package, toc)
    for archive in pyz_archives:

        # if we set built an empty bytecode header earlier, replace it with a correct bytecode magic from the PYZ files
        if pyc_header[:4] == b"\x00\x00\x00\x00" and (pyc_magic := get_python_magic(archive[1])):
            pyc_header = pyc_magic + pyc_header[4:]
            results["python_magic_pyc_version"] = struct.unpack("<H", pyc_header[:2])[0]

        # if we couldn't set a Python version earlier, try again now
        if "python_version" not in results and (ver := get_python_version(archive[1])):
            results["python_version"] = ver

        # get archive file listings
        short, long = list_pyz_files(archive[1])
        results[archive[0]] = (archive[1], short, long)

    scripts = get_scripts(package, toc)
    if len(scripts) != 0:
        results["scripts"] = []

        # put scripts into results dict
        for script in scripts:
            # compiled files will have nulls in their first 16 bytes
            if script[1][:16].find(b"\x00") > -1:
                # is compiled, add header
                name = script[0] + ".pyc"
                s = pyc_header + script[1]
            else:
                # uncompiled code, no header needed
                name = script[0] + ".py"
                s = script[1]
            results["scripts"].append((name, s))

    results["cookie_size"] = cookie_size

    # get platform, global is set previously by get_package() or ??
    platform = set_platform(d.get("py_lib", ""), contents[:16])
    if platform is not None:
        results["build_platform"] = platform

    # done?
    return results


def build_pyc_header(py_version: tuple) -> bytes:
    """Create a blank PYC header."""
    header = [b"\x00" * 4]  # fake py version number
    major, minor = py_version

    # Check version for PEP552: https://peps.python.org/pep-0552/
    if major >= 3 and minor >= 7:
        header.append(b"\x00" * 4)  # add bitfield
        header.append(b"\x00" * 8)  # add modification date + size
    else:
        header.append(b"\x00" * 4)  # timestamp
        if major >= 3 and minor >= 3:
            header.append(b"\x00" * 4)  # size
    return b"".join(header)


def set_platform(lib: str, header: bytes) -> str:
    """Determine the platform from the python lib used OR the header passed.

    :param lib: The library name
    :return: The name of the platform the package was built for or None
    """
    if lib.endswith(".dll") or header[:2] == b"MZ":
        return "Windows"

    if lib == "Python" or header[:4] == b"\xce\xfa\xed\xfe" or header[:4] == b"\xcf\xfa\xed\xfe":
        return "Mac"

    if lib.startswith("libpython") or header[:3] == b"ELF":
        return "Linux"


def find_package(contents: bytes) -> tuple[bytes, int]:
    """Find the package within the PyInstaller file and return it.

    If the entire file is the package, this still works nicely.
    :param contents: the full contents of the PyInstaller file
    :return: the extracted package
    """
    # find magic
    marker = contents.rfind(PYI_MAGIC)

    # marker points to start of toc in file space
    if marker == -1:
        # marker missing, not good
        # print("marker missing?")
        raise InvalidFile

    # start == magic + magic_struct_size - package_size
    # cookie struct is one of these sizes, hopefully
    struct_sizes = [88, 84, 20, 24]

    # get package size
    p = struct.unpack(">i", contents[marker + 8 : marker + 12])[0]

    for s in struct_sizes:
        index = marker + s - p
        # package usually starts with zlib compressed file, older packages have PYZ archive first
        if contents[index : index + 2] in ZLIB_HEADERS or contents[index : index + 4] == b"PYZ\x00":
            cookie = contents[marker : marker + s]
            package = contents[index : index + p]
            return package, len(cookie)

    # if we haven't found it by now, we should give up
    raise InvalidFile


def parse_cookie(cookie: bytes) -> dict:
    """Parse the cookie structure returning a dict of field values.

    :param cookie: Data to parse
    :return: Dict of parsed fields
    """
    # supported lengths are 88, 84, 24, 20
    if len(cookie) == 88:
        # has a py version
        keys = ["magic", "length", "toc_index", "toc_length", "py_version", "py_lib"]
        values = struct.unpack(">8siiii64s", cookie)
        x = dict(zip(keys, values))
    elif len(cookie) == 84:
        # v3 or earlier, no pyvers
        keys = ["magic", "length", "toc_index", "toc_length", "py_lib"]
        values = struct.unpack(">8siii64s", cookie)
        x = dict(zip(keys, values))
    elif len(cookie) == 24:
        # v3 or earlier, no pyvers
        keys = ["magic", "length", "toc_index", "toc_length", "py_version"]
        values = struct.unpack(">8siiii", cookie)
        x = dict(zip(keys, values))
    elif len(cookie) == 20:
        # v3 or earlier, no pyvers
        keys = ["magic", "length", "toc_index", "toc_length"]
        values = struct.unpack(">8siii", cookie)
        x = dict(zip(keys, values))
    else:
        # cookie length is unknown, which is bad here
        raise InvalidFile

    # clean up null padding from python dll name
    if "py_lib" in x:
        x["py_lib"] = x["py_lib"].decode("utf-8").rstrip("\x00")

    return x


def parse_toc(toc_contents: bytes) -> dict[str, dict[str, Any]]:
    """Parse the table of contents into a list of files within the installer.

    :param toc_contents: The table of contents from the file
    :return: A list of dicts containing toc entries
    """
    toc_dict: dict[str, dict[str, Any]] = {}

    while len(toc_contents) > 0:
        # read dword at start of toc
        entry_len = struct.unpack(">i", toc_contents[0:4])[0]

        # remove that many bytes from start of toc
        head = toc_contents[0:entry_len]
        toc_contents = toc_contents[entry_len:]

        name, record = get_record(head)
        toc_dict[name] = record

    return toc_dict


def get_record(record: bytes) -> tuple[str, dict[str, Any]]:
    """Read an entry from the table of contents into a dict of its values.

    :param record: An entry in the toc, whose first 18 bytes hold data and the filename is the remainder
    :return: A dict of entries
    """
    # 18 is the length of the bytes before the name
    keys = ["size", "offset", "compressed_size", "decompressed_size", "compressed_flag", "entry_type"]
    v = struct.unpack(">iiiiBc", record[:18])

    # convert entry type to str for internal use
    values = (v[0], v[1], v[2], v[3], v[4], v[5].decode("utf-8"))

    rec = dict(zip(keys, values))
    try:
        # randomish stuff can sometime pass this decode but still be gunk?
        name = record[18:].rstrip(b"\x00").decode("utf-8")

        # some filenames are actually just random bytes that happen to decode somewhat as utf-8
        if not name.isprintable():
            # replace those names
            name = "unknown_unicode_filename"
    except UnicodeDecodeError:
        # name can apparently be utf-16?
        # some malware seems to be generating random filenames here, so we won't decode it
        # name = record[18:].rstrip(b"\x00").decode("utf-16")
        name = "unknown_unicode_filename"

    return name, rec


def get_pyc_header(package: bytes, toc: dict[str, dict[str, Any]]) -> Optional[bytes]:
    """Examine the included struct module to get a valid .pyc to use with extracted scripts.

    :param package: The package that contains all the files
    :param toc: The toc for the compressed files in the package
    :return: An 8, 12, or 16 byte .pyc header from struct.pyc if it is in the archive, None otherwise
    """
    header = None

    # get header from struct if it exists
    if "struct" in toc:
        decompressed = decompress_file(package, toc["struct"])

        header_size = get_header_length(decompressed)
        if header_size == -1:
            return

        header = decompressed[:header_size]

    # search all the "m" types for a header
    else:
        for filename in toc.keys():
            if toc[filename]["entry_type"] == "m":
                # get compressed file
                decompressed = decompress_file(package, toc[filename])

                header_size = get_header_length(decompressed)
                if header_size == -1:
                    return

                header = decompressed[:header_size]

    header = header.replace(b"pyi0", b"\x00\x00\x00\x00")
    return header


def get_compile_time(pyc_header: bytes) -> tuple[Optional[int], Optional[str]]:
    """Determine the compile time of a pyc that didn't have this information scrubbed.

    :param pyc_header: A pyc header
    :return: Tuple of unix time and GMT time string if timestamp exists and is non-zero,
    None otherwise
    """
    # if header length is 16, timestamp @ 8-12
    # if header length is 12, timestamp @ 4-8
    # if header length is 8, timestamp @ 4-8

    if len(pyc_header) == 16:
        start = 8
        end = 12
    elif len(pyc_header) == 12 or len(pyc_header) == 8:
        start = 4
        end = 8
    else:
        return None, None

    unix_time = struct.unpack("<i", pyc_header[start:end])[0]
    if unix_time > 0:
        # time value wasn't cleared, or replaced with pyi0
        gmt_time = time.ctime(unix_time)

        return unix_time, gmt_time
    return None, None


def get_header_length(pyc: bytes) -> int:
    """Determine length of the pyc header by inspecting the first few bytes.

    :param pyc: Compiled python code with a header
    :return: Length of header, -ve if unknown/invalid.
    """
    # checking from the later bytes first, just in case we had a source size that
    # coincidentally matches the first dword of the compiled code
    # if dword @16 is 0xE3 -> 16 byte header
    # if dword @12 is 0xE3 -> 12 byte header
    # if dword @12 is 0x63 -> 12 byte header
    # if dword @8 is 0x63 -> 8 byte header

    # unpack 5 32 bit ints from the header and test it
    values = struct.unpack("<iiiii", pyc[:20])

    # find first instance of long code, if any
    if values[4] == 0xE3:
        # if dword @16 is 0xE3 -> 16 byte header
        return 16

    if values[3] == 0xE3:
        # if dword @12 is 0xE3 -> 12 byte header
        return 12

    if values[3] == 0x63:
        # if dword @12 is 0x63 -> 12 byte header
        return 12

    if values[2] == 0x63:
        # if dword @8 is 0x63 -> 8 byte header
        return 8

    if values[1] == 0x63:
        # if dword @8 is 0x63 -> 8 byte header
        return 8

    # nothing matched, will have to dump out a pyc with no header
    return -1


def get_scripts(package: bytes, toc: dict) -> list:
    """Get all the script files from the package.

    :param package: PyInstaller package blob
    :param toc: Table of contents for the package
    :return: List of tuples, each containing the filename and file contents
    """
    scripts = []
    for filename in toc.keys():
        # check if type is s
        # also filter out additional filenames from pyinstaller
        if (
            toc[filename]["entry_type"] == "s"
            and not filename.startswith("pyi")
            and not filename.startswith("_pyi")
            and not filename.startswith("_")
        ):
            # found a script
            script = decompress_file(package, toc[filename])
            scripts.append((filename, script))

    return scripts


def decompress_file(package: bytes, record: dict[str, Any]) -> bytes:
    """Decompresses a zlib compressed file from the installer archive.

    :param package: package sesction from the installer file
    :param record: A dict from the table of contents for the file to decompress
    :return: The decompressed file contents, None otherwise
    """
    # get compressed file
    compressed_file = package[record["offset"] : record["offset"] + record["compressed_size"]]
    # python 3.x doesn't need to specify level.
    decompressed = zlib.decompress(compressed_file)
    return decompressed


def get_pyz_contents(package: bytes, toc: dict) -> list[tuple[str, bytes]]:
    """Look for any .pyz files in the archive and returns a list of their contents.

    :param package: The package from the PyInstaller file
    :param toc: Table of contents list parsed from file
    :return: A list of the contents of .pyz files, possibly empty if none were found
    """
    # I'm fairly certain that there's only 1 .pyz per archive, but this ensures that we get
    # any other ones if they exist.
    pyzs = []

    for filename in toc.keys():
        if filename.lower().endswith(".pyz"):
            record = toc[filename]
            archive = package[record["offset"] : record["offset"] + record["compressed_size"]]
            pyzs.append((filename, archive))

    return pyzs


def write_to_disk(filename: str, file_contents: bytes) -> None:
    """Write the given file contents to the specified path."""
    with open(filename, "wb") as z:
        z.write(file_contents)


def main():
    """Unpack the supplied file arg from the command-line."""
    if len(sys.argv) != 2:
        print("No input file specified!")
        sys.exit(1)

    # check that file is a file?
    if os.path.isfile(sys.argv[1]) is not True:
        print("[-] {} is not a file!".format(sys.argv[1]))
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        content = f.read()

    try:
        print("[+] Unpacking {}".format(sys.argv[1]))
        r = process_pyinstaller(content)

        for key in r.keys():
            if key == "scripts":
                # iterate through extracted scripts list
                for script_info in r["scripts"]:
                    fname = script_info[0]
                    scr = script_info[1]

                    print(
                        "[+] Writing {} ({})".format(
                            fname, hashlib.md5(scr).hexdigest()  # noqa: S303 # nosec B303 B324
                        )
                    )
                    write_to_disk(fname, scr)

            elif key.lower().endswith(".pyz"):
                print(
                    "[+] Writing {} ({})".format(
                        key, hashlib.md5(r[key][0]).hexdigest()  # noqa: S303 # nosec B303 B324
                    )
                )
                write_to_disk(key, r[key][0])

                # write import lists
                short = "# Standard Libraries\n"
                for lib in r[key][1]["standard"]:
                    short += "{}\n".format(lib)
                short += "\n# External Libraries\n"
                for lib in r[key][1]["external"]:
                    short += "{}\n".format(lib)
                fn = key + "_short"
                print("[+] Writing short imports to {}".format(fn))
                with open(fn, "w") as f:
                    f.write(short)

                long = "# Standard Libraries\n"
                for lib in r[key][2]["standard"]:
                    long += "{}\n".format(lib)
                long += "\n# External Libraries\n"
                for lib in r[key][2]["external"]:
                    long += "{}\n".format(lib)
                fn = key + "_long"
                print("[+] Writing long imports to {}".format(fn))
                with open(fn, "w") as f:
                    f.write(long)

            else:
                print("[=] Metadata: {} = {}".format(key, r[key]))

    except NoPackage:
        print("[-] No PyInstaller package found")
        sys.exit(1)
    except InvalidFile:
        print("[-] {} is not a PyInstaller file".format(sys.argv[1]))
        sys.exit(1)
    except UnsupportedFile as e:
        print("[-] Unsupported file format: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
