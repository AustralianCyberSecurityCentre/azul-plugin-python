"""Wraps pycdc command-line tool to provide a simple decompiler library."""

import hashlib
import os
import subprocess  # nosec B404
import sys
import tempfile
from datetime import (
    datetime,
)
from typing import TypedDict

import xdis
import xdis.load


class DecompileResults(TypedDict):
    """Decompile results to keep pipeline happy."""

    error_type: str | None
    error_msg: str | None
    source: bytes | None
    magic: int | None
    filesize: int | None
    version: str | None
    path: str | None
    filename: str | None


def _write(filename, content):
    """Write decompiled source to a file.

    :param content: The decompiled source code
    :param filename: The name of the destination file
    """
    with open(filename, "wb") as f:
        f.write(content)


def decompile_file(file_path: str):
    """Decompile the bytecode and return source and some metadata.

    :param file_path: path to the python bytecode
    :return: dict containing decompiled source and metadata
    """
    TEMP_PYC_DIR = "pycdc"
    pycdc_run = subprocess.run(  # noqa: S603
        [TEMP_PYC_DIR, file_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # easier to work with
    stdout = pycdc_run.stdout.decode("utf-8")
    stderr = pycdc_run.stderr.decode("utf-8")

    # Get metadata
    results: DecompileResults = DecompileResults()
    if len(stdout) > 1:
        results = extract_metadata(file_path)
    else:
        results["error_type"] = "Input"

    if "error_type" in results:
        results["error_msg"] = stderr
        return results

    # source needs to be a byte object, not str
    split_src = stdout.split("\n")
    if (
        split_src[0] == "# Source Generated with Decompyle++"
        and split_src[1].startswith("# File: ")
        and split_src[2] == ""
    ):
        # pycdc generates "headers" that contain a filename, this is the parsed file
        # not the pyc original file name. this trims that out of the source if they're both
        # present as it causes inconsistencies with the decompilation hash.
        # splits by newline, trims the first 3 lines off, rebuilds string together again
        results["source"] = b"\n".join(pycdc_run.stdout.split(b"\n")[3:])
    else:
        # backup just in case
        results["source"] = pycdc_run.stdout

    # There is basically always an stderr message, but I think its worth logging it regardless
    # These cases were pulled from reading the source code of pycdc
    results["stdout_msg"] = stdout
    results["stderr_msg"] = stderr

    # Since pycdc isnt correctly checking for broken versions
    # its failing to decomp hello world on 3.13+ without being reported as failure
    # it is outright failing on 3.14
    major, minor = results["version"].split(".")
    if int(major) == 3 and int(minor) > 12:
        results["error_msg"] = stderr
        results["error_type"] = "Unsupported version"

    if "error" in stderr.lower():
        results["error_msg"] = stderr

        if "Bad MAGIC!" in stderr:
            # reproducable
            results["error_type"] = "Magic"

        elif "Unsupported version" in stderr:
            # bugged in pycdc, never fires in testing
            results["error_type"] = "Unsupported version"

        elif "Error decompyling" in stderr:
            # couldn't get it to fire in testing
            results["error_type"] = "Decompilation"

        elif "Error opening file" in stderr:
            # if pycdc cant load the file IO
            results["error_type"] = "Opening file"

        elif "Error loading" in stderr:
            # happens when file is loaded but not a python file
            results["error_type"] = "Loading file"

    # Determine if the decompiler knows it is incomplete
    last_line = stdout.strip().split("\n")[-1]
    results["partial_decompile"] = str(last_line == "# WARNING: Decompyle incomplete")

    return results


def decompile(content: bytes):
    """Decompile the bytecode and return source and some metadata.

    :param content: python bytecode
    :return: dict containing decompiled source and metadata
    """
    with tempfile.NamedTemporaryFile(delete=True, suffix=".pyc") as tmp:
        tmp.write(content)
        tmp.flush()
        return decompile_file(tmp.name)


def extract_metadata(file: str):
    """Unpacks metadata from header of pycdc object.

    :param file: file path that is being handled
    :return: a dict of results with metadata extracted
    """
    # pycdc doesn't output this metadata so i have to use this
    # not getting code as purely for me
    pyc_meta = xdis.load.load_module(file, get_code=False)

    results = {}
    results["magic"] = int(pyc_meta[2])
    results["filesize"] = pyc_meta[5]

    # Python didn't exist in 1970
    if pyc_meta[1] != 0:
        results["timestamp"] = datetime.fromtimestamp(pyc_meta[1])

    # version shenanigans
    # truncate .0 if theres a subversion; from testing this is always the case but just in case
    results["version"] = ".".join(map(str, pyc_meta[0][:2]))

    # extract filename from xdis/pyc file, this requires get_code
    try:
        pyc_meta2 = xdis.load.load_module(file, get_code=True)
        if pyc_meta2[3] is not None:
            if "\\" in file or "/" in file:
                results["path"] = pyc_meta2[3].co_filename
            results["filename"] = pyc_meta2[3].co_filename.replace("\\", "/").split("/")[-1]
    except ImportError:
        ""

    return results


def print_results(res):
    """Print the results dict from decompilation.

    :param res: Dict of results from decompilation
    """
    if not res:
        return

    for key in res.keys():
        if key == "source":
            content = res[key]
            filehash = hashlib.md5(content).hexdigest()  # noqa: S324
            if "filename" in res:
                fn = res["filename"]
            else:
                fn = filehash
            length = len(content)
            _write(fn, content)

            print("{} bytes written to {} ({})".format(length, res["filename"], filehash))
        elif key == "timestamp":
            print("{}: {}".format(key, res[key].isoformat()))
        elif key == "error_msg":
            pass
        else:
            print("{}: {}".format(key, res[key]))


def cmd():
    """Decompile the supplied filepath arg, printing results to stdout."""
    if len(sys.argv) != 2:
        print("No input file specified!")
        sys.exit(1)

    filename = sys.argv[1]

    # check that file is a file?
    if not os.path.isfile(filename):
        print("{} is not a file!".format(filename))
        sys.exit(1)

    print("Decompiling {}".format(filename))

    with open(filename, "rb") as f:
        content = f.read()

    # test file contents for valid python magic bytes
    if content[:4] in xdis.magics.versions.keys():
        # recognised this magic number
        print("Magic number recognised - Python {}".format(xdis.magics.versions[content[:4]]))

        print("Decompiling...")
        dc = decompile(content)
        print_results(dc)

    else:
        print("Unknown magic number!")
        print("Is {} really Python bytecode?".format(filename))


if __name__ == "__main__":
    cmd()
