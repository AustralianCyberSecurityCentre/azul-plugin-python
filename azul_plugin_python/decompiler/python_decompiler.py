"""Wraps uncompyle6 command-line tool to provide a simple decompiler library."""

import hashlib
import os
import re
import sys
import tempfile
import traceback
from datetime import datetime
from io import StringIO

import pytz
import xdis
from tzlocal import get_localzone
from uncompyle6.main import main


def _write(filename, content):
    """Write decompiled source to a file.

    :param content: The decompiled source code
    :param filename: The name of the destination file
    """
    with open(filename, "wb") as f:
        f.write(content)


def _ts_to_dt(ts):
    """Convert timestamp to datetime object.

    Handles conversion from localtime to UTC.
    :param ts: ISO8601 timestamp
    :return: naive datetime object
    """
    tz = get_localzone()
    local = datetime.fromisoformat(ts).astimezone(tz)
    return local.astimezone(pytz.utc).replace(tzinfo=None)


def decompile_file(file_path: str):
    """Decompile the bytecode and return source and some metadata.

    :param file_path: path to the python bytecode
    :return: dict containing decompiled source and metadata
    """
    so = StringIO()
    se = StringIO()
    created_sym_link = False
    try:
        # capture library's stdout/stderr
        sys.stdout = so
        sys.stderr = se

        # write content to tmp
        # file needs a .pyc extension for uncompyle6
        if not file_path.endswith(".pyc"):
            os.link(file_path, file_path + ".pyc")
            file_path += ".pyc"
            created_sym_link = True
        main(
            os.path.dirname(file_path),
            None,
            compiled_files=[os.path.basename(file_path)],
            source_files=[],
            outfile=None,
        )
    except Exception as ex:
        traceback.print_exception(type(ex), ex, ex.__traceback__)
    finally:
        # restore filehandles
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        if created_sym_link:
            os.remove(file_path)

    results = {}

    # unpack output from decompilation
    if len(so.getvalue()) > 1:
        results = extract_metadata(so.getvalue().encode("utf-8") + se.getvalue().encode("utf-8"))
    else:
        results["error_type"] = "Input"

    # store error
    if len(se.getvalue()):
        results["error_msg"] = se.getvalue()

        # Input had bad magic
        if "Unknown magic number" in se.getvalue():
            results["error_type"] = "Input"
        elif "error_type" not in results:
            results["error_type"] = "Decompile"
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


def extract_metadata(output):
    """Unpacks metadata from header at start of uncompyle output.

    :param output: stdout and stderr concatenated from running uncompyle6
    :return: a dict of results with metadat extracted
    """
    lines = output.split(b"\n")
    results = {}

    # to avoid processing all the source, only check the head for metadata
    if len(lines) > 10:
        head = lines[:10]
    else:
        head = lines

    for line in head:
        # new uncompyle output seems to go 3 decimal versions.. only take first two as used as float later
        # newer versions of uncompyle changed the output text. Added optional match group to support both.
        matches = re.search(rb"^# Python bytecode(?: version base) (.\..)(\..)? \((.+)\)$", line)
        if matches is not None:
            # got a match, should have three groups?
            results["version"] = float(matches.group(1))
            results["magic"] = int(matches.group(3))

        matches = re.search(b"^# Embedded file name: (.+)$", line)
        if matches is not None:
            filepath = matches.group(1)

            if b"\\" in filepath or b"/" in filepath:
                results["path"] = filepath.decode("utf-8")

                # get just the filename
                results["filename"] = filepath.replace(b"\\", b"/").split(b"/")[-1].decode("utf-8")
            else:
                results["filename"] = filepath.decode("utf-8")

        matches = re.search(b"^# Compiled at: (.+)$", line)
        if matches is not None:
            # timestamp
            results["timestamp"] = _ts_to_dt(matches.group(1).decode("utf-8"))

    # strip changing temp path from file
    regex = re.compile(b"# okay decompiling .+\\.pyc\n")
    output = regex.sub(b"# okay decompiling\n", output)

    regex = re.compile(b"# file .+\\.pyc\n")
    output = regex.sub(b"", output)

    # dump all output into source
    results["source"] = output

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
            filehash = hashlib.md5(content).hexdigest()  # noqa: S303 # nosec B303 B324
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
