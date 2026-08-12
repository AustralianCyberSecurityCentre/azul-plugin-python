# Azul Plugin Python Decompiler

Python bytecode decompiler for Azul 3.

Decompiles python code up to Python version 3.12

## Development Installation

To install azul-plugin-python for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
azul-plugin-python malware.file
```

Example Output:

```
----- PythonDecompiler results -----
OK

Output features:
  python_compile_time: 2018-02-25 23:07:10
                  tag: python_bytecode
       python_version: 2.7

Feature key:
  python_compile_time:  Python bytecode compile time
  python_version:  Python version compiled for
  tag:  Any informational label about the sample

Generated child entities (1):
  {'action': 'decompiled'} <binary: 9c4ac3ea5bf4598938b60d079b241152976dde7463f864228baa3940c9556d7b>
    content: 9053 bytes
```

Automated usage in system:

```bash
azul-plugin-python --server http://azul-dispatcher.localnet/
```

## Issues

- Attempts are made to normalise the `pycdc` output to prevent output hash
  mismatches but they may change on minor updates. This will break tests.

### Example

    python_decompiler samples/netflix.cpython-312.pyc

Yields:

    Magic number recognised - Python 3.12.0rc2
    Decompiling...
    6781 bytes written to netflix.py (78d48f1eb0a6f8bb3cc66d3b94d8d50e)
    magic: 3531
    filesize: 6119
    version: 3.12
    path: netflix.py
    filename: netflix.py
    timestamp: 2026-08-12T03:53:40
    partial_decompile: True

### Partial decompilation

In cases where `pycdc` may not be able to completely decompile some Python bytecode files. In those
cases `python_decompiler` will return as much of the original source as `pycdc` could decompile.
This is indicated by the flag `partial_decompilation`, and a comment inline that notify the user
that the decompilation could not be completed.

```python
...
def sha256_of_file(path = None):
Unsupported opcode: MAKE_CELL (225)
    '''Return the SHA-256 hex digest of a file.'''
    pass
# WARNING: Decompyle incomplete
...
```


### PyInstaller

Extracts Python bytecode and libraries from PyInstaller executables. Python bytecode may be decompilable with existing Python decompiler (pycdc).

Currently configured to process:

- Win32 EXE
- ELF
- Mach-O

Example Output:

```
----- AzulPluginPython-unpacker results -----
COMPLETED

events (3)

event for 12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af:None
  {}
  output features:
    pyinstaller_build_platform: Windows
                python_library: __future__
                                _compat_pickle
                                _compression
                                _py_abc
                                _pydatetime
                                _pydecimal
                                _strptime
                                _threading_local
                                argparse
                                ast
                                base64
                                bisect
                                bz2
                                calendar
                                code
                                codeop
                                contextlib
                                contextvars
                                copy
                                csv
                                ctypes
                                dataclasses
                                datetime
                                decimal
                                dis
                                email
                                fnmatch
                                fractions
                                getopt
                                gettext
                                gzip
                                hashlib
                                hmac
                                http
                                importlib
                                inspect
                                ipaddress
                                json
                                logging
                                lzma
                                mimetypes
                                numbers
                                opcode
                                pathlib
                                pickle
                                pprint
                                py_compile
                                pyaes
                                queue
                                quopri
                                random
                                selectors
                                shutil
                                signal
                                socket
                                sqlite3
                                ssl
                                statistics
                                string
                                stringprep
                                subprocess
                                tarfile
                                tempfile
                                textwrap
                                threading
                                token
                                tokenize
                                tracemalloc
                                typing
                                urllib
                                urllib3
                                zipfile
                python_version: Python 3.12

event for f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4:None
  {'action': 'unpacked_pyinstaller'}
  child of 12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af
  output data streams (1):
    1470 bytes - EventData(hash='f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4', label='content')
  output features:
    filename: unknown_unicode_filename.pyc

event for 95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995:None
  {'action': 'unpacked_pyinstaller'}
  child of 12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af
  output data streams (1):
    1616841 bytes - EventData(hash='95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995', label='content')
  output features:
    filename: PYZ-00.pyz

Feature key:
  filename:  Original script filename
  pyinstaller_build_platform:  Platform used to build PyInstaller archive
  python_library:  Python library package within this archive
  python_version:  Python version of the byte code
```

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the pyproject.toml and debian.txt file.

Version pinning is achieved using the `uv.lock` file.
Because the `uv.lock` file is configured to use a private UV registry, external developers using UV will need to delete the existing `uv.lock` file and update the project configuration to point to the publicly available PyPI registry instead.

To add new dependencies it's recommended to use uv with the command `uv add <new-package>`
    or for a dev package `uv add --dev <new-dev-package>`

The tool used for linting and managing styling is `ruff` and it is configured via `pyproject.toml`

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.