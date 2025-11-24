# Azul Plugin Python Decompiler

Python bytecode decompiler for Azul 3.

Decompiles python code up to Python version 3.9

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

- Attempts are made to normalise the `uncompyle6` output to prevent output hash
  mismatches but they may change on minor updates. This will break tests.

## Why wrap `uncompyle6`

The two main advantages that `python_decompiler` provides over using `uncompyle6` are

- It allows in memory handling of decompilation, with no need to read or write temporary files
- It is easier to call from other scripts

### Example

    python_decompiler samples/NetflixChecker.pyc

Yields:

    Decompiling samples/NetflixChecker.pyc
    Magic number recognised - Python 3.7.0
    version: 3.7
    magic: 3394
    filename: NetflixChecker.py
    15009 bytes written to NetflixChecker.py (2cd1471c3db139374f06ffdf35af0c35)

### Partial decompilation

In cases where `uncomplye6` may not be able to completely decompile some Python bytecode files. In those
cases `python_decompiler` will return as much of the original source as `uncompyle6` could decompile.

    Decompiling samples/nanobomber.pyc
    Magic number recognised - Python 3.8.0rc1+
    Decompiling...
    magic: 3344
    version: 3.8
    filename: nanobomber.py
    15036 bytes written to nanobomber.py (c61a4738b79a5de5f6685257b10ba85b)
    error_type: Decompile

nanobomber.pyc could not be completely decompiled, examining the tail of the output file (nanobomber.py)
shows comments `uncompyle6` has appended comments to the source it was able to decompile:

    # NOTE: have internal decompilation grammar errors.
    # Use -t option to show full context.
    # not in loop:
    #       break (2)
    #      0.  L. 340      3492  POP_EXCEPT
    #      1.          3494_3496  BREAK_LOOP         3508  'to 3508'

    # file /tmp/tmpcdnm37ry.pyc
    # Deparsing hit an internal grammar-rule bug


### PyInstaller

Extracts Python bytecode and libraries from PyInstaller executables. Python bytecode may be decompilable with existing Python decompilers (uncompyle6 or decompyle3).

Currently configured to process:

- Win32 EXE
- ELF
- Mach-O

Example Output:

```
----- AzulPluginUnbox-pyinstaller results -----
COMPLETED

events (3)

event for binary:12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af:None
  {}
  output features:
                     box_count: 2
                  box_filepath: PYZ-00.pyz
                                unknown_unicode_filename.pyc
                      box_type: pyinstaller
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

event for binary:95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995:None
  {'action': 'unpacked'}
  child of binary:12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af
  output data streams (1):
    1616841 bytes - EventData(hash='95d840c8a9e9b100e6bfbfabb33875c2fb66f4d3e6a80a014a36c47a9afad995', label='content')
  output features:
    filename: PYZ-00.pyz

event for binary:f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4:None
  {'action': 'unpacked'}
  child of binary:12a04feb4e388ad3a3e16ce8f1798dd4927af2828c2a1ae1fcbd8acf77e4e4af
  output data streams (1):
    1470 bytes - EventData(hash='f4aa6bd7b64c46ace259fae65d1f24ea2f47f380f67b2394a53ed84defcdc6b4', label='content')
  output features:
    filename: unknown_unicode_filename.pyc

Feature key:
  box_count:  Number of items found in the box
  box_filepath:  This entity contains this filepath
  box_type:  The binary is of this box type
  filename:  The name of the file in its parent archive
  pyinstaller_build_platform:  Platform used to build PyInstaller archive
  python_library:  Python library package within this archive
  python_version:  Python version used to build archive
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

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

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
