# Azul Plugin Python Decompiler

Python bytecode decompiler for Azul 3.

Decompiles python code up to Python version 3.9

## Development Installation

To install azul-plugin-python-decompiler for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
azul-plugin-python-decompiler malware.file
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
azul-plugin-python-decompiler --server http://azul-dispatcher.localnet/
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
