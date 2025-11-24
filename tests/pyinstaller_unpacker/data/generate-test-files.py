#!/usr/bin/env python
import subprocess

test_script_name = "テスト.py"

test_script = """
import pprint
import PyInstaller
pprint([\"Hello testing world!\",\"日本語\", PyInstaller.loader.pyimod02_archive.CRYPT_BLOCK_SIZE])
"""

with open(test_script_name, "w") as f:
    f.write(test_script)

subprocess.call(["python", "-m", "PyInstaller", "-F", test_script_name, "-n", "py39-pyi36"])
