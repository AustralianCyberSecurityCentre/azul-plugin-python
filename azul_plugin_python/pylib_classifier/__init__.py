"""Categorise and analyse python library paths.

The PyLibClassifier class takes a list of files or file paths that correspond
to Python libraries, such as those found within a `py2exe` or `PyInstaller`
archive.  Those paths are analysed and categorised.

It is primarily intended to be used from the `py2exe-unpacker` and
`pyinstaller-unpacker` utilities as a way to categorise the packages required
by the python package into less interesting (standard Python library) and more
interesting (third party libraries, possibly related to the main package).


## Note

PyLibClassifier relies upon the `isort` package to classify Python packages.
This approach is far from flawless.

Additional, known standard library files that were miscategorised have been
hardcoded into `KNOWN_STDLIB`, which can be updated going forward.
"""
