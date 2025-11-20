"""Categories Python libraries between standard library, first and third party libraries.

Intended use is to take a list of paths to .pyc files included with a py2exe or PyInstaller program
and provide a subset that likely includes third party libraries
"""

from isort import SortImports

HEADER = "## "

STDLIB = "Standard Library"
FUTURE = "Future Libraries"
FIRSTPARTY = "Suspected First Party Libraries"
THIRDPARTY = "Suspected Third Party Libraries"
LOCAL = "Suspected Local Folder Libraries"

import_keys = ["future", "standard", "first", "third", "local"]
label_keys = [FUTURE, STDLIB, FIRSTPARTY, THIRDPARTY, LOCAL]
trans_keys = dict(zip(label_keys, import_keys))

# list of standard library files that isort doesn't identify
# add entries to this list when things that are obviously part of the std lib get lost
KNOWN_STDLIB = [
    "_abcoll",
    "_LWPCookieJar",
    "_MozillaCookieJar",
    "repr",
    "sre",
    "xmllib",
    "os2emxpath",
    "macurl2path",
    "__main__",
]


class PyLibClassifier:
    """Classifies Python files into libraries, using isort for a rough categorisation."""

    def __init__(self, files, filehash=""):
        """Create a classifier for the list of python file names."""
        self.filehash = filehash

        self.short_report = ""
        self.long_report = ""

        self.short_imports = {"future": [], "standard": [], "first": [], "third": [], "local": []}
        self.long_imports = {"future": [], "standard": [], "first": [], "third": [], "local": []}

        self.all_files = []
        self.packages = []

        for filename in files:
            if "/" in filename:
                filename = filename.replace("/", ".")
            self.all_files.append(filename)
            fn = filename.split(".")[0]
            if fn not in self.packages:
                # unique package names
                self.packages.append(fn)

        self._build_reports()
        self._parse_reports()

    def _build_reports(self):
        """Build reports on the libraries observed within some archive."""
        short_imports = ""
        for i in self.packages:
            short_imports += "import {}\n".format(i)

        report = SortImports(
            file_contents=short_imports,
            import_heading_stdlib=STDLIB,
            import_heading_future=FUTURE,
            import_heading_firstparty=FIRSTPARTY,
            import_heading_thirdparty=THIRDPARTY,
            import_heading_localfolder=LOCAL,
            known_standard_library=KNOWN_STDLIB,
        ).output

        # remove import statements
        self.short_report = "# Used Imports (Short) - {}\n\n".format(self.filehash) + report.replace(
            "\nimport ", "\n"
        ).replace("# ", HEADER)

        long_imports = ""
        for i in self.all_files:
            long_imports += "import {}\n".format(i)

        report = SortImports(
            file_contents=long_imports,
            import_heading_stdlib=STDLIB,
            import_heading_future=FUTURE,
            import_heading_firstparty=FIRSTPARTY,
            import_heading_thirdparty=THIRDPARTY,
            import_heading_localfolder=LOCAL,
            known_standard_library=KNOWN_STDLIB,
        ).output

        # remove import statements
        self.long_report = "# Used Imports (Long) - {}\n\n".format(self.filehash) + report.replace(
            "\nimport ", "\n"
        ).replace("# ", HEADER)

    def _parse_reports(self):
        """Parse reports of imports that were created."""
        for short in self.short_report.split(HEADER):
            entries = short.split("\n")
            if entries[0] in label_keys:
                for libs in entries[1:]:
                    if len(libs) > 0:
                        self.short_imports[trans_keys[entries[0]]].append(libs)
        # combine first and third party into external
        self.short_imports["external"] = self.short_imports.pop("first") + self.short_imports.pop("third")
        self.short_imports["standard"] += self.short_imports.pop("future")
        self.short_imports["external"] += self.short_imports.pop("local")
        self.short_imports["standard"].sort()
        self.short_imports["external"].sort()

        for long in self.long_report.split(HEADER):
            entries = long.split("\n")
            if entries[0] in label_keys:
                for libs in entries[1:]:
                    if len(libs) > 0:
                        self.long_imports[trans_keys[entries[0]]].append(libs)
        self.long_imports["external"] = self.long_imports.pop("first") + self.long_imports.pop("third")
        self.long_imports["standard"] += self.long_imports.pop("future")
        self.long_imports["external"] += self.long_imports.pop("local")
        self.long_imports["standard"].sort()
        self.long_imports["external"].sort()

    def get_imports(self):
        """Return a tuple of categoried imports split by short form and long form."""
        return self.short_imports, self.long_imports
