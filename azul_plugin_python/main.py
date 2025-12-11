"""Decompile and resubmit python bytecode."""

import pathlib
import tempfile
import traceback
from datetime import datetime, timezone

import xdis.magics
from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Feature,
    FeatureType,
    Filepath,
    Job,
    State,
    add_settings,
    cmdline_run,
    settings,
)
from pylingual.decompiler import decompile as pylingual_decompile

from azul_plugin_python.py2exe_unpacker import (
    Py2ExeUnpacker,
    Py2ExeUnpackError,
)
from azul_plugin_python.pyinstaller_unpacker import pyi

from .decompiler.python_decompiler import decompile_file


class AzulPluginPython(BinaryPlugin):
    """Decompile and resubmit python bytecode."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.12.11"

    DECOMPILE_DATA_TYPES = [
        "python/bytecode",
        "code/python",
    ]
    UNPACKER_DATA_TYPES = [
        # Windows exe
        "executable/windows/pe",
        "executable/windows/pe32",
        "executable/windows/pe64",
        "executable/windows/dos",
        "executable/windows/com",
        # # Potential Windows Exe
        "executable/dll32",
        "executable/pe32",
        # Linux exe
        "executable/linux/elf64",
        "executable/linux/elf32",
        "executable/linux/so64",
        "executable/linux/so32",
        "executable/mach-o",
    ]

    SETTINGS = add_settings(
        # Python bytecode is either data or python x.y byte-compiled
        filter_data_types={"content": list(set(DECOMPILE_DATA_TYPES + UNPACKER_DATA_TYPES))},
        run_timeout=(int, 300),
    )
    # features set on parents and children
    FEATURES = [
        Feature("python_version", "Python version of the byte code", FeatureType.String),
        # Python decompile features
        Feature("python_compile_time", "Python bytecode compile time", FeatureType.Datetime),
        Feature("filename", "Original script filename", FeatureType.Filepath),
        Feature("tag", "Any informational label about the sample", FeatureType.String),
        # unpackers
        Feature(name="build_time", desc="Build time of the executable or archive", type=FeatureType.Datetime),
        Feature(name="python_library", desc="Python library package within this archive", type=FeatureType.String),
        # py installer
        Feature(
            name="pyinstaller_build_platform",
            desc="Platform used to build PyInstaller archive",
            type=FeatureType.String,
        ),
    ]

    def __init__(self, config: settings.Settings | dict = None):
        super().__init__(config)

        self.register_multiplugin("decompiler", None, self.execute_decompiler)
        self.register_multiplugin("pylingual", None, self.execute_pylingual)
        self.register_multiplugin("unpacker", None, self.execute_unpacker)

    def execute(self, job: Job):
        """Accept anything that passes the initial filters."""
        return

    def execute_pylingual(self, job: Job):
        """Decompile provided bytecode with pylingual."""
        if job.event.entity.file_format not in self.DECOMPILE_DATA_TYPES:
            return State(
                label=State.Label.OPT_OUT,
                failure_name="not_byte_code",
                message="file is not python bytecode",
            )
        with tempfile.NamedTemporaryFile() as decompiled_py:
            try:
                pylingual_decompile(
                    pyc=pathlib.Path(job.get_data().get_filepath()), save_to=pathlib.Path(decompiled_py.name), top_k=10
                )
            except Exception as e:
                traceback.print_exc()
                print(e)
                return State(
                    label=State.Label.OPT_OUT,
                    failure_name="not_pylingual_compatible",
                    message="file cannot be decompiled by pylingual,"
                    + " either the python version is too old or it's not bytecode",
                )
            decompiled_py.seek(0)
            self.add_data_file(DataLabel.TEXT, {}, decompiled_py)

    def execute_decompiler(self, job: Job):
        """Decompile the provided python bytecode."""
        if job.event.entity.file_format not in self.DECOMPILE_DATA_TYPES:
            return State(
                label=State.Label.OPT_OUT,
                failure_name="not_byte_code",
                message="file is not python bytecode",
            )
        child_features = {}
        parent_features = {}
        data = job.get_data()
        # test file contents for known python magic bytes
        if data.read(4) not in xdis.magics.versions.keys():
            # unknown magic or not a .pyc file, so skip processing
            return State(
                label=State.Label.OPT_OUT,
                failure_name="unknown_python_magic_bytes",
                message="python magic bytes unknown or not a pyc file",
            )

        # rewind and get everything
        data.seek(0)
        file_path = data.get_filepath()

        dc = decompile_file(file_path)

        # check decompilation results
        if "error_type" in dc and "error_msg" in dc and "Unsupported Python version" in dc.get("error_msg", ""):
            # FUTURE completed-empty
            # decompilation returned an unsupported error only returned an error, give up
            return State(
                State.Label.OPT_OUT, failure_name="unsupported_python_version", message=dc.get("error_msg", "")
            )

        if dc is None or (len(dc.keys()) == 2 and "error_type" in dc and "error_msg" in dc):
            # decompilation only returned an error, give up
            return State(State.Label.ERROR_EXCEPTION, message="decompilation failed")

        # got some decompilation results, so parent must be python bytecode
        parent_features["tag"] = ["python_bytecode"]

        # set this file's python version
        if "version" in dc:
            # set python version on the parent binary
            # we don't also set it on the child, since it shouldn't be a child feature
            # the feature value is formatted to match other plugins that set the same feature
            parent_features["python_version"] = f'Python {dc["version"]}'

        if "timestamp" in dc:
            # set compile time on this binary
            # normalise on whatever lief uses for binaries
            parent_features["python_compile_time"] = dc["timestamp"]

        if "filename" in dc:
            # set filename on child
            child_features["filename"] = Filepath(dc["filename"])

        if "path" in dc:
            # set path on child, overwriting previously set name if a full path exists
            child_features["filename"] = Filepath(dc["path"])

        # if there's a child, set it up correctly
        if "error_type" not in dc and "error_msg" not in dc and "source" in dc:
            # add the decompiled output as a text stream on the parent
            # leave comments in, for now, as add context but might cause some stream variability
            self.add_data(label=DataLabel.TEXT, data=dc["source"], tags={"language": "python"})

            # also raise as child for downstream processing/correlation
            c = self.add_child_with_data({"action": "decompiled"}, self._clean_decompiled_child(dc["source"]))
            c.add_feature_values("tag", ["python_script", "decompiled_script"])
            c.add_many_feature_values(child_features)

        self.add_many_feature_values(parent_features)

    def _clean_decompiled_child(self, source):
        """Strip comments to normalise child output.

        Source output includes decompilation info including environment details like python
        version used to perform the decompile.
        Some of this metadata will change between deployments/runs resulting in hash changes
        unless stripped.

        :param source: byte string containing decompiled script output.
        :return: byte string with normalised output.
        """
        return b"\n".join((x for x in source.split(b"\n") if not x.startswith(b"#")))

    def execute_pyinstaller(self, raw_content: bytes) -> str | None:
        """Attempt to extract python byte code using pyinstaller."""
        try:
            contents = pyi.process_pyinstaller(raw_content)
        except pyi.NoPackage:
            return "No package found"
        except pyi.InvalidFile:
            return "Invalid file"
        except pyi.UnsupportedFile:
            return "Unsupported file"

        if contents is None:
            return "Unpacking failed to get contents"

        # scripts contains a list of tuples of scripts and their contents
        if "scripts" in contents:
            for script_info in contents["scripts"]:
                child_event = self.add_child_with_data({"action": "unpacked_pyinstaller"}, script_info[1])
                child_event.add_feature_values("filename", script_info[0])
        else:
            return "No scripts were extracted"

        # get pyz archives
        for key, value in contents.items():
            if key.lower().endswith(".pyz"):
                child_event = self.add_child_with_data({"action": "unpacked_pyinstaller"}, value[0])
                child_event.add_feature_values("filename", key)
                # set python libraries
                imports_short = value[1]["standard"] + value[1]["external"]
                # imports_long = value[2]["standard"] + value[2]["external"]
                self.add_feature_values("python_library", set(imports_short))

        py_version: tuple[int, int] = contents.get("python_version")
        if py_version and len(py_version) >= 2:
            self.add_feature_values("python_version", f"Python {py_version[0]}.{py_version[1]}")

        if "compile_time_unix" in contents:
            self.add_feature_values(
                "build_time", datetime.fromtimestamp(contents["compile_time_unix"], tz=timezone.utc)
            )
        self.add_feature_values("pyinstaller_build_platform", contents.get("build_platform"))
        return None

    def execute_py2exe(self, raw_content: bytes) -> str | None:
        """Attempt to extract pyc files the underlying pyc files from an executable."""
        try:
            # unpack everything and store it until extract needs it
            py2exe = Py2ExeUnpacker(raw_content)
            contents = py2exe.get_results()
        except Py2ExeUnpackError as e:
            return f"Extraction error, {e}"

        # check that it worked
        if contents is None:
            return "Py2Exe unpacking failed"

        # scripts contains a list of tuples of scripts and their contents
        if "scripts" in contents:
            for script_name, script_contents in contents["scripts"].items():
                # need to exclude default py2exe scripts by name
                if not (script_name.endswith("\\py2exe\\boot_common.pyc") or script_name.startswith("<")):
                    child_event = self.add_child_with_data({"action": "unpacked_py2exe"}, script_contents)
                    child_event.add_feature_values("filename", script_name)
        else:
            return "No scripts were extracted"

        # get zip archive, if it exists
        for key, value in contents.items():
            if key.lower().endswith(".zip"):
                child_event = self.add_child_with_data({"action": "unpacked_py2exe"}, value)
                child_event.add_feature_values("filename", key)

        if "imports_short" in contents:
            self.add_feature_values(
                "python_library", contents["imports_short"]["standard"] + contents["imports_short"]["external"]
            )

        if "build_time" in contents:
            self.add_feature_values("build_time", datetime.fromtimestamp(contents["build_time"], tz=timezone.utc))

        if py_version := contents.get("python_version"):
            self.add_feature_values("python_version", py_version)

    def execute_unpacker(self, job: Job):
        """Extract the python byte code from a file with py2exe and pyinstaller."""
        if job.event.entity.file_format not in self.UNPACKER_DATA_TYPES:
            return State(
                label=State.Label.OPT_OUT,
                failure_name="not_executable",
                message="file is not an executable",
            )
        print("starting pyinstaller")
        content = job.get_data().read()
        error_message = self.execute_pyinstaller(content)
        print("pyinstaller error is ", error_message)
        # Successful extraction completed so plugin can stop.
        if not error_message:
            return

        print("starting py2exe")
        # Attempt py2exe unpacker as pyinstaller didn't work.
        error_message_py2exe = self.execute_py2exe(content)
        print("py2exe error is ", error_message_py2exe)

        if error_message_py2exe:
            return State(
                label=State.Label.OPT_OUT,
                failure_name="not_python",
                message="executable file has not been compiled by pyinstaller or py2exe",
            )


def main():
    """Run the plugin from the command-line."""
    cmdline_run(plugin=AzulPluginPython)


if __name__ == "__main__":
    main()
