"""Decompile and resubmit python bytecode."""

from datetime import datetime

import xdis.magics
from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Feature,
    Filepath,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from .python_decompiler import decompile_file


class AzulPluginPythonDecompiler(BinaryPlugin):
    """Decompile and resubmit python bytecode."""

    CONTACT = "ASD's ACSC"
    VERSION = "2024.05.03"
    SETTINGS = add_settings(
        # Python bytecode is either data or python x.y byte-compiled
        filter_data_types={"content": ["python/bytecode", "code/python"]},
        run_timeout=(int, 180),
    )
    # features set on parents and children
    FEATURES = [
        Feature("tag", "Any informational label about the sample", str),
        Feature("python_compile_time", "Python bytecode compile time", datetime),
        Feature("python_version", "Python version compiled for", str),
        Feature("filename", "Original script filename", Filepath),
    ]

    def execute(self, job: Job):
        """Accept all content and opt out if not valid byte code."""
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
            c = self.add_child_with_data({"action": "decompiled"}, self._clean_child(dc["source"]))
            c.add_feature_values("tag", ["python_script", "decompiled_script"])
            c.add_many_feature_values(child_features)

        self.add_many_feature_values(parent_features)

    def _clean_child(self, source):
        """Strip comments to normalise child output.

        Source output includes decompilation info including environment details like python
        version used to perform the decompile.
        Some of this metadata will change between deployments/runs resulting in hash changes
        unless stripped.

        :param source: byte string containing decompiled script output.
        :return: byte string with normalised output.
        """
        return b"\n".join((x for x in source.split(b"\n") if not x.startswith(b"#")))


def main():
    """Run the plugin from the command-line."""
    cmdline_run(plugin=AzulPluginPythonDecompiler)


if __name__ == "__main__":
    main()
