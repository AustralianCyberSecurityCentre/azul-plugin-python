"""Build and compile pycdc from Github."""

import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

REPO = "https://github.com/zrax/pycdc.git"
COMMIT = "b4289760970dbc399684f1e155ec6d1ea1cc787e"


class CustomBuildHook(BuildHookInterface):
    """Build hook for running actions at build time."""

    def initialize(self, version, build_data):
        """Downloads, builds, and compiles pycdc for use in plugin."""
        root = Path(self.root)
        source = root / "_pycdc" / "source"
        pycdc_build = root / ".venv" / "bin" / "pycdc"

        # download/clone the repo
        if not source.is_dir():
            source.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", REPO, str(source)], check=True)  # noqa: S603, S607
            subprocess.run(["git", "-C", str(source), "checkout", COMMIT], check=True)  # noqa: S603, S607

        # compile, cmake returning non-0 in testing while succeeding
        subprocess.run(["cmake", "."], cwd=source, check=False)  # noqa: S607
        subprocess.run(["make"], cwd=source, check=True)  # noqa: S607

        # since cmake is unreliable for checking output
        if not pycdc_build.is_file():
            raise Exception("No compiled pycdc found")

        shutil.move(pycdc_build, (root / "pycdc"))
