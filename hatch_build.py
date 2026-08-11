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
        stage = root / "_pycdc" / "binaries"

        # download/clone the repo
        if not source.is_dir():
            source.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", REPO, str(source)], check=True)  # noqa: S603, S607
            subprocess.run(["git", "-C", str(source), "checkout", COMMIT], check=True)  # noqa: S603, S607

        # compile, cmake returning non-0 in testing while succeeding
        subprocess.run(["cmake", "."], cwd=source, check=False)  # noqa: S607
        subprocess.run(["make"], cwd=source, check=True)  # noqa: S607

        # since cmake is unreliable for checking output
        if not (source / "pycdc").is_file():
            raise RuntimeError("No compiled pycdc found")

        stage.mkdir(parents=True,exist_ok=True)
        for name in ("pycdc", "pycdas"):
            built = source / name
            if not built.is_file():
                raise RuntimeError(f"{name} not found at {built}")

            shutil.copy2(built, stage / name)
            (stage / name).chmod(0o755)

        build_data["shared_scripts"] = {str(stage.relative_to(root)): ""}
        build_data["pure_python"] = False
        build_data["infer_tag"] = True