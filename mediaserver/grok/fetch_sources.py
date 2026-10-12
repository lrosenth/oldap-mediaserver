"""Fetch the pinned Grok CLI source and its required submodules for Docker builds.

Archives are checksum-verified before extraction. No compiler, headers or source
are copied to the runtime image; licenses and this source manifest are retained.
"""

import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

SOURCES = (
    (
        ".",
        "GrokImageCompression/grok",
        "v20.4.15",
        "01bb691dd64f1917b0bba867659f2b7e0ae07a856833b81ae8bdb904149d7277",
    ),
    (
        "src/include/CLI11",
        "CLIUtils/CLI11",
        "a41ba814b3202aeb35f6ed36f0fde80402bf85cc",
        "8f6ddb87868fb6b79116551d481506f95dc59447ac18ebfafe8c9b71a87a5a1a",
    ),
    (
        "src/include/spdlog",
        "gabime/spdlog",
        "ce0424bb375805955c0c5482a32ddb821708eb47",
        "6efddb9c922df1fc548a0f3ec067d744103e6a2783d290df1b221f2186041b78",
    ),
    (
        "src/include/taskflow",
        "boxerab/taskflow",
        "8e85ff949e54664efe19b3df0763a6bc24aa421d",
        "a09b3d3742121bb1ba7d3d17aa1ec0bf77ca9c22edd1abcbffe8f75d8c82e4a6",
    ),
    (
        "src/lib/core/highway",
        "google/highway",
        "05230e7c367405e05215d61c1426aea0e3858cec",
        "50bfa634575e0efa85471a3ba96120ea3d0be2a5ffd154dabc465dbedf466142",
    ),
)


def main() -> None:
    """Populate /src and retain upstream license files under /opt/grok/licenses."""
    root = Path("/src")
    licenses = Path("/opt/grok/licenses")
    for relative, repository, revision, digest in SOURCES:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            archive = temporary / "source.tar.gz"
            url = f"https://github.com/{repository}/archive/{revision}.tar.gz"
            urllib.request.urlretrieve(url, archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"Checksum mismatch for {repository}")
            extracted = temporary / "extracted"
            with tarfile.open(archive) as source:
                source.extractall(extracted, filter="data")
            (source_root,) = extracted.iterdir()
            shutil.copytree(source_root, root / relative, dirs_exist_ok=True)
            destination = licenses / repository.split("/")[-1]
            destination.mkdir(parents=True, exist_ok=True)
            for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
                for license_file in source_root.glob(pattern):
                    if license_file.is_file():
                        shutil.copy2(license_file, destination)
    shutil.copy2(__file__, licenses / "fetch_sources.py")


if __name__ == "__main__":
    main()
