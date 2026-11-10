"""Build checked local mediahelper images, then publish those exact IDs separately.

The receipt freezes the allowlisted context and both architecture image IDs.
Publication never builds, replaces existing registry tags, or updates latest.
Use one publisher per version; Docker Hub does not offer conditional tag writes.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import requests

ROOT = Path(__file__).resolve().parents[1]
ARCHES = ("amd64", "arm64")


def command(*args):
    """Run a fixed command, retaining only the expected stdout."""
    return subprocess.check_output(args, text=True).strip()


def save(path, value):
    """Atomically publish a complete receipt only after its checks succeed."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def hashes(context):
    """Identify the exact secret-free build inputs, independently of Git dirtiness."""
    return {
        str(path.relative_to(context)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(context.rglob("*"))
        if path.is_file()
    }


def snapshot(destination):
    """Copy only the existing Dockerfile's explicit allowlist into a new context.

    Reject newly introduced glob/negation rules rather than approximating Docker's
    matching semantics and accidentally admitting local data or credentials.
    """
    ignore = ROOT / "mediaserver/Dockerfile.dockerignore"
    rules = [line.strip() for line in ignore.read_text().splitlines()]
    rules = [line for line in rules if line and not line.startswith("#")]
    if rules[0] != "**":
        raise ValueError("Build context must start with a deny-all rule")
    selected = []
    for rule in rules[1:]:
        if not rule.startswith("!") or any(char in rule[1:] for char in "*?[]!"):
            raise ValueError("Review changed Docker context rules before building")
        relative = Path(rule[1:])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe build input path")
        source = ROOT / relative
        if source.is_symlink():
            raise ValueError("Build input symlinks are not allowed")
        if not rule.endswith("/"):
            if not source.is_file():
                raise ValueError("Missing allowlisted build input: " + str(relative))
            selected.append(relative)
    destination.mkdir(parents=True, exist_ok=False)
    for relative in selected:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


def build(bundle, image, version):
    """Build/load both platforms and write acceptance only after all tests pass."""
    bundle.mkdir(parents=True, exist_ok=False)
    context = bundle / "context"
    snapshot(context)
    inputs = hashes(context)
    receipt = {"image": image, "version": version, "inputs": inputs, "images": {}}
    for arch in ARCHES:
        reference = f"{image}:v{version}-{arch}"
        subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/" + arch,
                "--load",
                "-f",
                str(context / "mediaserver/Dockerfile"),
                "--build-arg",
                "MEDIAHELPER_VERSION=" + version,
                "-t",
                reference,
                str(context),
            ],
            check=True,
        )
        image_id = command(
            "docker", "image", "inspect", "--format", "{{.Id}}", reference
        )
        run = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/" + arch,
            "--entrypoint",
            "python",
            image_id,
        ]
        subprocess.run(run + ["-m", "pip", "check"], check=True)
        subprocess.run(
            run
            + [
                "-c",
                "import derivatives, mobile_upload_worker; "
                "from oldaplib.src.authentication import TokenCodec",
            ],
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check_mobile_shutdown.py"),
                "--image",
                image_id,
                "--platform",
                "linux/" + arch,
            ],
            check=True,
        )
        receipt["images"][arch] = {"reference": reference, "id": image_id}
    if hashes(context) != inputs:
        raise ValueError("Build inputs changed during verification")
    save(bundle / "accepted.json", receipt)
    print("Built and checked both platforms; nothing published.")


def registry(reference):
    """Return a Docker Hub digest; only MANIFEST_UNKNOWN means a new tag is free."""
    repository, tag = reference.split(":", 1)
    response = requests.get(
        "https://auth.docker.io/token",
        params={
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        },
        timeout=30,
    )
    response.raise_for_status()
    response = requests.get(
        f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}",
        headers={
            "Authorization": "Bearer " + response.json()["token"],
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json",
        },
        timeout=30,
    )
    if response.status_code == 404 and any(
        error.get("code") == "MANIFEST_UNKNOWN"
        for error in response.json().get("errors", [])
    ):
        return None
    response.raise_for_status()
    digest = response.headers["Docker-Content-Digest"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Unexpected registry digest")
    return digest


def publish(bundle, image, version):
    """Push only previously accepted IDs, after preflighting every destination."""
    receipt = json.loads((bundle / "accepted.json").read_text())
    if receipt["image"] != image or receipt["version"] != version:
        raise ValueError("Receipt does not match selected image/version")
    if hashes(bundle / "context") != receipt["inputs"] or set(receipt["images"]) != set(
        ARCHES
    ):
        raise ValueError("Incomplete acceptance or modified build context")
    target = f"{image}:v{version}"
    references = [target]
    for arch in ARCHES:
        item = receipt["images"][arch]
        if item["reference"] != f"{target}-{arch}":
            raise ValueError("Unexpected architecture tag")
        if (
            command(
                "docker", "image", "inspect", "--format", "{{.Id}}", item["reference"]
            )
            != item["id"]
        ):
            raise ValueError("Local image changed since acceptance")
        references.append(item["reference"])
    for reference in references:
        if registry(reference) is not None:
            raise ValueError("Refusing existing registry tag: " + reference)
    published = {}
    for arch in ARCHES:
        item = receipt["images"][arch]
        if registry(item["reference"]) is not None:
            raise ValueError("Registry tag appeared during publication")
        # Recheck immediately before pushing; never silently publish a retagged image.
        if (
            command(
                "docker", "image", "inspect", "--format", "{{.Id}}", item["reference"]
            )
            != item["id"]
        ):
            raise ValueError("Local image changed during publication")
        subprocess.run(["docker", "push", item["reference"]], check=True)
        digest = registry(item["reference"])
        if digest is None:
            raise ValueError("Published image is not confirmed by the registry")
        published[arch] = image + "@" + digest
        save(bundle / "published.json", published)
    if registry(target) is not None:
        raise ValueError("Version tag appeared during publication")
    subprocess.run(
        ["docker", "buildx", "imagetools", "create", "-t", target, *published.values()],
        check=True,
    )
    published["index"] = registry(target)
    if published["index"] is None:
        raise ValueError("Published multiarchitecture index is not confirmed")
    save(bundle / "published.json", published)
    print(json.dumps(published, indent=2))


def main():
    """Keep build and publication explicit; reject unsafe tags before any action."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "publish"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--image", default="lrosenth/oldap-mediahelper")
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*/oldap-mediahelper", args.image):
        parser.error("Expected a Docker Hub namespace/oldap-mediahelper repository")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9][a-zA-Z0-9.-]*)?", args.version):
        parser.error("Expected a stable or prerelease Docker-compatible version")
    try:
        {"build": build, "publish": publish}[args.action](
            args.bundle.resolve(), args.image, args.version
        )
    except (ValueError, FileExistsError, FileNotFoundError) as error:
        parser.exit(
            1,
            str(error)
            + "\nUse a new bundle for builds; inspect partial publication before retrying.\n",
        )


if __name__ == "__main__":
    main()
