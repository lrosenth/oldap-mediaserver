"""Release boundaries: checked IDs only, immutable inputs and no implicit push."""

import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mediahelper_images", ROOT / "scripts/mediahelper_images.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
IMAGE = "lrosenth/oldap-mediahelper"
VERSION = "9.8.7"


def accepted(tmp_path):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("fixture")
    receipt = {
        "image": IMAGE,
        "version": VERSION,
        "inputs": release.hashes(context),
        "images": {
            arch: {"reference": f"{IMAGE}:v{VERSION}-{arch}", "id": "sha256:checked"}
            for arch in release.ARCHES
        },
    }
    release.save(tmp_path / "accepted.json", receipt)
    return receipt


def test_existing_tag_blocks_every_push(tmp_path):
    accepted(tmp_path)
    with patch.object(release, "command", return_value="sha256:checked"), patch.object(
        release, "registry", return_value="sha256:existing"
    ), patch.object(release.subprocess, "run") as run:
        with pytest.raises(ValueError, match="existing registry tag"):
            release.publish(tmp_path, IMAGE, VERSION)
        run.assert_not_called()


@pytest.mark.parametrize("failure", ["context", "id", "version", "missing"])
def test_changed_or_missing_acceptance_never_reaches_registry(tmp_path, failure):
    accepted(tmp_path)
    if failure == "context":
        (tmp_path / "context/Dockerfile").write_text("changed")
    if failure == "missing":
        (tmp_path / "accepted.json").unlink()
    with patch.object(
        release,
        "command",
        return_value="changed" if failure == "id" else "sha256:checked",
    ), patch.object(release, "registry") as registry:
        with pytest.raises((ValueError, FileNotFoundError)):
            release.publish(
                tmp_path, IMAGE, "9.8.8" if failure == "version" else VERSION
            )
        registry.assert_not_called()


def test_publish_uses_checked_tags_and_registry_digests_without_build_or_latest(
    tmp_path,
):
    accepted(tmp_path)
    published = set()

    def run(args, **kwargs):
        if args[1] == "push":
            published.add(args[2])
        else:
            assert args[1:4] == ["buildx", "imagetools", "create"]
            published.add(args[5])

    def registry(ref):
        return "sha256:" + "a" * 64 if ref in published else None

    with patch.object(release, "command", return_value="sha256:checked"), patch.object(
        release, "registry", side_effect=registry
    ), patch.object(release.subprocess, "run", side_effect=run) as call:
        release.publish(tmp_path, IMAGE, VERSION)
    commands = [item.args[0] for item in call.call_args_list]
    assert len(commands) == 3
    assert all("build" not in cmd for cmd in commands)
    assert "latest" not in str(commands)
    assert commands[-1][-2:] == [IMAGE + "@sha256:" + "a" * 64] * 2
    assert "index" in json.loads((tmp_path / "published.json").read_text())


def test_registry_failure_never_pushes(tmp_path):
    accepted(tmp_path)
    with patch.object(release, "command", return_value="sha256:checked"), patch.object(
        release, "registry", side_effect=TimeoutError
    ), patch.object(release.subprocess, "run") as run:
        with pytest.raises(TimeoutError):
            release.publish(tmp_path, IMAGE, VERSION)
        run.assert_not_called()


def test_build_checks_both_architectures_and_never_publishes(tmp_path):
    def snapshot(destination):
        destination.mkdir()
        (destination / "Dockerfile").write_text("fixture")

    bundle = tmp_path / "new"
    with patch.object(release, "snapshot", side_effect=snapshot), patch.object(
        release, "command", return_value="sha256:checked"
    ), patch.object(release.subprocess, "run") as run:
        release.build(bundle, IMAGE, VERSION)
    commands = [item.args[0] for item in run.call_args_list]
    assert sum("--load" in cmd for cmd in commands) == 2
    assert sum("--platform" in cmd and "linux/arm64" in cmd for cmd in commands) == 4
    assert "--push" not in str(commands) and "latest" not in str(commands)
    assert (bundle / "accepted.json").exists()
    with pytest.raises(FileExistsError):
        release.build(bundle, IMAGE, VERSION)


def test_failed_build_leaves_no_acceptance(tmp_path):
    with patch.object(release, "snapshot"), patch.object(
        release, "hashes", return_value={}
    ), patch.object(
        release.subprocess,
        "run",
        side_effect=subprocess.CalledProcessError(1, "docker"),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            release.build(tmp_path / "new", IMAGE, VERSION)
    assert not (tmp_path / "new/accepted.json").exists()


def test_snapshot_excludes_local_secrets_and_media_dump(tmp_path):
    release.snapshot(tmp_path / "context")
    files = release.hashes(tmp_path / "context")
    assert "mediaserver/mobile_upload_worker.py" in files
    assert "pyproject.toml" in files and "poetry.lock" in files
    assert not any(".env" in name or name.endswith(".tar.gz") for name in files)


@pytest.mark.parametrize(
    "target,action",
    [
        ("docker-build", "build"),
        ("docker-image", "build"),
        ("docker-publish", "publish"),
        ("docker-push", "publish"),
    ],
)
def test_root_make_routes_without_side_effects(target, action):
    result = subprocess.run(
        ["make", "-n", target, "IMAGE_BUNDLE=/tmp/bundle with spaces"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "mediahelper_images.py " + action in result.stdout
    assert '"/tmp/bundle with spaces"' in result.stdout
    assert "--push" not in result.stdout and ":latest" not in result.stdout


def test_publish_cli_requires_existing_acceptance(tmp_path):
    import sys

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/mediahelper_images.py"),
            "publish",
            "--bundle",
            str(tmp_path),
            "--version",
            VERSION,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "accepted.json" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "code,error,missing",
    [
        (404, "MANIFEST_UNKNOWN", True),
        (404, "NAME_UNKNOWN", False),
        (403, "DENIED", False),
        (500, "UNKNOWN", False),
    ],
)
def test_registry_only_treats_missing_manifest_as_available(code, error, missing):
    import requests

    token = requests.Response()
    token.status_code = 200
    token._content = b'{"token":"test-token"}'
    response = requests.Response()
    response.status_code = code
    response._content = json.dumps({"errors": [{"code": error}]}).encode()
    with patch.object(release.requests, "get", side_effect=[token, response]):
        if missing:
            assert release.registry(IMAGE + ":v" + VERSION) is None
        else:
            with pytest.raises(requests.HTTPError):
                release.registry(IMAGE + ":v" + VERSION)
