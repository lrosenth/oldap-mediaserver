"""Regression tests for production and test deployment safety invariants."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_DIR = REPOSITORY_ROOT / "ansible"


def _dry_run_make(target: str) -> str:
    """Return the command shape emitted by a non-executing Make target."""
    result = subprocess.run(
        ["make", "-n", target],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _inventory_host(host: str) -> dict[str, object]:
    """Return resolved host variables using the deployment's Ansible inventory."""
    if shutil.which("ansible-inventory") is None:
        pytest.skip("ansible-inventory is required for deployment configuration tests")

    with tempfile.TemporaryDirectory(prefix="oldap-media-ansible-") as local_temp:
        environment = os.environ.copy()
        environment["ANSIBLE_LOCAL_TEMP"] = local_temp
        result = subprocess.run(
            ["ansible-inventory", "-i", "inventory.ini", "--host", host],
            cwd=ANSIBLE_DIR,
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    return json.loads(result.stdout)


def test_make_targets_apply_matching_host_expression_and_limit() -> None:
    """Production and test commands must constrain the same group twice."""
    production = _dry_run_make("deploy-production")
    test = _dry_run_make("deploy-test")

    assert "-l mediaserver" in production
    assert "-e target_hosts=mediaserver" in production
    assert "test_mediaserver" not in production

    assert "-l test_mediaserver" in test
    assert "-e target_hosts=test_mediaserver" in test


def test_production_inventory_preserves_public_media_clients() -> None:
    """Production CORS must cover every frontend that reads media directly."""
    host = _inventory_host("dhlab-iii.dhlab.unibas.ch")
    origins = set(str(host["cors_origins"]).split(","))

    assert host["media_domain"] == "media.oldap.org"
    assert host["oldap_api_url"] == "https://api.oldap.org"
    assert origins == {
        "https://app.oldap.org",
        "https://fasnacht.oldap.org",
        "https://fasnacht.digital",
    }


def test_home_inventory_cannot_inherit_production_endpoints() -> None:
    """The home target must keep its own API, domain, CORS, and TLS policy."""
    host = _inventory_host("media.home.org")
    origins = set(str(host["cors_origins"]).split(","))

    assert host["media_domain"] == "media.home.org"
    assert host["oldap_api_url"] == "http://api.home.org"
    assert origins == {
        "https://app.home.org",
        "https://fasnacht.home.org",
        "http://app.home.org",
        "http://fasnacht.home.org",
    }
    assert host["caddy_tls_internal"] is True
