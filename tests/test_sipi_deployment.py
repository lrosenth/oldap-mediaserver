"""Render both IIIF backends and check their storage, policy and routing contracts."""

import json
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def render_compose(backend="sipi", policy=""):
    """Render public deployment defaults with synthetic tags and no credentials."""
    values = yaml.safe_load((ROOT / "ansible/group_vars/all.yml").read_text())
    values.update(
        caddy_data_dir="/opt/oldap-mediaserver/caddy-data",
        caddy_config_dir="/opt/oldap-mediaserver/caddy-config",
        iiif_backend=backend,
        sipi_image="example/sipi:1.2.3",
        sipi_public_origin="https://media.example.org",
        sipi_preflight_source=policy,
        oldap_mediahelper_tag="v1.2.3",
        oldap_imageserver_tag="v0.2.1",
    )
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = bool
    template = (ROOT / "ansible/templates/docker-compose.yml.j2").read_text()
    return yaml.safe_load(env.from_string(template).render(**values))


def test_sipi_deployment_has_readonly_media_and_separate_persistent_cache():
    service = render_compose()["services"]["imageserver"]
    assert service["image"] == "example/sipi:1.2.3"
    assert service["volumes"] == [
        "/data/media:/data/images:ro",
        "sipi_cache:/var/cache/sipi",
    ]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "ports" not in service
    assert service["expose"] == ["8182"]
    env = service["environment"]
    assert env["SIPI_PUBLIC_BASE_URL"] == "https://media.example.org"
    assert env["OLDAP_SIPI_ANONYMOUS"] == "true"
    assert env["SIPI_PREFLIGHT_CONFIG_ANONYMOUS_PERMISSION_TTL"] == "600"
    assert env["SIPI_JPEG_SAMPLING"] == "4:4:4"
    assert env["SIPI_CORS_ORIGINS"] == "*"
    assert env["SIPI_CORS_CREDENTIALS"] == "false"
    assert service["env_file"] == ["./mediaserver.env"]


def test_custom_policy_is_mounted_readonly_at_the_configured_location():
    service = render_compose(policy="/controller/policy.lua")["services"]["imageserver"]
    assert service["environment"]["SIPI_PREFLIGHT_SCRIPT"] == "/etc/sipi/preflight.lua"
    assert "./sipi-preflight.lua:/etc/sipi/preflight.lua:ro" in service["volumes"]


def test_cantaloupe_rollback_does_not_inherit_sipi_entrypoint_or_restrictions():
    services = render_compose("cantaloupe")["services"]
    service = services["imageserver"]
    assert service["image"] == "lrosenth/oldap-imageserver:v0.2.1"
    assert service["volumes"] == ["/data/media:/data/images"]
    for key in ("entrypoint", "read_only", "cap_drop", "environment", "working_dir"):
        assert key not in service
    # Selecting a backend cannot alter uploads, private workers, or proxy routes.
    sipi = render_compose()["services"]
    assert {k: v for k, v in services.items() if k != "imageserver"} == {
        k: v for k, v in sipi.items() if k != "imageserver"
    }


def test_local_compose_matches_the_deployed_policy_defaults():
    service = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"][
        "imageserver"
    ]
    assert service["image"] == "${SIPI_IMAGE:-lrosenth/sipi-2:0.1.0}"
    assert (
        service["entrypoint"]
        == render_compose()["services"]["imageserver"]["entrypoint"]
    )
    assert "${MEDIA_DATA_HOST:-./data}:/data/images:ro" in service["volumes"]
    assert "sipi_cache:/var/cache/sipi" in service["volumes"]


def test_deployment_probe_uses_invalid_token_not_anonymous_api_availability():
    play = yaml.safe_load((ROOT / "ansible/deploy-media.yml").read_text())[0]
    probe = next(
        t
        for t in play["tasks"]
        if t["name"] == "Verify the public IIIF authorization path"
    )
    assert probe["ansible.builtin.uri"]["url"].endswith(
        "?token=invalid-deployment-probe"
    )
    assert "403 if iiif_backend == 'sipi' else 401" in probe["until"]
    policy = next(
        t
        for t in play["tasks"]
        if t["name"] == "Install an optional deployment-specific SIPI policy"
    )
    assert policy["notify"] == "Restart SIPI after policy change"


@pytest.mark.parametrize(
    "target,group", [("deploy-vm", "mediaserver"), ("deploy-home", "test_mediaserver")]
)
def test_familiar_deployment_aliases_keep_target_and_image_selection(target, group):
    result = subprocess.run(
        ["make", "-n", target], cwd=ROOT, capture_output=True, text=True, check=True
    )
    assert f"-l {group}" in result.stdout
    assert f"-e target_hosts={group}" in result.stdout
    assert '-e sipi_image="lrosenth/sipi-2:0.1.0"' in result.stdout
    assert '-e iiif_backend="sipi"' in result.stdout
