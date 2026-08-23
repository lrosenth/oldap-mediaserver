"""Static safety invariants for the additive mobile-media deployment."""

import json
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"


def test_local_mobile_worker_and_storage_are_privately_bounded() -> None:
    """Only mediahelper and its worker may access durable mobile upload state."""

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    media_volumes = services["mediaserver"]["volumes"]
    worker = services["mobile-media-worker"]

    assert any(volume.endswith(":/data/mobile-uploads") for volume in media_volumes)
    for service_name in ("imageserver", "caddy", "ingest-worker", "export-worker"):
        assert all(
            "/data/mobile-uploads" not in volume
            for volume in services[service_name].get("volumes", [])
        )

    assert worker["profiles"] == ["mobile-media"]
    assert "ports" not in worker and "expose" not in worker
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert worker["security_opt"] == ["no-new-privileges:true"]
    assert worker["cpus"] == 4.0
    assert worker["mem_limit"] == "6g"
    assert worker["memswap_limit"] == "6g"
    assert worker["pids_limit"] == 128
    assert worker["command"] == ["python", "-m", "mobile_upload_worker"]
    assert any(volume.endswith(":/data/images") for volume in worker["volumes"])
    assert any(volume.endswith(":/data/mobile-uploads") for volume in worker["volumes"])

    environment = set(worker["environment"])
    assert environment == {
        "OLDAP_API_URL",
        "OLDAP_JWT_ISSUER",
        "OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET",
        "OLDAP_MOBILE_UPLOAD_ROOT",
        "UPLOADER_IMGDIR",
        "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES",
        "OLDAP_MOBILE_MAX_ORIGINAL_BYTES",
        "OLDAP_MOBILE_CHUNK_BYTES",
        "OLDAP_MOBILE_INACTIVITY_SECONDS",
        "OLDAP_MOBILE_LEASE_SECONDS",
        "OLDAP_MOBILE_MAX_ACTIVE_PER_USER",
        "OLDAP_MOBILE_MAX_ACTIVE_PER_STAGING_AREA",
        "OLDAP_MOBILE_MAX_RESERVED_BYTES_PER_USER",
        "OLDAP_MOBILE_MAX_RESERVED_BYTES_PER_STAGING_AREA",
        "OLDAP_MOBILE_MAX_PROCESSING_JOBS",
    }
    assert (
        not {
            "OLDAP_ACCESS_JWT_SECRET",
            "OLDAP_MEDIA_JWT_SECRET",
            "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
            "OLDAP_IMPORT_SERVICE_JWT_SECRET",
            "OLDAP_IMPORT_RECORDS_JWT_SECRET",
            "OLDAP_EXPORT_SERVICE_JWT_SECRET",
            "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET",
        }
        & environment
    )


def test_mobile_caddy_route_is_additive_bounded_and_non_serving() -> None:
    """Caddy may proxy the exact API but must never serve its private files."""

    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    template = (ROOT / "ansible" / "templates" / "Caddyfile.j2").read_text(
        encoding="utf-8"
    )

    for proxy in (caddyfile, template):
        assert "@upload path /upload /upload/*" in proxy
        assert "@mobile_media path /media/v1 /media/v1/*" in proxy
        assert "@mobile_media_method not method GET POST PATCH DELETE OPTIONS" in proxy
        assert "max_size 5MB" in proxy
        assert "reverse_proxy mediaserver:8000" in proxy
        assert "/internal/mobile-media" not in proxy
    assert "{% if mobile_media_enabled | bool %}" in template

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert all(
        "/data/mobile-uploads" not in volume
        for volume in compose["services"]["caddy"]["volumes"]
    )


def test_ansible_mobile_activation_fails_closed_and_keeps_roots_separate() -> None:
    """Known targets opt in, while missing secrets and unsafe roots stop deployment."""

    defaults = yaml.safe_load(
        (ROOT / "ansible" / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    production = yaml.safe_load(
        (ROOT / "ansible" / "host_vars" / "dhlab-iii.dhlab.unibas.ch.yml").read_text(
            encoding="utf-8"
        )
    )
    home = yaml.safe_load(
        (ROOT / "ansible" / "host_vars" / "media.home.org.yml").read_text(
            encoding="utf-8"
        )
    )
    playbook = (ROOT / "ansible" / "deploy-media.yml").read_text(encoding="utf-8")
    worker_environment = (
        ROOT / "ansible" / "templates" / "mobile-media-worker.env.j2"
    ).read_text(encoding="utf-8")
    secret_example = yaml.safe_load(
        (ROOT / "ansible" / "auth-secrets.example.yml").read_text(encoding="utf-8")
    )

    assert defaults["mobile_media_enabled"] is False
    assert production["mobile_media_enabled"] is True
    assert home["mobile_media_enabled"] is True
    assert defaults["media_mobile_upload_root"] not in {
        defaults["media_root"],
        defaults["media_ingest_root"],
        defaults["media_import_records_root"],
        defaults["media_export_root"],
    }
    assert defaults["media_mobile_upload_root"].startswith(
        defaults["media_storage_mountpoint"] + "/"
    )

    assert "oldap_mobile_media_service_jwt_secret is not defined" in playbook
    assert "not (rollback | bool) and mobile_media_enabled | bool" in playbook
    assert playbook.count("rollback | bool or not (mobile_media_enabled | bool)") == 8
    assert "Validate private mobile-upload storage separation" in playbook
    assert "Inspect private mobile-upload root without following symlinks" in playbook
    assert "Reject a symlinked or non-directory mobile-upload root" in playbook
    assert "Resolve canonical media storage boundaries" in playbook
    assert "Validate canonical mobile-upload storage separation" in playbook
    assert "resolved_mobile_root.startswith(resolved_mountpoint" in playbook
    assert "Create private mobile upload directory" in playbook
    assert 'mode: "0700"' in playbook
    assert "Render restricted mobile-media worker environment" in playbook
    assert 'dest: "{{ compose_dir }}/mobile-media-worker.env"' in playbook
    assert "mobile-media" in playbook
    assert "Stop mobile-media worker when explicitly disabled" in playbook
    assert "Verify mobile-media worker is running when enabled" in playbook
    assert "Verify the public mobile-media authentication boundary" in playbook

    assert secret_example["oldap_mobile_media_service_jwt_secret"] == ""
    assert "OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET" in worker_environment
    for unrelated_secret in (
        "OLDAP_ACCESS_JWT_SECRET",
        "OLDAP_MEDIA_JWT_SECRET",
        "OLDAP_IMPORT_UPLOAD_JWT_SECRET",
        "OLDAP_IMPORT_SERVICE_JWT_SECRET",
        "OLDAP_IMPORT_RECORDS_JWT_SECRET",
        "OLDAP_EXPORT_SERVICE_JWT_SECRET",
        "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET",
    ):
        assert unrelated_secret not in worker_environment


def test_ansible_mobile_templates_render_strictly_without_secret_values() -> None:
    """Tracked templates must be complete before an operator opens the Vault."""

    variables = yaml.safe_load(
        (ANSIBLE / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    variables.update(
        {
            "oldap_mediahelper_tag": "v-test",
            "oldap_imageserver_tag": "v-test",
            "mobile_media_enabled": True,
            "oldap_mobile_media_service_jwt_secret": "dummy-mobile-secret-not-used",
            "container_extra_hosts": [],
            "caddy_data_dir": "/tmp/caddy-data",
            "caddy_config_dir": "/tmp/caddy-config",
        }
    )
    environment = Environment(
        loader=FileSystemLoader(ANSIBLE / "templates"),
        undefined=StrictUndefined,
        autoescape=False,
    )
    environment.filters["bool"] = bool
    environment.filters["to_json"] = json.dumps

    compose = environment.get_template("docker-compose.yml.j2").render(**variables)
    rendered_compose = yaml.safe_load(compose)
    assert "mobile-media-worker" in rendered_compose["services"]

    caddy = environment.get_template("Caddyfile.j2").render(**variables)
    assert "@mobile_media path /media/v1 /media/v1/*" in caddy

    worker = environment.get_template("mobile-media-worker.env.j2").render(**variables)
    assert (
        'OLDAP_MOBILE_MEDIA_SERVICE_JWT_SECRET="dummy-mobile-secret-not-used"' in worker
    )
