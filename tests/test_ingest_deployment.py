"""Static deployment invariants for private ZIP ingest storage."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_local_compose_mounts_ingest_only_into_mediahelper() -> None:
    """Delivery containers must have no filesystem path to quarantine."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    media_volumes = services["mediaserver"]["volumes"]
    worker = services["ingest-worker"]

    assert any("/data/ingest" in volume for volume in media_volumes)
    for service_name in ("imageserver", "caddy"):
        assert all(
            "/data/ingest" not in volume
            for volume in services[service_name].get("volumes", [])
        )
    assert worker["profiles"] == ["zip-import-validation"]
    assert "ports" not in worker and "expose" not in worker
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert set(worker["cap_add"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "KILL",
        "SETGID",
        "SETUID",
    }
    assert worker["security_opt"] == ["no-new-privileges:true"]
    assert worker["cpus"] == 4.0
    assert worker["mem_limit"] == "6g"
    assert worker["memswap_limit"] == "6g"
    assert worker["pids_limit"] == 128
    assert set(worker["environment"]) == {
        "OLDAP_API_URL",
        "OLDAP_JWT_ISSUER",
        "OLDAP_IMPORT_SERVICE_JWT_SECRET",
        "OLDAP_IMPORT_SERVICE_SUBJECT",
        "OLDAP_INGEST_WORKER_ID",
        "OLDAP_INGEST_ROOT",
        "OLDAP_IMPORT_RECORDS_ROOT",
        "UPLOADER_IMGDIR",
        "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES",
    }
    assert any("/data/images" in volume for volume in worker["volumes"])


def test_image_contains_ingest_modules_and_caddy_has_bounded_route() -> None:
    """The production image and proxy retain the reviewed ingress boundary."""
    dockerfile = (ROOT / "mediaserver" / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (ROOT / "mediaserver" / "Dockerfile.dockerignore").read_text(
        encoding="utf-8"
    )
    caddyfile = (ROOT / "Caddyfile").read_text(encoding="utf-8")
    caddy_template = (ROOT / "ansible" / "templates" / "Caddyfile.j2").read_text(
        encoding="utf-8"
    )

    assert "COPY mediaserver/ingest_auth.py /app/ingest_auth.py" in dockerfile
    assert "COPY mediaserver/export_sources.py /app/export_sources.py" in dockerfile
    assert "COPY mediaserver/export_artifacts.py /app/export_artifacts.py" in dockerfile
    assert "COPY mediaserver/export_service.py /app/export_service.py" in dockerfile
    assert "COPY mediaserver/export_worker.py /app/export_worker.py" in dockerfile
    for module in (
        "export_artifacts.py",
        "export_service.py",
        "export_sources.py",
        "export_worker.py",
    ):
        assert f"!mediaserver/{module}" in dockerignore
    assert "COPY mediaserver/ingest_callback.py /app/ingest_callback.py" in dockerfile
    assert "COPY mediaserver/quarantine.py /app/quarantine.py" in dockerfile
    assert "COPY mediaserver/zip_validation.py /app/zip_validation.py" in dockerfile
    assert "COPY mediaserver/import_records.py /app/import_records.py" in dockerfile
    assert (
        "COPY mediaserver/content_validation.py /app/content_validation.py"
        in dockerfile
    )
    assert "COPY mediaserver/ingest_service.py /app/ingest_service.py" in dockerfile
    assert "COPY mediaserver/ingest_worker.py /app/ingest_worker.py" in dockerfile
    assert "COPY mediaserver/parser_sandbox.py /app/parser_sandbox.py" in dockerfile
    assert "COPY mediaserver/storage_capacity.py /app/storage_capacity.py" in dockerfile
    assert (
        "COPY mediaserver/validation_documents.py /app/validation_documents.py"
        in dockerfile
    )
    assert "verapdf/cli:v1.30.2@sha256:" in dockerfile
    assert "qpdf" in dockerfile
    assert "libseccomp2" in dockerfile
    assert "--uid 65532 --gid 65532" in dockerfile
    assert "default-jre-headless" in dockerfile
    assert "^/imports/[0-9a-fA-F-]{36}/sip$" in caddyfile
    assert "max_size 500MB" in caddyfile
    assert "read_timeout 15m" in caddyfile
    for proxy_config in (caddyfile, caddy_template):
        assert "^/internal/imports/[0-9a-fA-F-]{36}/records/report$" in proxy_config
        assert "@import_report_method not method GET" in proxy_config
        assert "path /internal/export-sources/resolve" in proxy_config
        assert "@export_source_method not method POST" in proxy_config
        assert "max_size 10MB" in proxy_config
        assert "path /internal/*" not in proxy_config
        # An exclusive handle must be sorted with the other handled routes,
        # before the final catch-all. A route directive would be unreachable.
        assert "handle @export_archive" in proxy_config
        assert "route @export_archive" not in proxy_config
        assert "handle @export_archive {\n" in proxy_config
        assert "route {" in proxy_config
        assert "(?P<export_id>" in proxy_config
        assert (
            "uri /auth/exports/{re.export_archive.export_id}/archive"
            in proxy_config
        )
        assert "uri /auth{http.request.uri}" not in proxy_config


def test_callback_retry_and_service_secret_are_deployment_wired() -> None:
    """Production receives a distinct callback key and bounded retry interval."""
    compose_template = (
        ROOT / "ansible" / "templates" / "docker-compose.yml.j2"
    ).read_text(encoding="utf-8")
    environment_template = (
        ROOT / "ansible" / "templates" / "mediahelper-access.env.j2"
    ).read_text(encoding="utf-8")

    assert "OLDAP_IMPORT_CALLBACK_RECONCILE_SECONDS" in compose_template
    assert "OLDAP_INGEST_PART_MAX_AGE_SECONDS" in compose_template
    assert "OLDAP_IMPORT_SERVICE_JWT_SECRET" in environment_template
    assert "OLDAP_IMPORT_SERVICE_SUBJECT" in environment_template
    assert "OLDAP_IMPORT_RECORDS_JWT_SECRET" in environment_template
    assert "OLDAP_EXPORT_SERVICE_JWT_SECRET" in environment_template
    assert "OLDAP_IMPORT_RECORDS_ROOT" in environment_template
    assert "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES" in (
        ROOT / "ansible" / "templates" / "mediaserver.env.j2"
    ).read_text(encoding="utf-8")

    worker_environment = (
        ROOT / "ansible" / "templates" / "ingest-worker.env.j2"
    ).read_text(encoding="utf-8")
    assert "OLDAP_IMPORT_SERVICE_JWT_SECRET" in worker_environment
    assert "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES" in worker_environment
    assert "OLDAP_ACCESS_JWT_SECRET" not in worker_environment
    assert "OLDAP_MEDIA_JWT_SECRET" not in worker_environment
    assert "OLDAP_IMPORT_UPLOAD_JWT_SECRET" not in worker_environment
    assert "OLDAP_IMPORT_RECORDS_JWT_SECRET" not in worker_environment
    assert "OLDAP_EXPORT_SERVICE_JWT_SECRET" not in worker_environment

    deployment = (ROOT / "ansible" / "deploy-media.yml").read_text(encoding="utf-8")
    assert "oldap_export_service_jwt_secret is not defined" in deployment
    assert (
        "(oldap_export_service_jwt_secret | default('') | string | length) >= 32"
        in deployment
    )


def test_export_worker_and_private_delivery_are_isolated() -> None:
    """Export write, read, and credential scopes remain independently bounded."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    worker = services["export-worker"]

    assert worker["profiles"] == ["zip-export-worker"]
    assert "ports" not in worker and "expose" not in worker
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert worker["security_opt"] == ["no-new-privileges:true"]
    assert any(volume.endswith(":/data/images:ro") for volume in worker["volumes"])
    assert any(volume.endswith(":/data/exports") for volume in worker["volumes"])
    assert set(worker["environment"]) == {
        "OLDAP_API_URL",
        "OLDAP_JWT_ISSUER",
        "OLDAP_EXPORT_SERVICE_JWT_SECRET",
        "OLDAP_EXPORT_SERVICE_SUBJECT",
        "OLDAP_EXPORT_WORKER_ID",
        "OLDAP_EXPORT_POLL_SECONDS",
        "OLDAP_EXPORT_HEARTBEAT_SECONDS",
        "OLDAP_EXPORT_LEASE_SECONDS",
        "OLDAP_EXPORT_ROOT",
        "MEDIA_DATA",
        "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES",
    }
    assert any(
        volume.endswith(":/data/exports:ro")
        for volume in services["mediaserver"]["volumes"]
    )
    assert any(
        volume.endswith(":/data/exports:ro") for volume in services["caddy"]["volumes"]
    )
    assert all(
        "/data/exports" not in volume
        for volume in services["imageserver"].get("volumes", [])
    )

    access_environment = (
        ROOT / "ansible" / "templates" / "mediahelper-access.env.j2"
    ).read_text(encoding="utf-8")
    worker_environment = (
        ROOT / "ansible" / "templates" / "export-worker.env.j2"
    ).read_text(encoding="utf-8")
    assert "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET" in access_environment
    assert "OLDAP_EXPORT_DOWNLOAD_JWT_SECRET" not in worker_environment
    assert "OLDAP_EXPORT_SERVICE_JWT_SECRET" in worker_environment
    assert "OLDAP_ACCESS_JWT_SECRET" not in worker_environment

    defaults = yaml.safe_load(
        (ROOT / "ansible" / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    assert defaults["zip_export_worker_enabled"] is False
    assert defaults["media_export_root"] not in {
        defaults["media_root"],
        defaults["media_ingest_root"],
        defaults["media_import_records_root"],
    }


def test_production_deployment_starts_and_verifies_worker_by_default() -> None:
    """Normal deployments must not depend on an undocumented manual start."""
    defaults = yaml.safe_load(
        (ROOT / "ansible" / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    playbook = (ROOT / "ansible" / "deploy-media.yml").read_text(encoding="utf-8")

    assert defaults["zip_import_worker_enabled"] is True
    assert defaults["media_storage_mountpoint"] == "/data"
    assert "Verify the dedicated media filesystem is mounted" in playbook
    assert "profiles:" in playbook
    assert "zip-import-validation" in playbook
    assert "Stop ZIP validation worker when explicitly disabled" in playbook
    assert "Verify ZIP validation worker is running when enabled" in playbook
