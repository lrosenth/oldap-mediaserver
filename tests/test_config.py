"""Tests for side-effect-free mediahelper environment parsing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


MEDIAHELPER_SOURCE = Path(__file__).resolve().parents[1] / "mediaserver"
if str(MEDIAHELPER_SOURCE) not in sys.path:
    sys.path.insert(0, str(MEDIAHELPER_SOURCE))

from config import (  # noqa: E402
    IngestWorkerResources,
    MediahelperSettings,
    ZipImportLimits,
    normalized_base_url,
    non_negative_environment_integer,
    parse_csv,
)


def test_settings_parse_environment_without_touching_storage(
    monkeypatch, tmp_path: Path
) -> None:
    """Configuration loading normalizes values but does not create directories."""

    media_root = tmp_path / "not-created"
    ingest_root = tmp_path / "ingest-not-created"
    records_root = tmp_path / "records-not-created"
    monkeypatch.setenv("UPLOADER_IMGDIR", str(media_root))
    monkeypatch.setenv("OLDAP_INGEST_ROOT", str(ingest_root))
    monkeypatch.setenv("OLDAP_IMPORT_RECORDS_ROOT", str(records_root))
    monkeypatch.setenv("IIIF_BASE_URL", "https://media.example/iiif/3")
    monkeypatch.setenv("MEDIA_BASE_URL", "https://media.example")
    monkeypatch.setenv("OLDAP_API_URL", " https://api.example ")
    monkeypatch.setenv("CORS_ORIGINS", " https://one.example, ,https://two.example ")

    settings = MediahelperSettings.from_environment()

    assert settings.media_root == media_root
    assert settings.ingest_root == ingest_root
    assert settings.import_records_root == records_root
    assert settings.iiif_base_url == "https://media.example/iiif/3/"
    assert settings.media_base_url == "https://media.example/"
    assert settings.oldap_api_url == "https://api.example"
    assert settings.cors_origins == ("https://one.example", "https://two.example")
    assert settings.storage_absolute_reserve_bytes == 0
    assert not media_root.exists()
    assert not ingest_root.exists()
    assert not records_root.exists()


def test_configuration_value_helpers_are_deterministic() -> None:
    """CSV and URL normalization are reusable without process-global state."""

    assert parse_csv("a, b, ,c") == ("a", "b", "c")
    assert (
        normalized_base_url("https://example.test/base") == "https://example.test/base/"
    )
    assert (
        normalized_base_url("https://example.test/base/")
        == "https://example.test/base/"
    )


def test_zip_limits_match_frozen_manifest_contract() -> None:
    """Runtime policy values cannot drift from the reviewed v1 JSON contract."""

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "zip-import"
        / "v1"
        / "common.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    properties = schema["$defs"]["LimitsSnapshot"]["properties"]
    contract_constants = {
        name: definition["const"] for name, definition in properties.items()
    }

    assert ZipImportLimits().to_contract_snapshot() == contract_constants
    assert IngestWorkerResources() == IngestWorkerResources(
        cpu_count=4,
        memory_bytes=6 * 1_024**3,
        pid_limit=128,
    )


def test_absolute_storage_reserve_is_a_non_negative_byte_count(monkeypatch) -> None:
    """Operators may tighten, but never disable, the frozen percentage guard."""

    monkeypatch.setenv("OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES", "250000000000")
    assert (
        non_negative_environment_integer("OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES")
        == 250_000_000_000
    )
    monkeypatch.setenv("OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES", "-1")
    with pytest.raises(ValueError, match="non-negative integer"):
        MediahelperSettings.from_environment()
