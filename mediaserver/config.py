"""Environment-backed configuration for the OLDAP mediahelper.

Configuration parsing is kept outside Flask application construction so HTTP
handlers, batch workers, and tests can share one explicit settings contract.
The module performs no filesystem writes or network access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
)


@dataclass(frozen=True, slots=True)
class ZipImportLimits:
    """Frozen Phase 0 security policy consumed by future ingest workers.

    These values are code-level ceilings rather than environment overrides.
    Raising one requires a new reviewed policy version and matching contract
    fixtures; deployment configuration may not silently broaden acceptance.
    """

    max_compressed_bytes: int = 500_000_000
    max_extracted_bytes: int = 3_000_000_000
    max_individual_file_bytes: int = 3_000_000_000
    max_entries: int = 10_000
    max_compression_ratio_per_file: int = 100
    max_aggregate_compression_ratio: int = 50
    max_directory_depth: int = 5
    max_path_segment_utf8_bytes: int = 255
    max_relative_path_utf8_bytes: int = 1_024
    max_image_pixels: int = 100_000_000
    max_image_axis_pixels: int = 30_000
    max_text_bytes: int = 1_048_576
    max_audio_channels: int = 2
    min_audio_sample_rate_hz: int = 8_000
    max_wav_pcm_sample_rate_hz: int = 192_000
    allowed_wav_pcm_bits_per_sample: tuple[int, ...] = (8, 16, 24, 32)
    max_flac_sample_rate_hz: int = 192_000
    allowed_flac_bits_per_sample: tuple[int, ...] = (8, 16, 24)
    max_mp3_sample_rate_hz: int = 48_000
    allowed_h264_profiles: tuple[str, ...] = ("Baseline", "Main", "High")
    max_h264_level: float = 5.2
    allowed_video_pixel_formats: tuple[str, ...] = ("yuv420p",)
    allowed_aac_profiles: tuple[str, ...] = ("LC",)
    max_video_width: int = 3_840
    max_video_height: int = 2_160
    max_video_frames_per_second: int = 60
    max_video_duration_seconds: int = 7_200
    max_validation_seconds: int = 21_600
    max_concurrent_validation_or_import_jobs: int = 1

    def to_contract_snapshot(self) -> dict[str, int | float | list[int] | list[str]]:
        """Return the JSON field names frozen by the v1 manifest contract."""

        return {
            "maxCompressedBytes": self.max_compressed_bytes,
            "maxExtractedBytes": self.max_extracted_bytes,
            "maxIndividualFileBytes": self.max_individual_file_bytes,
            "maxEntries": self.max_entries,
            "maxCompressionRatioPerFile": self.max_compression_ratio_per_file,
            "maxAggregateCompressionRatio": self.max_aggregate_compression_ratio,
            "maxDirectoryDepth": self.max_directory_depth,
            "maxPathSegmentUtf8Bytes": self.max_path_segment_utf8_bytes,
            "maxRelativePathUtf8Bytes": self.max_relative_path_utf8_bytes,
            "maxImagePixels": self.max_image_pixels,
            "maxImageAxisPixels": self.max_image_axis_pixels,
            "maxTextBytes": self.max_text_bytes,
            "maxAudioChannels": self.max_audio_channels,
            "minAudioSampleRateHz": self.min_audio_sample_rate_hz,
            "maxWavPcmSampleRateHz": self.max_wav_pcm_sample_rate_hz,
            "allowedWavPcmBitsPerSample": list(self.allowed_wav_pcm_bits_per_sample),
            "maxFlacSampleRateHz": self.max_flac_sample_rate_hz,
            "allowedFlacBitsPerSample": list(self.allowed_flac_bits_per_sample),
            "maxMp3SampleRateHz": self.max_mp3_sample_rate_hz,
            "allowedH264Profiles": list(self.allowed_h264_profiles),
            "maxH264Level": self.max_h264_level,
            "allowedVideoPixelFormats": list(self.allowed_video_pixel_formats),
            "allowedAacProfiles": list(self.allowed_aac_profiles),
            "maxVideoWidth": self.max_video_width,
            "maxVideoHeight": self.max_video_height,
            "maxVideoFramesPerSecond": self.max_video_frames_per_second,
            "maxVideoDurationSeconds": self.max_video_duration_seconds,
            "maxValidationSeconds": self.max_validation_seconds,
            "maxConcurrentValidationOrImportJobs": (
                self.max_concurrent_validation_or_import_jobs
            ),
        }


@dataclass(frozen=True, slots=True)
class IngestWorkerResources:
    """Confirmed process/container envelope for the sequential ingest worker."""

    cpu_count: int = 4
    memory_bytes: int = 6 * 1_024**3
    pid_limit: int = 128


def parse_csv(value: str) -> tuple[str, ...]:
    """Return non-empty, whitespace-trimmed values from a CSV setting."""

    return tuple(item.strip() for item in value.split(",") if item.strip())


def normalized_base_url(value: str) -> str:
    """Return a non-empty base URL with exactly the required trailing slash."""

    stripped = value.strip()
    return stripped if stripped.endswith("/") else f"{stripped}/"


def non_negative_environment_integer(name: str, default: int = 0) -> int:
    """Parse one non-negative integer setting without accepting units."""

    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be a non-negative integer.") from error
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer.")
    return value


@dataclass(frozen=True, slots=True)
class MediahelperSettings:
    """Runtime configuration shared by mediahelper application components."""

    media_root: Path
    ingest_root: Path
    import_records_root: Path
    iiif_base_url: str
    media_base_url: str
    oldap_api_url: str
    cors_origins: tuple[str, ...]
    storage_absolute_reserve_bytes: int

    @classmethod
    def from_environment(cls) -> "MediahelperSettings":
        """Parse mediahelper settings from the current process environment."""

        cors_default = ",".join(DEFAULT_CORS_ORIGINS)
        return cls(
            media_root=Path(os.environ.get("UPLOADER_IMGDIR", "/data/images").strip()),
            ingest_root=Path(
                os.environ.get("OLDAP_INGEST_ROOT", "/data/ingest").strip()
            ),
            import_records_root=Path(
                os.environ.get(
                    "OLDAP_IMPORT_RECORDS_ROOT", "/data/import-records"
                ).strip()
            ),
            iiif_base_url=normalized_base_url(
                os.environ.get("IIIF_BASE_URL", "http://localhost:8088/iiif/3/")
            ),
            media_base_url=normalized_base_url(
                os.environ.get("MEDIA_BASE_URL", "http://localhost:8088/")
            ),
            oldap_api_url=os.environ.get(
                "OLDAP_API_URL", "http://localhost:8000"
            ).strip(),
            cors_origins=parse_csv(os.environ.get("CORS_ORIGINS", cors_default)),
            storage_absolute_reserve_bytes=non_negative_environment_integer(
                "OLDAP_STORAGE_ABSOLUTE_RESERVE_BYTES"
            ),
        )
