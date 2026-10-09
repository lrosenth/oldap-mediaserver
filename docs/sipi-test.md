# Local SIPI-2 source build

SIPI-2 is now the default backend. For normal local/VM use, configuration, cache
lifecycle and Cantaloupe fallback, see [deployment](sipi-deployment.md).
The optional override is only needed to build the sibling sipi-2 checkout:

```sh
docker compose -f docker-compose.yml -f docker-compose.sipi-test.yml build imageserver
docker compose -f docker-compose.yml -f docker-compose.sipi-test.yml up -d --no-deps imageserver
```

The checkout is expected at `../../sipi-2`. No C++ source is placed in the runtime
image. The base file owns policy, environment, storage and resource settings;
the override changes only image/build. Ordinary `docker compose up -d` selects
the image from `SIPI_IMAGE` in the ignored `.env`, or the base release default.

The earlier 2026-10-07 trial used a separate `sipi_test_cache` volume. It is not
deleted by the migration and need not be copied into the new `sipi_cache` volume.
Source files, asset IDs, media tokens and Caddy's `/iiif/3` path are unchanged.
