# Repo root (pyproject.toml lives one level up). The media helper Dockerfile
# has its own .dockerignore file, so this context stays intentionally tiny.
ROOT_DIR := $(abspath $(CURDIR)/..)

# The component version is independent from the repository-wide Python package
# version and from the other deployable images in this repository.
IMAGE ?= lrosenth/oldap-mediahelper
VERSION_FILE := $(CURDIR)/VERSION
override VERSION := $(strip $(shell sed -n '1p' $(VERSION_FILE)))
override TAG := v$(VERSION)
override IMAGE_REF := $(IMAGE):$(TAG)

.PHONY: help check-version show-version show-tag show-image run \
	docker-build-local docker-build docker-run-local docker-run

help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  show-version      Show the mediahelper component version"
	@echo "  show-tag          Show the derived Docker tag"
	@echo "  show-image        Show the complete versioned image reference"
	@echo "  run               Run the mediahelper directly with Gunicorn"
	@echo "  docker-build      Build and push the versioned mediahelper image"
	@echo "  docker-run        Run the versioned mediahelper Docker image"

check-version:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$$' || { \
		echo "Invalid mediahelper version in $(VERSION_FILE): $(VERSION)"; \
		exit 1; \
	}

show-version: check-version
	@echo "$(VERSION)"

show-tag: check-version
	@echo "$(TAG)"

show-image: check-version
	@echo "$(IMAGE_REF)"

run:
	set -a; . ../mediaserver.env; . ../mediahelper-access.env; set +a; \
	OLDAP_API="http://localhost:8000" \
	UPLOADER_IMGDIR="../imageserver/test-images" \
	gunicorn -b 0.0.0.0:8080 app:app


docker-build-local: check-version
	docker buildx build \
	    --load \
	    -f Dockerfile \
	    --build-arg MEDIAHELPER_VERSION="$(VERSION)" \
	    -t "$(IMAGE):local" \
	    $(ROOT_DIR)

docker-build: check-version
	docker buildx build \
	    --platform linux/amd64,linux/arm64 \
	    -f Dockerfile \
	    --build-arg MEDIAHELPER_VERSION="$(VERSION)" \
	    -t "$(IMAGE_REF)" \
	    -t "$(IMAGE):latest" \
	    --push \
	    $(ROOT_DIR)

docker-run-local:
	docker run --rm -it \
	  --name uploader-api \
	  -p 8080:8000 \
	  --env-file ../mediaserver.env \
	  --env-file ../mediahelper-access.env \
	  -e OLDAP_API_URL=http://host.docker.internal:8000 \
	  -e UPLOADER_IMGDIR="/data/images" \
	  -v "$$(pwd)/../imageserver/test-images:/data/images" \
	  "$(IMAGE):local"

docker-run: check-version
	docker run --rm -it \
	  --name uploader-api \
	  -p 8080:8000 \
	  --env-file ../mediaserver.env \
	  --env-file ../mediahelper-access.env \
	  -e OLDAP_API_URL=http://host.docker.internal:8000 \
	  -e UPLOADER_IMGDIR="/data/images" \
	  -v "$$(pwd)/../imageserver/test-images:/data/images" \
	  "$(IMAGE_REF)"
