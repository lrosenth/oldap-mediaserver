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
	@echo "  help               Show this help message"
	@echo "  show-version       Show the mediahelper component version"
	@echo "  show-tag           Show the derived Docker tag"
	@echo "  show-image         Show the complete versioned image reference"
	@echo "  run                Run the mediahelper directly with Gunicorn"
	@echo "  docker-build       Build and verify both architectures locally (docker-image alias)"
	@echo "  docker-publish     Publish accepted images without rebuilding or updating latest"
	@echo "  docker-build-local Build a local-only docker image"
	@echo "  docker-run         Run the versioned mediahelper Docker image"

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
	OLDAP_MOBILE_UPLOAD_ROOT="$(ROOT_DIR)/mobile-uploads" \
	gunicorn -b 0.0.0.0:8080 app:app


docker-build-local: check-version
	docker buildx build \
	    --load \
	    -f Dockerfile \
	    --build-arg MEDIAHELPER_VERSION="$(VERSION)" \
	    -t "$(IMAGE):local" \
	    $(ROOT_DIR)

# A new bundle freezes inputs; publication requires its accepted image IDs.
IMAGE_BUNDLE ?= $(ROOT_DIR)/build/mediahelper/$(VERSION)
.PHONY: docker-image docker-publish docker-push
docker-build docker-image: check-version
	cd "$(ROOT_DIR)" && poetry run python scripts/mediahelper_images.py build \
		--bundle "$(IMAGE_BUNDLE)" --image "$(IMAGE)" --version "$(VERSION)"

docker-publish docker-push: check-version
	cd "$(ROOT_DIR)" && poetry run python scripts/mediahelper_images.py publish \
		--bundle "$(IMAGE_BUNDLE)" --image "$(IMAGE)" --version "$(VERSION)"

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
