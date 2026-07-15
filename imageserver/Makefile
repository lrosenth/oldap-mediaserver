# The component version is intentionally independent from the bundled
# Cantaloupe release and from the other deployable images in this repository.
IMAGE ?= lrosenth/oldap-imageserver
VERSION_FILE := $(CURDIR)/VERSION
override VERSION := $(strip $(shell sed -n '1p' $(VERSION_FILE)))
override TAG := v$(VERSION)
override IMAGE_REF := $(IMAGE):$(TAG)
CANTALOUPE_VERSION ?= 5.0.7

.PHONY: help check-version show-version show-tag show-image init-multiarch \
	docker-build-local docker-build docker-run-local docker-run
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  show-version      Show the imageserver component version"
	@echo "  show-tag          Show the derived Docker tag"
	@echo "  show-image        Show the complete versioned image reference"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build      Build and push the versioned imageserver image"
	@echo "  docker-run        Run imageserver as docker image"

check-version:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$$' || { \
		echo "Invalid imageserver version in $(VERSION_FILE): $(VERSION)"; \
		exit 1; \
	}

show-version: check-version
	@echo "$(VERSION)"

show-tag: check-version
	@echo "$(TAG)"

show-image: check-version
	@echo "$(IMAGE_REF)"

init-multiarch:
	docker buildx create --use
	docker buildx create --name multiarch --use
	docker buildx inspect --bootstrap

docker-build-local: check-version
	docker buildx build \
		--build-arg IMAGE_VERSION="$(VERSION)" \
		--build-arg CANTALOUPE_VERSION="$(CANTALOUPE_VERSION)" \
		-t "$(IMAGE):local" \
		--load .

docker-build: check-version
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg IMAGE_VERSION="$(VERSION)" \
		--build-arg CANTALOUPE_VERSION="$(CANTALOUPE_VERSION)" \
		-t "$(IMAGE_REF)" \
		-t "$(IMAGE):latest" \
		--push .

docker-run-local:
	docker rm -f oldap-imageserver
	docker run -d \
	  --name oldap-imageserver \
	  -p 8182:8182 \
	  -v "$$(pwd)/test-images:/data/images" \
	  --env-file ../mediaserver.env \
	  -e OLDAP_API_URL="http://host.docker.internal:8000" \
	  -e OLDAP_UNKNOWN_USERID="unknown" \
	  "$(IMAGE):local"

docker-run: check-version
	docker rm -f oldap-imageserver
	docker run -d \
	  --name oldap-imageserver \
	  -p 8182:8182 \
	  -v "$$(pwd)/test-images:/data/images" \
	  --env-file ../mediaserver.env \
	  -e OLDAP_API_URL="http://host.docker.internal:8000" \
	  -e OLDAP_UNKNOWN_USERID="unknown" \
	  "$(IMAGE_REF)"
