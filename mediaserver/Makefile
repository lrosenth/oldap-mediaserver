.PHONY: help
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build      Build and push base image for kakadu"
	@echo "  docker-run        Run docker image"

# Repo root (pyproject.toml lives one level up)
ROOT_DIR := $(abspath $(CURDIR)/..)

# Image naming
IMAGE ?= lrosenth/oldap-mediahelper
VERSION ?= v0.0.10

.PHONY: run
run:
	OLDAP_JWT_SECRET="56cbaa67af5bc403f1de9b7035e7c88239a853e4b40d6fc659ab4e4679b42785" \
	OLDAP_API="http://localhost:8000" \
	UPLOADER_IMGDIR="../imageserver/test-images" \
	gunicorn -b 0.0.0.0:8080 app:app


.PHONY: docker-build-local
docker-build-local:
	docker buildx build \
	    --load \
	    -f Dockerfile \
	    -t $(IMAGE):$(VERSION) \
	    -t $(IMAGE):latest \
	    $(ROOT_DIR)

.PHONY: docker-build
docker-build:
	docker buildx build \
	    --platform linux/amd64,linux/arm64 \
	    -f Dockerfile \
	    -t $(IMAGE):$(VERSION) \
	    -t $(IMAGE):latest \
	    --push \
	    $(ROOT_DIR)

.PHONY: docker-run
docker-run:
	docker run --rm -it \
	  --name uploader-api \
	  -p 8080:8000 \
	  -e OLDAP_JWT_SECRET="56cbaa67af5bc403f1de9b7035e7c88239a853e4b40d6fc659ab4e4679b42785" \
	  -e OLDAP_API_URL=http://host.docker.internal:8000 \
	  -e UPLOADER_IMGDIR="/data/images" \
	  -v "$$(pwd)/../imageserver/test-images:/data/images" \
	  $(IMAGE):$(VERSION)