.PHONY: help
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build"     Build and push base image for kakadu""

.PHONY: init-multiarch
init-multiarch:
	docker buildx create --use
	docker buildx create --name multiarch --use
	docker buildx inspect --bootstrap

.PHONY: docker-build
docker-build:
	docker buildx build \
		--no-cache \
		--platform linux/amd64,linux/arm64 \
		-t lrosenth/kakadu-base:v8.6.0 \
		-t lrosenth/kakadu-base:latest \
		--push .
