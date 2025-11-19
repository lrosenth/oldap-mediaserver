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
		--platform linux/amd64,linux/arm64 \
		-t lrosenth/oldap-imageserver:v0.1.0 \
		-t lrosenth/oldap-imageserver:latest \
		--push .

.PHONY: docker-run
docker-run:
	docker run -d \
	  --name oldap-imageserver \
	  -p 8182:8182 \
	  -v "$$(pwd)/test-images:/data/images" \
	  lrosenth/oldap-imageserver:latest

