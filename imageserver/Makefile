.PHONY: help
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build      Build and push base image for kakadu"
	@echo "  docker-run        Run imageserver as docker image"

.PHONY: init-multiarch
init-multiarch:
	docker buildx create --use
	docker buildx create --name multiarch --use
	docker buildx inspect --bootstrap

.PHONY: docker-build-local
docker-build-local:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t lrosenth/oldap-imageserver:local \
		--load .

.PHONY: docker-build
docker-build:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t lrosenth/oldap-imageserver:v0.1.0 \
		-t lrosenth/oldap-imageserver:latest \
		--push .

.PHONY: docker-run-local
docker-run-local:
	docker run -d \
	  --name oldap-imageserver \
	  -p 8182:8182 \
	  -v "$$(pwd)/test-images:/data/images" \
	  -e OLDAP_JWT_SECRET="A very short secret!" \
	  -e OLDAP_JWT_ISS="http://oldap.org" \
	  -e OLDAP_API_BASE="http://host.docker.internal:8000" \
	  -e OLDAP_UNKNOWN_USERID="unknown" \
	  lrosenth/oldap-imageserver:local

.PHONY: docker-run
docker-run:
	docker run -d \
	  --name oldap-imageserver \
	  -p 8182:8182 \
	  -v "$$(pwd)/test-images:/data/images" \
	  -e OLDAP_JWT_SECRET="A very short secret!" \
	  -e OLDAP_JWT_ISS="http://oldap.org" \
	  -e OLDAP_API_BASE="http://localhost:8000" \
	  -e OLDAP_UNKNOWN_USERID="unknown" \
	  lrosenth/oldap-imageserver:latest

