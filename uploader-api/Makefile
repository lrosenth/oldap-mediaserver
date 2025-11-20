.PHONY: help
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build"     Build and push base image for kakadu""

.PHONY: docker-build
docker-build:
	poetry export --only main -f requirements.txt --without-hashes -o requirements.txt
	docker buildx build \
	    --platform linux/amd64,linux/arm64 \
	    -t lrosenth/oldap-uploadserver:v0.0.1 \
	    -t lrosenth/oldap-uploadserver:latest \
	    --push .

.PHONY: docker-run
docker-run:
	docker run --rm -it \
	  --name uploader-api \
	  -p 8080:8000 \
	  -v "$$(pwd)/../imageserver/test-images:/data/images" \
	  lrosenth/oldap-uploadserver:latest