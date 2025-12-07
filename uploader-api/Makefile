.PHONY: help
help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  init-multiarch    Initialize multiple architectures for docker"
	@echo "  docker-build      Build and push base image for kakadu"
	@echo "  docker-run        Run docker image"

.PHONY: run
run:
	OLDAP_JWT_SECRET="A very short secret!" \
	OLDAP_API="http://localhost:8000" \
	UPLOADER_IMGDIR="../imageserver/test-images2" \
	gunicorn -b 0.0.0.0:8080 app:app


.PHONY: docker-build-local
docker-build-local:
	poetry export --only main -f requirements.txt --without-hashes -o requirements.txt
	docker buildx build \
	    --load \
	    -t lrosenth/oldap-uploadserver:v0.0.4 \
	    -t lrosenth/oldap-uploadserver:latest \
		.

.PHONY: docker-build
docker-build:
	poetry export --only main -f requirements.txt --without-hashes -o requirements.txt
	docker buildx build \
	    --platform linux/amd64,linux/arm64 \
	    -t lrosenth/oldap-uploadserver:v0.0.4 \
	    -t lrosenth/oldap-uploadserver:latest \
	    --push .

.PHONY: docker-run
docker-run:
	docker run --rm -it \
	  --name uploader-api \
	  -p 8080:8000 \
	  -e OLDAP_JWT_SECRET="A very short secret!" \
	  -e OLDAP_API_URL=http://host.docker.internal:8000 \
	  -e UPLOADER_IMGDIR="/data/images" \
	  -v "$$(pwd)/../imageserver/test-images:/data/images" \
	  lrosenth/oldap-uploadserver:v0.0.4