ANSIBLE_DIR := $(CURDIR)/ansible
# Explicit deployment image; no latest tag and no sibling checkout required.
SIPI_IMAGE ?= lrosenth/sipi-2:0.1.0
IIIF_BACKEND ?= sipi
IMAGESERVER_TAG ?= $(shell $(MAKE) --no-print-directory -s -C imageserver show-tag)
MEDIAHELPER_TAG ?= $(shell $(MAKE) --no-print-directory -s -C mediaserver show-tag)
AUTH_SECRETS_FILE ?= $(HOME)/ProgDev/OLDAP/auth/auth.vault.yml
ANSIBLE_VAULT_ARGS ?= --ask-vault-pass
ANSIBLE_ARGS ?=
LOCAL_COMPOSE_ENV_FILES := $(if $(wildcard .env),--env-file .env) --env-file mediahelper-access.env

.PHONY: help show-versions check-auth-secrets check-local-media-env deploy-production deploy-test deploy-vm deploy-home run-local

help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  show-versions     Show component tags passed to deployment"
	@echo "  deploy-production Deploy the media stack to production"
	@echo "  deploy-test       Deploy the media stack to media.home.org"
	@echo "  deploy-vm         Alias for deploy-production"
	@echo "  deploy-home       Alias for deploy-test"
	@echo "  run-local         Start docker images locally"

show-versions:
	@echo "IIIF_BACKEND=$(IIIF_BACKEND)"
	@echo "SIPI_IMAGE=$(SIPI_IMAGE)"
	@echo "IMAGESERVER_TAG=$(IMAGESERVER_TAG)"
	@echo "MEDIAHELPER_TAG=$(MEDIAHELPER_TAG)"

check-auth-secrets:
	@test -f "$(AUTH_SECRETS_FILE)" || { \
		echo "Missing authentication Vault file: $(AUTH_SECRETS_FILE)"; \
		exit 1; \
	}

check-local-media-env:
	@test -f "mediaserver.env" || { \
		echo "Missing local media configuration: mediaserver.env"; \
		exit 1; \
	}
	@test -f "mediahelper-access.env" || { \
		echo "Missing local media access configuration: mediahelper-access.env"; \
		exit 1; \
	}
	@grep -Eq '^OLDAP_IMPORT_SERVICE_JWT_SECRET=.{32,}$$' mediahelper-access.env || { \
		echo "OLDAP_IMPORT_SERVICE_JWT_SECRET is missing or shorter than 32 characters in mediahelper-access.env"; \
		exit 1; \
	}

deploy-vm: deploy-production

deploy-home: deploy-test

deploy-production: check-auth-secrets
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-l mediaserver \
		-e target_hosts=mediaserver \
		-e "auth_secrets_file=$(AUTH_SECRETS_FILE)" $(ANSIBLE_VAULT_ARGS) \
		-e iiif_backend="$(IIIF_BACKEND)" \
		-e sipi_image="$(SIPI_IMAGE)" \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" \
		-e oldap_mediahelper_tag="$(MEDIAHELPER_TAG)" $(ANSIBLE_ARGS)

deploy-test: check-auth-secrets
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-T 60 \
		-l test_mediaserver \
		-e target_hosts=test_mediaserver \
		-e "auth_secrets_file=$(AUTH_SECRETS_FILE)" $(ANSIBLE_VAULT_ARGS) \
		-e iiif_backend="$(IIIF_BACKEND)" \
		-e sipi_image="$(SIPI_IMAGE)" \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" \
		-e oldap_mediahelper_tag="$(MEDIAHELPER_TAG)" $(ANSIBLE_ARGS)

run-local: check-local-media-env
	docker compose $(LOCAL_COMPOSE_ENV_FILES) \
		--profile zip-import-validation \
		--profile zip-export-worker \
		up -d
