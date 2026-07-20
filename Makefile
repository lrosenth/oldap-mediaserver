ANSIBLE_DIR := $(CURDIR)/ansible
IMAGESERVER_TAG ?= $(shell $(MAKE) --no-print-directory -s -C imageserver show-tag)
MEDIAHELPER_TAG ?= $(shell $(MAKE) --no-print-directory -s -C mediaserver show-tag)
AUTH_SECRETS_FILE ?= $(HOME)/ProgDev/OLDAP/auth/auth.vault.yml
ANSIBLE_VAULT_ARGS ?= --ask-vault-pass
ANSIBLE_ARGS ?=

.PHONY: help show-versions check-auth-secrets deploy-production deploy-test

help:
	@echo "Usage: make [target] ..."
	@echo ""
	@echo "Available targets:"
	@echo "  help              Show this help message"
	@echo "  show-versions     Show component tags passed to deployment"
	@echo "  deploy-production Deploy the media stack to production"
	@echo "  deploy-test       Deploy the media stack to media.home.org"

show-versions:
	@echo "IMAGESERVER_TAG=$(IMAGESERVER_TAG)"
	@echo "MEDIAHELPER_TAG=$(MEDIAHELPER_TAG)"

check-auth-secrets:
	@test -f "$(AUTH_SECRETS_FILE)" || { \
		echo "Missing authentication Vault file: $(AUTH_SECRETS_FILE)"; \
		exit 1; \
	}

deploy-production: check-auth-secrets
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-e "auth_secrets_file=$(AUTH_SECRETS_FILE)" $(ANSIBLE_VAULT_ARGS) \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" \
		-e oldap_mediahelper_tag="$(MEDIAHELPER_TAG)" $(ANSIBLE_ARGS)

deploy-test: check-auth-secrets
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-T 60 \
		-e target_hosts=test_mediaserver \
		-e "auth_secrets_file=$(AUTH_SECRETS_FILE)" $(ANSIBLE_VAULT_ARGS) \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" \
		-e oldap_mediahelper_tag="$(MEDIAHELPER_TAG)" $(ANSIBLE_ARGS)
