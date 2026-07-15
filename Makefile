ANSIBLE_DIR := $(CURDIR)/ansible
IMAGESERVER_TAG ?= $(shell $(MAKE) --no-print-directory -s -C imageserver show-tag)
ANSIBLE_ARGS ?=

.PHONY: help show-versions deploy-production deploy-test

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

deploy-production:
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" $(ANSIBLE_ARGS)

deploy-test:
	cd "$(ANSIBLE_DIR)" && ansible-playbook \
		-i inventory.ini \
		deploy-media.yml \
		-K \
		-T 60 \
		-e target_hosts=test_mediaserver \
		-e oldap_imageserver_tag="$(IMAGESERVER_TAG)" $(ANSIBLE_ARGS)
