PLUGIN_DIR := kubectl-krb_keycloak

.PHONY: build test integration-test lint cross-build clean

build test integration-test lint cross-build clean:
	$(MAKE) -C $(PLUGIN_DIR) $@
