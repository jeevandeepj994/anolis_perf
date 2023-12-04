include Makefile.configs

ifeq ($(MAKELEVEL),0)
    $(error The config related target cannot be executed directly from the shell.)
endif

dist-defconfig:
	@sh scripts/generate_configs.sh ${DIST_ARCH}

dist-debug-defconfig:
	@sh scripts/generate_configs.sh ${DIST_ARCH}-debug

dist-configs:
	@sh scripts/generate_configs.sh ${DIST_CONFIG_KERNEL_ARCHS}

dist-configs-help:
	@echo ''
	@echo '--------------------------------'
	@echo 'Generate and update kernel configs'
	@echo '    dist-defconfig:        - generate anolis default config file of current ARCH, output to $${DIST_OUTPUT}'
	@echo '    dist-debug-defconfig:  - generate anolis debug default config file of current ARCH, output to $${DIST_OUTPUT}'
	@echo '    dist-configs:          - generate anolis config files to all arch, output to $${DIST_OUTPUT}'

export