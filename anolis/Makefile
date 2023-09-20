include Makefile.variables

all: help

dist-check:
	@if [ "${DIST_BUILD_MODE}" == "official" ]; then \
		if [ "$(shell git describe --tags --exact-match HEAD 2>/dev/null)" != "${DIST_ANOLIS_VERSION}" ]; then \
			echo "Error: For official build, the tag ${DIST_ANOLIS_VERSION} should point to HEAD"; \
			exit 1; \
		fi \
	fi

dist-genlog:
	sh genlog.sh

dist-genspec: dist-check
	sh genspec.sh

dist-genrpmtree: dist-check
	sh genrpmtree.sh

dist-rpms: dist-genrpmtree dist-check
	sh buildpkg.sh

clean:
	rm -rf $(DIST_OUTPUT)

dist-version:
	@echo $(DIST_ANOLIS_VERSION)

help:
	@echo 'For anolis release'
	@echo ''
	@echo 'generic commands:'
	@echo '    dist-genspec     - generate kernel spec file through kernel.spec.template and changelog files'
	@echo '    dist-genlog      - generate changelogs'
	@echo '    dist-genrpmtree  - generate rpm tree'
	@echo '    dist-rpms        - build kernel rpm package, it will auto generated in $(DIST_SHORT_OUTPUT)'
	@echo '    dist-version     - show dist version'
	@echo '    clean            - cleanup output dir'
	@echo ''
	@echo '-------------------------------'
	@echo 'the environment variables that could override:'
	@echo '    DIST                 - the distribution suffix, eg: .an7, .an8, .an23'
	@echo '    DIST_OUTPUT          - the output directory, default: $(DIST_SHORT_OUTPUT)'
	@echo '    DIST_BUILD_MODE      - the build mode. optional: official/nightly/devel'
	@echo '                           !!! NOTE: BE CAUTIOUS ABOUT USING official BUILD !!!'
	@echo '                             - official build. kernel version: $(DIST_KERNELVERSION)-$(DIST_OFFICIAL_PKGRELEASEVERION), with srpm'
	@echo '                             - nightly build. kernel version: $(DIST_KERNELVERSION)-$(DIST_UNOFFICIAL_PKGRELEASEVERION), with srpm'
	@echo '                             - devel build. kernel version: $(DIST_KERNELVERSION)-$(DIST_UNOFFICIAL_PKGRELEASEVERION), without srpm'
	@echo '    DIST_BUILD_NUMBER    - the build number for unofficial build, eg: 1/2'
	@echo '    DIST_BUILD_VARIANT & DIST_BUILD_EXTRA  - see comments in buildpkg.sh'

export