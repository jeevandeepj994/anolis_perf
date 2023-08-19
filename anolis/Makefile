include Makefile.variables

all: help

dist-genlog:
	sh genlog.sh

dist-genspec:
	sh genspec.sh

dist-genrpmtree:
	sh genrpmtree.sh

dist-rpms: dist-genrpmtree
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
	@echo '    DIST_DO_SIGNMODULES  - should sign kernel modules. optional: 0/1, default: 0'
	@echo '    DIST_OUTPUT          - the output directory, default: $(DIST_SHORT_OUTPUT)'
	@echo '    DIST_OFFICIAL_BUILD  - if offical build, the kernel version looks like: 5.10.134-15.1_rc1,'
	@echo '                           else it looks like: 5.10.134-1.git.6235a991a61d'
	@echo '    DIST_BUILD_NUMBER    - the build number for unofficial build, eg: 1/2'
	@echo '    DIST_BUILD_VARIANT & DIST_BUILD_EXTRA  - see comments in buildpkg.sh'

export