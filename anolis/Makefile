include Makefile.variables

all: help

dist-genlog:
	sh genlog.sh

dist-genspec:
	sh genspec.sh

clean:
	rm -rf $(DIST_OUTPUT)

dist-version:
	@echo $(DIST_ANOLIS_VERSION)

help:
	@echo 'For anolis release'

export