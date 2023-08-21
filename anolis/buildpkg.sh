set -xe

function do_rpmbuild() {
	if [ -z "$DIST_OFFICIAL_BUILD" ]; then
		CMD="-bb"
	else
		CMD="-ba"
	fi

	# Now we have:
	#  + variants: default, only-debug, with-debug
	#  + extras: base, with-debuginfo, full
	#  + modes: nightly, dev, pre-release
	#TODO: add with-gcov
	#
	# Matrix
	#
	# | Extra\Var | Default  | Only-debug | With-debug |
	# |-----------|----------|------------|------------|
	# | Base      | +default | -default   | +default   |
	# |           | -debug   | +debug     | +debug     |
	# |           |            +headers                |
	# |-----------|------------------------------------|
	# | debuginfo |            +debuginfo              |
	# |-----------|------------------------------------|
	# | full      |         +tools +doc +perf          |
	#
	# Note: pre-release mode will always be "full" and "with-debug" by default

	build_opts="--with headers --without bpftool --without signmodules"

	if [ "_${DIST_BUILD_VARIANT}" == "_only-debug" ]; then
		build_opts="$build_opts --without default --with debug"
	elif [ "_${DIST_BUILD_VARIANT}" == "_with-debug" ]; then
		build_opts="$build_opts --with default --with debug"
	else # assume default
		build_opts="$build_opts --with default --without debug"
	fi

	if [ "_${DIST_BUILD_EXTRA}" == "_debuginfo" ]; then
		build_opts="$build_opts --with debuginfo --without tools --without doc --without perf"
	elif [ "_${DIST_BUILD_EXTRA}" == "_base" ]; then
		build_opts="$build_opts --without debuginfo --without tools --without doc --without perf"
	else # assume full
		build_opts="$build_opts --with debuginfo --with tools --with doc --with perf"
	fi

    # launch a new shell to clear current environment variables passed by Makefile
	 rpmbuild \
		--define "%_smp_mflags -j$(nproc)" \
		--define "%packager <alicloud-linux@alibaba-inc.com>" \
		--define "%_topdir ${DIST_RPMBUILDDIR_OUTPUT}" \
		${build_opts} \
		${CMD} ${DIST_RPMBUILDDIR_OUTPUT}/SPECS/kernel.spec \
		--target=$(uname -m) || exit 1
}

function output() {
	if [ -z "$DIST_OFFICIAL_BUILD" ]; then
		targetdir=${DIST_BUILD_NUMBER}
	else
		targetdir=${DIST_ANOLIS_VERSION}
	fi

	mkdir -p ${DIST_OUTPUT}/${targetdir}

	cp ${DIST_RPMBUILDDIR_OUTPUT}/RPMS/$(uname -m)/*.rpm ${DIST_OUTPUT}/${targetdir}/

	# copy srpm packages if and only if they exist.
	if [ -f ${DIST_RPMBUILDDIR_OUTPUT}/SRPMS/*.rpm ]; then
		cp ${DIST_RPMBUILDDIR_OUTPUT}/SRPMS/*.rpm ${DIST_OUTPUT}/${targetdir}
	fi

	i=0
	for p in ${DIST_OUTPUT}/${targetdir}/*.rpm; do
		echo $p
		((i++))
	done

	echo "$i rpm(s) copied."
}

do_rpmbuild
output