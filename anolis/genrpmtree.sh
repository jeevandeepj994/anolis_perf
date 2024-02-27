#! /bin/bash

set -xe

function do_prep() {
    mkdir -p ${DIST_RPMBUILDDIR_OUTPUT}
    mkdir -p ${DIST_RPMBUILDDIR_OUTPUT}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    cp ${DIST_RPM}/cpupower*            ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/
    cp ${DIST_RPM}/filter-*             ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/
    cp ${DIST_RPM}/mod-*                ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/
    cp ${DIST_RPM}/generate_bls_conf.sh ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/

    # for official build, the corresponding tag should exist
    if [ -n "$DIST_OFFICIAL_BUILD" ]; then
        if ! git tag | grep -q -x "${DIST_PKG_COMMIT_ID}"; then
            echo "cannot find official build tag: ${DIST_PKG_COMMIT_ID}"
            exit 1
        fi
    fi

    pkgname="linux-${DIST_ANOLIS_VERSION}${DIST}"
    pushd ${DIST_SRCROOT} > /dev/null
    git archive --format=tar --prefix="${pkgname}/" ${DIST_PKG_COMMIT_ID} | xz -T$(nproc) > ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/${pkgname}.tar.xz
    md5sum ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/${pkgname}.tar.xz > ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/download
    popd > /dev/null
    DIST_OUTPUT=${DIST_RPMBUILDDIR_OUTPUT}/SPECS/ sh genspec.sh

    # the kconfigs of x86 and arm64 has been moved to kconfig baseline,
    # so use `make dist-configs` to generate them
    make -C ${DIST_SRCROOT}/anolis dist-configs
    cp ${DIST_OUTPUT}/kernel-${DIST_KERNELVERSION}-x86-ANCK.config \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-x86_64.config
    cp ${DIST_OUTPUT}/kernel-${DIST_KERNELVERSION}-x86-debug-ANCK.config \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-x86_64-debug.config
    cp ${DIST_OUTPUT}/kernel-${DIST_KERNELVERSION}-arm64-ANCK.config \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-aarch64.config
    cp ${DIST_OUTPUT}/kernel-${DIST_KERNELVERSION}-arm64-debug-ANCK.config \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-aarch64-debug.config

    # the kconfigs of sw_64 and loongarch keep the legacy way,
    # so still copy them from arch/${arch}/configs/ directory.
    cp ${DIST_SRCROOT}/arch/sw_64/configs/anolis_defconfig \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-sw_64.config
    cp ${DIST_SRCROOT}/arch/sw_64/configs/anolis-debug_defconfig \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-sw_64-debug.config
    cp ${DIST_SRCROOT}/arch/loongarch/configs/anolis_defconfig \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-loongarch64.config
    cp ${DIST_SRCROOT}/arch/loongarch/configs/anolis-debug_defconfig \
    ${DIST_RPMBUILDDIR_OUTPUT}/SOURCES/kernel-${DIST_KERNELVERSION}-loongarch64-debug.config
}

do_prep