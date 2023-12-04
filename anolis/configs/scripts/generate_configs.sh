#! /bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Generate the whole kconfig files.
#
# Copyright (C) 2023 Qiao Ma <mqaio@linux.alibaba.com>

set -e

SCRIPT_DIR=$(realpath $(dirname $0))

mkdir -p ${DIST_OUTPUT}

for arch in $@
do
    python3 ${SCRIPT_DIR}/anolis_kconfig.py generate\
        --input_dir ${SCRIPT_DIR}/../ \
        --output_dir ${DIST_OUTPUT}\
        $arch

    config_file_name=kernel-${DIST_KERNELVERSION}-${arch}-${DIST_CONFIG_KERNEL_NAME}.config

    echo "* process ${config_file_name}"

    KCONFIG_CONFIG=${DIST_OUTPUT}/${config_file_name} \
    ARCH=${arch%%-*} \
    CROSS_COMPILE=scripts/dummy-tools/ \
    make -C ${DIST_SRCROOT} olddefconfig > /dev/null

    # remove old backup kconfig file
    rm -f ${DIST_OUTPUT}/${config_file_name}.old

    if [ "${DIST_DO_GENERATE_DOT_CONFIG}" == "Y" ]; then
        cp -f ${DIST_OUTPUT}/${config_file_name} \
        ${DIST_SRCROOT}.config
    fi
done
