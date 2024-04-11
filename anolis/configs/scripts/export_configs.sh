#! /bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# To export kconfigs as xlsx format.
#
# Copyright (C) 2023 Qiao Ma <mqaio@linux.alibaba.com>

set -e

SCRIPT_DIR=$(realpath $(dirname $0))

mkdir -p ${DIST_OUTPUT}
arch_list="x86 arm64"
sort_ref_list=""

pushd ${DIST_SRCROOT} > /dev/null
    files=
    for arch in ${arch_list}
    do
        ARCH=${arch} CROSS_COMPILE=scripts/dummy-tools/ make allyesconfig
        sort_name=${DIST_OUTPUT}/sorted_ref-${arch}
        cp .config ${sort_name}
        sort_ref_list="${sort_ref_list} ${sort_name}"
    done
popd > /dev/null

python3 ${SCRIPT_DIR}/anolis_kconfig.py export\
        --input_dir ${SCRIPT_DIR}/../ \
        --output ${DIST_OUTPUT}/configs.xlsx\
        ${sort_ref_list}
