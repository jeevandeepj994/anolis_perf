#! /bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# To export kconfigs as xlsx format.
#
# Copyright (C) 2023 Qiao Ma <mqaio@linux.alibaba.com>

set -e

SCRIPT_DIR=$(realpath $(dirname $0))

mkdir -p ${DIST_OUTPUT}
python3 ${SCRIPT_DIR}/anolis_kconfig.py export\
        --input_dir ${SCRIPT_DIR}/../ \
        --output ${DIST_OUTPUT}/configs.xlsx\
