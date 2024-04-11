#! /bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# To update kconfigs.
#
# Copyright (C) 2023 Qiao Ma <mqaio@linux.alibaba.com>

set -e

SCRIPT_DIR=$(realpath $(dirname $0))
BASE_CONFIG_DIR=$(realpath ${SCRIPT_DIR}/..)
TMP_DIR=${DIST_OUTPUT}/configs
OLD_CONFIG_DIR=${TMP_DIR}/old
NEW_CONFIG_DIR=${TMP_DIR}/new
BACKUP_CONFIG_DIR=${BASE_CONFIG_DIR}/configs.${DIST_CONFIG_KERNEL_NAME}.old

if [ "${DIST_CONFIG_KERNEL_NAME}" != "ANCK" ]; then
    OVERRIDE_CONFIG_DIR=${BASE_CONFIG_DIR}/OVERRIDE/${DIST_CONFIG_KERNEL_NAME}
else
    OVERRIDE_CONFIG_DIR=${BASE_CONFIG_DIR}
fi

function log() {
    echo $@
}

function prepare_env() {
    rm -rf ${TMP_DIR}
    mkdir -p ${OLD_CONFIG_DIR}
    mkdir -p ${NEW_CONFIG_DIR}
}

function prepare_old_configs() {
    log "collect all old configs..."
    # generate old config files
    python3 ${SCRIPT_DIR}/anolis_kconfig.py generate \
            --input_dir ${BASE_CONFIG_DIR} \
            --output_dir ${OLD_CONFIG_DIR} \
            ${DIST_CONFIG_KERNEL_ARCHS}

    for level in ${DIST_LEVELS}
    do
        if [ -d ${OVERRIDE_CONFIG_DIR}/${level} ]; then
            cp -r ${OVERRIDE_CONFIG_DIR}/${level} ${OLD_CONFIG_DIR}
        fi
    done
}

function import_old_configs() {
    TMP=${OLD_CONFIG_DIR}

    pushd ${DIST_SRCROOT} > /dev/null

    mkdir -p ${TMP}

    cat ${SCRIPT_DIR}/kconfig_locations | grep -v "^#" | while IFS= read -r line
    do
        if [ -z "$line" ]; then
            continue
        fi
        local array=($line)
        local arch=${array[0]}
        local name=${array[1]}
        local config=${array[2]}
        cp ${config} .config
        ARCH=${arch} CROSS_COMPILE=scripts/dummy-tools/ make olddefconfig > /dev/null 2>&1
        cp .config ${TMP}/kernel-${DIST_KERNELVERSION}-${name}-${DIST_CONFIG_KERNEL_NAME}.config
    done

    popd > /dev/null
}

function refresh_old_configs() {
    # refresh old config files into new config files
    log "refresh all old configs with \`make olddefconfig\`..."
    pushd ${DIST_SRCROOT} > /dev/null
    for arch in ${DIST_CONFIG_KERNEL_ARCHS}
    do
        local file_name=kernel-${DIST_KERNELVERSION}-${arch}-${DIST_CONFIG_KERNEL_NAME}.config
        local arch=$(echo ${arch} | sed -e 's/-debug//')
        cp -f ${OLD_CONFIG_DIR}/${file_name} ${DIST_SRCROOT}/.config
        ARCH=${arch} CROSS_COMPILE=scripts/dummy-tools/ make olddefconfig > /dev/null 2>&1
        cp .config ${NEW_CONFIG_DIR}/${file_name}
    done
    popd > /dev/null
}

function split_new_configs() {
    # split new config files
    echo "split new configs..."
    local new_config_files=$(find ${NEW_CONFIG_DIR} -type f)
    python3 ${SCRIPT_DIR}/anolis_kconfig.py split \
            --old_top_dir ${BASE_CONFIG_DIR} \
            --output_top_dir ${NEW_CONFIG_DIR} \
            ${new_config_files}
}

function replace_with_new_configs() {
    log "replace old configs with new configs...."

    rm -rf ${BACKUP_CONFIG_DIR}
    mkdir -p ${BACKUP_CONFIG_DIR}
    mkdir -p ${OVERRIDE_CONFIG_DIR}
    for level in ${DIST_LEVELS};
    do
        if [ -d ${OVERRIDE_CONFIG_DIR}/${level} ]; then
            mv ${OVERRIDE_CONFIG_DIR}/${level} ${BACKUP_CONFIG_DIR}
        fi
    done

    for level in ${DIST_LEVELS}
    do
        if [ -d ${NEW_CONFIG_DIR}/${level} ]; then
            mv ${NEW_CONFIG_DIR}/${level} ${OVERRIDE_CONFIG_DIR}
        fi
    done
}

function check_configs() {
    # check unknown config files
    echo ""
    echo "******************************************************************************"
    local unknown_dir=${OVERRIDE_CONFIG_DIR}/UNKNOWN
    if [ -d ${unknown_dir} ] && [ -n "$(ls ${unknown_dir})" ]; then
        echo "There are some UNKNOWN level's new configs."
        echo ""
        ls ${unknown_dir}
        echo ""
        echo "Need to classify above configs manually !!!"
        echo "See: ${unknown_dir}"
        echo "HINT: \`make dist-configs-move\` can help you."
        echo "eg: make dist-configs-move C=CONFIG_CAN* L=L2"
    else
        echo ""
        echo "Congratulations, all configs has a determined level."
        echo "**DO NOT FORGET** to add changelogs if any config is changed"
        rm -rf ${BACKUP_CONFIG_DIR}
    fi
    echo ""
    echo "******************************************************************************"
    echo ""
}

prepare_env
if [ -z "$DO_IMPORT_CONFIGS" ]; then
    prepare_old_configs
else
    import_old_configs
fi
refresh_old_configs
split_new_configs
replace_with_new_configs
check_configs
