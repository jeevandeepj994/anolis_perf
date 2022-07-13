// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "txgbe.h"
#include "txgbe_hw.h"
#include "txgbe_type.h"

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#ifdef CONFIG_HWMON
#include <linux/hwmon.h>
#endif

#ifdef CONFIG_HWMON
/* hwmon callback functions */
static ssize_t txgbe_hwmon_show_temp(struct device __always_unused *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct hwmon_attr *txgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value;

	/* reset the temp field */
	TCALL(txgbe_attr->hw, mac.ops.get_thermal_sensor_data);

	value = txgbe_attr->sensor->temp;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t txgbe_hwmon_show_alarmthresh(struct device __always_unused *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct hwmon_attr *txgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = txgbe_attr->sensor->alarm_thresh;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t txgbe_hwmon_show_dalarmthresh(struct device __always_unused *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct hwmon_attr *txgbe_attr = container_of(attr, struct hwmon_attr,
						     dev_attr);
	unsigned int value = txgbe_attr->sensor->dalarm_thresh;

	/* display millidegree */
	value *= 1000;

	return sprintf(buf, "%u\n", value);
}

/**
 * txgbe_add_hwmon_attr - Create hwmon attr table for a hwmon sysfs file.
 * @adapter: pointer to the adapter structure
 * @type: type of sensor data to display
 *
 * For each file we want in hwmon's sysfs interface we need a device_attribute
 * This is included in our hwmon_attr struct that contains the references to
 * the data structures we need to get the data to display.
 */
static int txgbe_add_hwmon_attr(struct txgbe_adapter *adapter, int type)
{
	struct hwmon_attr *txgbe_attr;
	unsigned int n_attr;

	n_attr = adapter->txgbe_hwmon_buff->n_hwmon;
	txgbe_attr = &adapter->txgbe_hwmon_buff->hwmon_list[n_attr];

	switch (type) {
	case TXGBE_HWMON_TYPE_TEMP:
		txgbe_attr->dev_attr.show = txgbe_hwmon_show_temp;
		snprintf(txgbe_attr->name, sizeof(txgbe_attr->name),
			 "temp%u_input", 0);
		break;
	case TXGBE_HWMON_TYPE_ALARMTHRESH:
		txgbe_attr->dev_attr.show = txgbe_hwmon_show_alarmthresh;
		snprintf(txgbe_attr->name, sizeof(txgbe_attr->name),
			 "temp%u_alarmthresh", 0);
		break;
	case TXGBE_HWMON_TYPE_DALARMTHRESH:
		txgbe_attr->dev_attr.show = txgbe_hwmon_show_dalarmthresh;
		snprintf(txgbe_attr->name, sizeof(txgbe_attr->name),
			 "temp%u_dalarmthresh", 0);
		break;
	default:
		return -EPERM;
	}

	/* These always the same regardless of type */
	txgbe_attr->sensor =
		&adapter->hw.mac.thermal_sensor_data.sensor;
	txgbe_attr->hw = &adapter->hw;
	txgbe_attr->dev_attr.store = NULL;
	txgbe_attr->dev_attr.attr.mode = 0444;
	txgbe_attr->dev_attr.attr.name = txgbe_attr->name;

	sysfs_attr_init(&txgbe_attr->dev_attr.attr);

	adapter->txgbe_hwmon_buff->attrs[n_attr] = &txgbe_attr->dev_attr.attr;

	++adapter->txgbe_hwmon_buff->n_hwmon;

	return 0;
}
#endif /* CONFIG_HWMON */

static void txgbe_sysfs_del_adapter(struct txgbe_adapter __maybe_unused *adapter)
{
}

/* called from txgbe_main.c */
void txgbe_sysfs_exit(struct txgbe_adapter *adapter)
{
	txgbe_sysfs_del_adapter(adapter);
}

/* called from txgbe_main.c */
int txgbe_sysfs_init(struct txgbe_adapter *adapter)
{
	int rc = 0;
#ifdef CONFIG_HWMON
	struct hwmon_buff *txgbe_hwmon;
	struct device *hwmon_dev;

	/* Don't create thermal hwmon interface if no sensors present */
	if (TCALL(&adapter->hw, mac.ops.init_thermal_sensor_thresh))
		goto exit;

	txgbe_hwmon = devm_kzalloc(&adapter->pdev->dev, sizeof(*txgbe_hwmon),
				   GFP_KERNEL);
	if (!txgbe_hwmon) {
		rc = -ENOMEM;
		goto exit;
	}

	adapter->txgbe_hwmon_buff = txgbe_hwmon;

	/* Bail if any hwmon attr struct fails to initialize */
	rc = txgbe_add_hwmon_attr(adapter, TXGBE_HWMON_TYPE_TEMP);
	rc |= txgbe_add_hwmon_attr(adapter, TXGBE_HWMON_TYPE_ALARMTHRESH);
	rc |= txgbe_add_hwmon_attr(adapter, TXGBE_HWMON_TYPE_DALARMTHRESH);
	if (rc)
		goto exit;

	txgbe_hwmon->groups[0] = &txgbe_hwmon->group;
	txgbe_hwmon->group.attrs = txgbe_hwmon->attrs;

	hwmon_dev = devm_hwmon_device_register_with_groups(&adapter->pdev->dev,
							   "txgbe",
							   txgbe_hwmon,
							   txgbe_hwmon->groups);
	if (IS_ERR(hwmon_dev))
		rc = PTR_ERR(hwmon_dev);
#endif /* CONFIG_HWMON */

exit:
	return rc;
}
