// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright(c) 2021 Shanghai Zhaoxin Semiconductor Corporation.
 *                    All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/version.h>

#define DRIVER_VERSION "1.5.1"

#define ZX_I2C_NAME "i2c_zhaoxin"

/* REG_CR Bit fields */
#define ZXI2C_REG_CR		0x00
#define ZXI2C_CR_ENABLE			BIT(0)
#define ZXI2C_CR_RX_END			BIT(1)
#define ZXI2C_CR_TX_END			BIT(2)
#define ZXI2C_CR_END_MASK			GENMASK(2, 1)
#define ZXI2C_CR_CPU_RDY		BIT(3)
#define ZXI2C_CR_MST_RST		BIT(7)
#define ZXI2C_CR_FIFO_MODE		BIT(14)

/* REG_TCR Bit fields */
#define ZXI2C_REG_TCR		0x02
#define ZXI2C_TCR_HS_MODE		BIT(13)
#define ZXI2C_TCR_MASTER_READ	BIT(14)
#define ZXI2C_TCR_FAST			BIT(15)

/* REG_CSR Bit fields */
#define ZXI2C_REG_CSR		0x04
#define ZXI2C_CSR_RCV_NOT_ACK	BIT(0)
#define ZXI2C_CSR_READY_MASK	BIT(1)

/* REG_ISR Bit fields */
#define ZXI2C_REG_ISR		0x06
#define ZXI2C_ISR_NACK_ADDR		BIT(0)
#define ZXI2C_ISR_BYTE_END		BIT(1)
#define ZXI2C_ISR_SCL_TIMEOUT	BIT(2)
#define ZXI2C_ISR_MASK_ALL			GENMASK(2, 0)
#define ZXI2C_IRQ_FIFOEND		BIT(3)
#define ZXI2C_IRQ_FIFONACK		BIT(4)
#define ZXI2C_IRQ_MASK	(ZXI2C_ISR_MASK_ALL | ZXI2C_IRQ_FIFOEND | ZXI2C_IRQ_FIFONACK)

/* REG_IMR Bit fields */
#define ZXI2C_REG_IMR		0x08
#define ZXI2C_IMR_ADDRNACK		BIT(0)
#define ZXI2C_IMR_BYTE			BIT(1)
#define ZXI2C_IMR_SCL_TIMEOUT	BIT(2)
#define ZXI2C_IMR_ENABLE_ALL		GENMASK(2, 0)

#define ZXI2C_REG_CLK		0x10
#define ZXI2C_CLK_50M			BIT(0)
#define ZXI2C_REG_REV		0x11
#define ZXI2C_REG_HCR		0x12
#define ZXI2C_HCR_RST_FIFO			GENMASK(1, 0)
#define ZXI2C_REG_HTDR		0x13
#define ZXI2C_REG_HRDR		0x14
#define ZXI2C_REG_HTLR		0x15
#define ZXI2C_REG_HRLR		0x16
#define ZXI2C_REG_HWCNTR	0x18
#define ZXI2C_REG_HRCNTR	0x19

#define ZXI2C_REG_CDR		0x0A
#define ZXI2C_REG_TR		0x0C
#define ZXI2C_REG_MCR		0x0E

struct zxi2c {
	struct i2c_adapter adapter;
	struct completion complete;
	struct device *dev;
	void __iomem *base;
	struct clk *clk;
	u16 tcr;
	int irq;
	u16 cmd_status;
	u16 tr;
	u16 mcr;
	u16 csr;
	u8 fstp;
	u8			hrv;
};

/* parameters Constants */
#define ZXI2C_GOLD_FSTP_100K	0xF3
#define ZXI2C_GOLD_FSTP_400K	0x38
#define ZXI2C_GOLD_FSTP_1M		0x13
#define ZXI2C_GOLD_FSTP_3400K	0x37

#define ZXI2C_HS_MASTER_CODE (0x08 << 8)
#define ZXI2C_FIFO_SIZE 32

static int zxi2c_wait_bus_ready(struct zxi2c *i2c)
{
	unsigned long timeout;
	void __iomem *base = i2c->base;
	u16 tmp;

	timeout = jiffies + msecs_to_jiffies(200);
	while (!(readw(base + ZXI2C_REG_CSR) & ZXI2C_CSR_READY_MASK)) {
		if (time_after(jiffies, timeout)) {
			dev_warn(i2c->dev, "timeout waiting for bus ready\n");
			return -EBUSY;
		}
		tmp = ioread16(i2c->base + ZXI2C_REG_CR);
		iowrite16(tmp | ZXI2C_CR_END_MASK,  i2c->base + ZXI2C_REG_CR);

		msleep(20);
	}

	return 0;
}

static int zxi2c_wait_status(struct zxi2c *i2c, u8 status)
{
	unsigned long time_left;

	time_left = wait_for_completion_timeout(&i2c->complete, msecs_to_jiffies(500));
	if (time_left <= 1)
		return -ETIMEDOUT;

	if (i2c->cmd_status & status)
		return 0;

	return -EIO;
}

static irqreturn_t zxi2c_isr(int irq, void *data)
{
	struct zxi2c *i2c = data;

	/* save the status and write-clear it */
	i2c->cmd_status = readw(i2c->base + ZXI2C_REG_ISR);
	if (!i2c->cmd_status)
		return IRQ_NONE;

	writew(i2c->cmd_status, i2c->base + ZXI2C_REG_ISR);

	complete(&i2c->complete);

	return IRQ_HANDLED;
}

static int zxi2c_write(struct zxi2c *i2c, struct i2c_msg *msg, bool last)
{
	u16 val, tcr_val = i2c->tcr;
	int xfer_len = 0;
	void __iomem *base = i2c->base;

	writew(msg->buf[0] & 0xFF, base + ZXI2C_REG_CDR);
	reinit_completion(&i2c->complete);
	writew(tcr_val | msg->addr, base + ZXI2C_REG_TCR);

	while (xfer_len < msg->len) {
		int err;

		err = zxi2c_wait_status(i2c, ZXI2C_ISR_BYTE_END);
		if (err)
			return err;

		xfer_len++;

		val = readw(base + ZXI2C_REG_CSR);
		if (val & ZXI2C_CSR_RCV_NOT_ACK) {
			dev_dbg(i2c->dev, "write RCV NACK error\n");
			return -EIO;
		}

		if (msg->len == 0) {
			val = ZXI2C_CR_TX_END | ZXI2C_CR_CPU_RDY | ZXI2C_CR_ENABLE;
			writew(val, base + ZXI2C_REG_CR);
			break;
		}

		if (xfer_len == msg->len) {
			if (last)
				writeb(ZXI2C_CR_TX_END, base + ZXI2C_REG_CR);
		} else {
			writew(msg->buf[xfer_len] & 0xFF, base + ZXI2C_REG_CDR);
			writew(ZXI2C_CR_CPU_RDY | ZXI2C_CR_ENABLE, base + ZXI2C_REG_CR);
		}
	}

	return 0;
}

static int zxi2c_read(struct zxi2c *i2c, struct i2c_msg *msg, bool first)
{
	u16 val, tcr_val = i2c->tcr;
	u32 xfer_len = 0;
	void __iomem *base = i2c->base;

	val = readw(base + ZXI2C_REG_CR);
	val &= ~(ZXI2C_CR_TX_END | ZXI2C_CR_RX_END);

	if (msg->len == 1)
		val |= ZXI2C_CR_RX_END;

	writew(val, base + ZXI2C_REG_CR);

	reinit_completion(&i2c->complete);

	tcr_val |= ZXI2C_TCR_MASTER_READ | msg->addr;

	writew(tcr_val, base + ZXI2C_REG_TCR);

	if (!first) {
		val = readw(base + ZXI2C_REG_CR);
		val |= ZXI2C_CR_CPU_RDY;
		writew(val, base + ZXI2C_REG_CR);
	}

	while (xfer_len < msg->len) {
		int err;

		err = zxi2c_wait_status(i2c, ZXI2C_ISR_BYTE_END);
		if (err)
			return err;

		msg->buf[xfer_len] = readw(base + ZXI2C_REG_CDR) >> 8;
		xfer_len++;

		val = readw(base + ZXI2C_REG_CR) | ZXI2C_CR_CPU_RDY;
		if (xfer_len == msg->len - 1)
			val |= ZXI2C_CR_RX_END;
		writew(val, base + ZXI2C_REG_CR);
	}

	return 0;
}

static int zxi2c_xfer(struct i2c_adapter *adap, struct i2c_msg msgs[], int num)
{
	struct i2c_msg *msg;
	int i;
	int ret = 0;
	struct zxi2c *i2c = i2c_get_adapdata(adap);

	for (i = 0; ret >= 0 && i < num; i++) {
		msg = &msgs[i];
		if (msg->len == 0) {
			dev_dbg(i2c->dev, "zero len unsupported\n");
			return -ENODEV;
		}
		if (msg->flags & I2C_M_RD)
			ret = zxi2c_read(i2c, msg, i == 0);
		else
			ret = zxi2c_write(i2c, msg, i == (num - 1));
	}

	return (ret < 0) ? ret : i;
}

static int zxi2c_fifo_xfer(struct zxi2c *i2c, struct i2c_msg *msg)
{
	u16 xfered_len = 0;
	u16 byte_left = msg->len;
	u16 tcr_val = i2c->tcr;
	void __iomem *base = i2c->base;
	bool read = !!(msg->flags & I2C_M_RD);

	while (byte_left) {
		u16 i;
		u8 tmp;
		int error;
		u16 xfer_len = min_t(u16, byte_left, ZXI2C_FIFO_SIZE);

		byte_left -= xfer_len;

		/* reset fifo buffer */
		tmp = ioread8(base + ZXI2C_REG_HCR);
		iowrite8(tmp | ZXI2C_HCR_RST_FIFO, base + ZXI2C_REG_HCR);

		/* set xfer len */
		if (read) {
			iowrite8(xfer_len - 1, base + ZXI2C_REG_HRLR);
		} else {
			iowrite8(xfer_len - 1, base + ZXI2C_REG_HTLR);
			/* set write data */
			for (i = 0; i < xfer_len; i++)
				iowrite8(msg->buf[xfered_len + i], base + ZXI2C_REG_HTDR);
		}

		/* prepare to stop transmission */
		if (i2c->hrv && !byte_left) {
			tmp = ioread8(i2c->base + ZXI2C_REG_CR);
			tmp |= read ? ZXI2C_CR_RX_END : ZXI2C_CR_TX_END;
			iowrite8(tmp, base + ZXI2C_REG_CR);
		}

		reinit_completion(&i2c->complete);

		if (xfered_len) {
			/* continue transmission */
			tmp = ioread8(i2c->base + ZXI2C_REG_CR);
			iowrite8(tmp |= ZXI2C_CR_CPU_RDY, i2c->base + ZXI2C_REG_CR);
		} else {
			/* start transmission */
			tcr_val |= (read ? ZXI2C_TCR_MASTER_READ : 0);
			writew(tcr_val | msg->addr, base + ZXI2C_REG_TCR);
		}

		error = zxi2c_wait_status(i2c, ZXI2C_IRQ_FIFOEND);
		if (error)
			return error;

		/* get the received data */
		if (read)
			for (i = 0; i < xfer_len; i++)
				msg->buf[xfered_len + i] = ioread8(base + ZXI2C_REG_HRDR);

		xfered_len += xfer_len;
	}

	return 1;
}

static int zxi2c_master_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	u8 tmp;
	int ret;
	struct zxi2c *i2c = (struct zxi2c *)i2c_get_adapdata(adap);

	ret = zxi2c_wait_bus_ready(i2c);
	if (ret)
		return ret;

	tmp = ioread8(i2c->base + ZXI2C_REG_CR);
	tmp &= ~(ZXI2C_CR_RX_END | ZXI2C_CR_TX_END);

	if (num == 1 && msgs->len >= 2 && (i2c->hrv || msgs->len <= ZXI2C_FIFO_SIZE)) {
		/* enable fifo mode */
		iowrite16(ZXI2C_CR_FIFO_MODE | tmp, i2c->base + ZXI2C_REG_CR);
		/* clear irq status */
		iowrite8(ZXI2C_IRQ_MASK, i2c->base + ZXI2C_REG_ISR);
		/* enable fifo irq */
		iowrite8(ZXI2C_ISR_NACK_ADDR | ZXI2C_IRQ_FIFOEND, i2c->base + ZXI2C_REG_IMR);
		ret = zxi2c_fifo_xfer(i2c, msgs);
	} else {
		/* enable byte mode */
		iowrite16(tmp, i2c->base + ZXI2C_REG_CR);
		/* clear irq status */
		iowrite8(ZXI2C_IRQ_MASK, i2c->base + ZXI2C_REG_ISR);
		/* enable byte irq */
		iowrite8(ZXI2C_ISR_NACK_ADDR | ZXI2C_IMR_BYTE, i2c->base + ZXI2C_REG_IMR);
		ret = zxi2c_xfer(adap, msgs, num);
		if (ret < 0)
			iowrite16(tmp | ZXI2C_CR_END_MASK, i2c->base + ZXI2C_REG_CR);
		/* make sure the state machine is stopped */
		usleep_range(1, 2);
	}
	/* dis interrupt */
	iowrite8(0, i2c->base + ZXI2C_REG_IMR);

	/* timeout may caused by another high-priority process, try again */
	if (ret == -ETIMEDOUT)
		ret = -EAGAIN;

	return ret;
}

static u32 zxi2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm zxi2c_algorithm = {
	.master_xfer	= zxi2c_master_xfer,
	.functionality	= zxi2c_func,
};

static const struct i2c_adapter_quirks zxi2c_quirks = {
	.flags = I2C_AQ_NO_ZERO_LEN | I2C_AQ_COMB_WRITE_THEN_READ,
};

static const u32 zxi2c_speed_params_table[][3] = {
	/* speed, ZXI2C_TCR, ZXI2C_FSTP */
	{ I2C_MAX_STANDARD_MODE_FREQ, 0, ZXI2C_GOLD_FSTP_100K },
	{ I2C_MAX_FAST_MODE_FREQ, ZXI2C_TCR_FAST, ZXI2C_GOLD_FSTP_400K },
	{ I2C_MAX_FAST_MODE_PLUS_FREQ, ZXI2C_TCR_FAST, ZXI2C_GOLD_FSTP_1M },
	{ I2C_MAX_HIGH_SPEED_MODE_FREQ, ZXI2C_TCR_HS_MODE | ZXI2C_TCR_FAST,
		ZXI2C_GOLD_FSTP_3400K },
	/* never reached, keep for debug. freq src is 27M mode */
	{ I2C_MAX_STANDARD_MODE_FREQ, 0, 0x83 },
	{ I2C_MAX_FAST_MODE_FREQ, ZXI2C_TCR_FAST, 0x1e },
	{ I2C_MAX_FAST_MODE_PLUS_FREQ, ZXI2C_TCR_FAST, 10 }
};

static void zxi2c_set_bus_speed(struct zxi2c *i2c)
{
	iowrite16(i2c->tr, i2c->base + ZXI2C_REG_TR);
	iowrite8(ZXI2C_CLK_50M, i2c->base + ZXI2C_REG_CLK);
	iowrite16(i2c->mcr, i2c->base + ZXI2C_REG_MCR);
}

static void zxi2c_get_bus_speed(struct zxi2c *i2c)
{
	u8 i, count;
	u8 fstp;
	const u32 *params;

	u32 acpi_speed = i2c_acpi_find_bus_speed(i2c->dev);

	count = ARRAY_SIZE(zxi2c_speed_params_table);
	for (i = 0; i < count; i++)
		if (acpi_speed == zxi2c_speed_params_table[i][0])
			break;
	/* if not found, use 400k as default */
	i = i < count ? i : 1;

	params = zxi2c_speed_params_table[i];
	fstp = ioread8(i2c->base + ZXI2C_REG_TR);
	if (abs(fstp - params[2]) > 0x10) {
		/*
		 * if BIOS setting value far from golden value,
		 * use golden value and warn user
		 */
		dev_warn(i2c->dev, "speed:%d, fstp:0x%x, golden:0x%x\n",
				params[0], fstp, params[2]);
		i2c->tr = params[2] | 0xff00;
	} else
		i2c->tr = fstp | 0xff00;

	i2c->tcr = params[1];
	i2c->mcr = ioread16(i2c->base + ZXI2C_REG_MCR);
	/* for Hs-mode, use 0000 1000 as master code */
	if (params[0] == I2C_MAX_HIGH_SPEED_MODE_FREQ)
		i2c->mcr |= ZXI2C_HS_MASTER_CODE;

	dev_info(i2c->dev, "speed mode is %s\n", i2c_freq_mode_string(params[0]));
}

static int zxi2c_init(struct platform_device *pdev, struct zxi2c **pi2c)
{
	int err;
	struct zxi2c *i2c;
	struct resource *res;

	i2c = devm_kzalloc(&pdev->dev, sizeof(*i2c), GFP_KERNEL);
	if (!i2c)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (IS_ERR(res)) {
		dev_err(&pdev->dev, "IORESOURCE_MEM failed\n");
		return -ENODEV;
	}
	i2c->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(i2c->base))
		return PTR_ERR(i2c->base);

	i2c->irq = platform_get_irq(pdev, 0);
	if (i2c->irq < 0)
		return i2c->irq;

	err = devm_request_irq(&pdev->dev, i2c->irq, zxi2c_isr, IRQF_SHARED, pdev->name, i2c);
	if (err)
		return dev_err_probe(&pdev->dev, err, "failed to request irq %i\n", i2c->irq);

	i2c->dev = &pdev->dev;
	init_completion(&i2c->complete);
	platform_set_drvdata(pdev, i2c);

	*pi2c = i2c;
	return 0;
}

static int zxi2c_probe(struct platform_device *pdev)
{
	int error;
	struct zxi2c *i2c;
	struct i2c_adapter *adap;

	error = zxi2c_init(pdev, &i2c);
	if (error)
		return error;

	zxi2c_get_bus_speed(i2c);
	zxi2c_set_bus_speed(i2c);
	i2c->hrv = ioread8(i2c->base + ZXI2C_REG_REV);

	adap = &i2c->adapter;
	adap->owner = THIS_MODULE;
	adap->algo = &zxi2c_algorithm;
	adap->retries = 2;
	adap->quirks = &zxi2c_quirks;

	adap->dev.parent = &pdev->dev;
	ACPI_COMPANION_SET(&adap->dev, ACPI_COMPANION(&pdev->dev));
	snprintf(adap->name, sizeof(adap->name), "zhaoxin-%s-%s", dev_name(pdev->dev.parent),
			dev_name(i2c->dev));
	i2c_set_adapdata(adap, i2c);

	error = i2c_add_adapter(adap);
	if (error)
		return error;

	dev_info(i2c->dev, "adapter /dev/i2c-%d registered. version %s\n",
			adap->nr, DRIVER_VERSION);

	return 0;
}

static int zxi2c_remove(struct platform_device *pdev)
{
	struct zxi2c *i2c = platform_get_drvdata(pdev);

	devm_free_irq(&pdev->dev, i2c->irq, i2c);

	i2c_del_adapter(&i2c->adapter);

	platform_set_drvdata(pdev, NULL);

	devm_kfree(&pdev->dev, i2c);

	return 0;
}

static int zxi2c_resume(struct device *dev)
{
	struct zxi2c *i2c = dev_get_drvdata(dev);

	iowrite8(ZXI2C_CR_MST_RST, i2c->base + ZXI2C_REG_CR);
	zxi2c_set_bus_speed(i2c);

	return 0;
}

static const struct dev_pm_ops zxi2c_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(NULL, zxi2c_resume)
};

static const struct acpi_device_id zxi2c_acpi_match[] = {
	{"IIC1D17", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, zxi2c_acpi_match);

static struct platform_driver zxi2c_driver = {
	.probe = zxi2c_probe,
	.remove = zxi2c_remove,
	.driver = {
		.name = ZX_I2C_NAME,
		.acpi_match_table = ACPI_PTR(zxi2c_acpi_match),
		.pm = &zxi2c_pm,
	},
};

module_platform_driver(zxi2c_driver);

MODULE_VERSION(DRIVER_VERSION);
MODULE_AUTHOR("HansHu@zhaoxin.com");
MODULE_DESCRIPTION("Shanghai Zhaoxin IIC driver");
MODULE_LICENSE("GPL");
