/*
 * Keystone crypto accelerator driver
 *
 * Copyright (C) 2015, 2016 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors:	Sandeep Nair
 *		Vitaly Andrianov
 *
 * Contributors:Tinku Mannan
 *		Hao Zhang
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/soc/ti/knav_dma.h>
#include "keystone-sa-hlp.h"

#define OF_PROP_READ(type, node, prop, var) \
	do { \
		ret = of_property_read_##type(node, prop, &var); \
		if (ret < 0) { \
			dev_err(dev, "missing \""prop"\" parameter\n"); \
			return -EINVAL; \
		} \
	} while (0)

#define OF_PROP_READ_U32_ARRAY(node, prop, array, size) \
	do { \
		ret = of_property_read_u32_array(node, prop, array, size); \
		if (ret < 0) { \
			dev_err(dev, "missing \""prop"\" parameter\n"); \
			return -EINVAL; \
		} \
	} while (0)

struct device *sa_ks2_dev;
static int sa_read_dtb(struct device_node *node,
		       struct keystone_crypto_data *dev_data)
{
	int i, ret = 0;
	struct device *dev = &dev_data->pdev->dev;
	u32 temp[2];

	OF_PROP_READ(string, node, "ti,tx-channel", dev_data->tx_chan_name);
	OF_PROP_READ(u32, node, "ti,tx-queue-depth", dev_data->tx_queue_depth);
	atomic_set(&dev_data->tx_dma_desc_cnt, dev_data->tx_queue_depth);
	OF_PROP_READ(u32, node, "ti,tx-submit-queue", dev_data->tx_submit_qid);
	OF_PROP_READ(u32, node, "ti,tx-completion-queue",
		     dev_data->tx_compl_qid);
	OF_PROP_READ(string, node, "ti,rx-channel", dev_data->rx_chan_name);

	OF_PROP_READ_U32_ARRAY(node, "ti,rx-queue-depth",
			       dev_data->rx_queue_depths,
			       KNAV_DMA_FDQ_PER_CHAN);

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN; i++)
		dev_dbg(dev, "rx-queue-depth[%d]= %u\n", i,
			dev_data->rx_queue_depths[i]);

	OF_PROP_READ_U32_ARRAY(node, "ti,rx-buffer-size",
			       dev_data->rx_buffer_sizes,
			       KNAV_DMA_FDQ_PER_CHAN);

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN; i++)
		dev_dbg(dev, "rx-buffer-size[%d]= %u\n", i,
			dev_data->rx_buffer_sizes[i]);

	atomic_set(&dev_data->rx_dma_page_cnt, 0);

	OF_PROP_READ(u32, node, "ti,rx-compl-queue", dev_data->rx_compl_qid);

	OF_PROP_READ_U32_ARRAY(node, "ti,tx-pool", temp, 2);
	dev_data->tx_pool_size = temp[0];
	dev_data->tx_pool_region_id = temp[1];

	OF_PROP_READ_U32_ARRAY(node, "ti,rx-pool", temp, 2);
	dev_data->rx_pool_size = temp[0];
	dev_data->rx_pool_region_id = temp[1];

	OF_PROP_READ_U32_ARRAY(node, "ti,sc-id", temp, 2);
	dev_data->sc_id_start = temp[0];
	dev_data->sc_id_end = temp[1];
	dev_data->sc_id = dev_data->sc_id_start;

	dev_data->regs = of_iomap(node, 0);
	if (!dev_data->regs) {
		dev_err(dev, "failed to of_iomap\n");
		return -ENOMEM;
	}

	return 0;
}

static int keystone_crypto_remove(struct platform_device *pdev)
{
	struct keystone_crypto_data *dev_data = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	clk_disable_unprepare(dev_data->clk);
	clk_put(dev_data->clk);

	platform_set_drvdata(pdev, NULL);
	return 0;
}

static int keystone_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = pdev->dev.of_node;
	struct keystone_crypto_data *dev_data;
	int ret;

	sa_ks2_dev = dev;

	dev_data = devm_kzalloc(dev, sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	dev_data->pdev = pdev;
	platform_set_drvdata(pdev, dev_data);

	dev_data->clk = clk_get(dev, NULL);
	if (IS_ERR_OR_NULL(dev_data->clk)) {
		dev_err(dev, "Couldn't get clock\n");
		ret = -ENODEV;
		goto err;
	}

	ret = clk_prepare_enable(dev_data->clk);
	if (ret < 0) {
		dev_err(dev, "Couldn't enable clock\n");
		clk_put(dev_data->clk);
		ret = -ENODEV;
		goto err;
	}

	/* Read configuration from device tree */
	ret = sa_read_dtb(node, dev_data);
	if (ret) {
		dev_err(dev, "Failed to get all relevant configurations from DTB...\n");
		goto err;
	}

	dev_info(dev, "crypto accelerator enabled\n");
	return 0;

err:
	keystone_crypto_remove(pdev);
	return ret;
}

static const struct of_device_id of_match[] = {
	{ .compatible = "ti,netcp-sa-crypto", },
	{},
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver keystone_crypto_driver = {
	.probe	= keystone_crypto_probe,
	.remove	= keystone_crypto_remove,
	.driver	= {
		.name		= "keystone-crypto",
		.of_match_table	= of_match,
	},
};

module_platform_driver(keystone_crypto_driver);

MODULE_DESCRIPTION("Keystone crypto acceleration support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sandeep Nair");
MODULE_AUTHOR("Vitaly Andrianov");

