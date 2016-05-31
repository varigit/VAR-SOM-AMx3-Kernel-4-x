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
#include <linux/platform_device.h>
#include "keystone-sa-hlp.h"

struct device *sa_ks2_dev;

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

