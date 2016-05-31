/*
 * Keystone crypto accelerator driver
 *
 * Copyright (C) 2015,2016 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors:	Sandeep Nair
 *		Vitaly Andrianov
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

#ifndef _KEYSTONE_SA_HLP_
#define _KEYSTONE_SA_HLP_

#include <linux/soc/ti/knav_dma.h>

/* Memory map of the SA register set */
struct sa_mmr_regs {
	u32 PID;
	u32 RES01;
	u32 CMD_STATUS;
	u32 RES02;
	u32 PA_FLOWID;
	u32 CDMA_FLOWID;
	u32 PA_ENG_ID;
	u32 CDMA_ENG_ID;
	u8  RSVD0[224];
	u32 CTXCACH_CTRL;
	u32 CTXCACH_SC_PTR;
	u32 CTXCACH_SC_ID;
	u32 CTXCACH_MISSCNT;
};

struct sa_regs {
	struct sa_mmr_regs mmr;
};

/* Crypto driver instance data */
struct keystone_crypto_data {
	struct platform_device	*pdev;
	struct clk		*clk;
	struct sa_regs		*regs;
	u32		tx_submit_qid;
	u32		tx_compl_qid;
	u32		rx_compl_qid;
	const char	*rx_chan_name;
	const char	*tx_chan_name;
	u32		tx_queue_depth;
	u32		rx_queue_depths[KNAV_DMA_FDQ_PER_CHAN];
	u32		rx_buffer_sizes[KNAV_DMA_FDQ_PER_CHAN];
	u32		rx_pool_size;
	u32		rx_pool_region_id;
	u32		tx_pool_size;
	u32		tx_pool_region_id;

	/* Security context data */
	u16		sc_id_start;
	u16		sc_id_end;
	u16		sc_id;
	atomic_t	rx_dma_page_cnt; /* N buf from 2nd pool available */
	atomic_t	tx_dma_desc_cnt; /* Tx DMA desc-s available */
};

extern struct device *sa_ks2_dev;

#endif /* _KEYSTONE_SA_HLP_ */
