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

#include <linux/soc/ti/knav_dma.h>
#include <linux/soc/ti/knav_qmss.h>

#include <crypto/scatterwalk.h>

#include "keystone-sa.h"
#include "keystone-sa-hlp.h"

/* Number of elements in scatterlist */
static int sg_count(struct scatterlist *sg, int len)
{
	int sg_nents = 0;

	while (sg && (len > 0)) {
		sg_nents++;
		len -= sg->length;
		sg = sg_next(sg);
	}
	return sg_nents;
}

/* buffer capacity of scatterlist */
static int sg_len(struct scatterlist *sg)
{
	int len = 0;

	while (sg) {
		len += sg->length;
		sg = sg_next(sg);
	}
	return len;
}

static inline unsigned int sa_scatterwalk_sglen(struct scatter_walk *walk)
{
	return walk->sg->offset + walk->sg->length - walk->offset;
}

static inline void *sa_scatterwalk_vaddr(struct scatter_walk *walk)
{
	return sg_virt(walk->sg) + (walk->offset - walk->sg->offset);
}

static inline void sa_scatterwalk_sgdone(struct scatter_walk *walk, size_t len)
{
	if (walk->offset >= walk->sg->offset + walk->sg->length)
		scatterwalk_start(walk, sg_next(walk->sg));
}

/* scatterwalk_copychunks() for mapped SG list */
static inline void
sa_scatterwalk_copychunks(void *buf,
			  struct scatter_walk *walk, unsigned int nbytes,
			  int out)
{
	unsigned int len_this_sg;

	for (;;) {
		len_this_sg = sa_scatterwalk_sglen(walk);

		if (len_this_sg > nbytes)
			len_this_sg = nbytes;

		if (out)
			memcpy(sa_scatterwalk_vaddr(walk), buf,
			       len_this_sg);
		else
			memcpy(buf, sa_scatterwalk_vaddr(walk),
			       len_this_sg);

		scatterwalk_advance(walk, len_this_sg);

		if (nbytes == len_this_sg)
			break;

		buf += len_this_sg;
		nbytes -= len_this_sg;

		sa_scatterwalk_sgdone(walk, len_this_sg);
	}
}

/* Copy buffer content from list of hwdesc-s to DST SG list */
static int sa_hwdesc2sg_copy(struct knav_dma_desc **hwdesc,
			     struct scatterlist *dst,
			     unsigned int src_offset, unsigned int dst_offset,
			     size_t len, int num)
{
	struct scatter_walk walk;
	int sglen, cplen;
	int j = 0;

	sglen = hwdesc[0]->desc_info & KNAV_DMA_DESC_PKT_LEN_MASK;

	if (unlikely(len + src_offset > sglen)) {
		pr_err("[%s] src len(%d) less than (%d)\n", __func__,
		       sglen, len + src_offset);
		return -1;
	}

	sglen = sg_len(dst);
	if (unlikely(len + dst_offset > sglen)) {
		pr_err("[%s] dst len(%d) less than (%d)\n", __func__,
		       sglen, len + dst_offset);
		return -1;
	}

	scatterwalk_start(&walk, dst);
	scatterwalk_advance(&walk, dst_offset);
	while ((j < num) && (len > 0)) {
		cplen = min((int)len, (int)(hwdesc[j]->buff_len - src_offset));
		if (likely(cplen)) {
			sa_scatterwalk_copychunks(((char *)hwdesc[j]->pad[0] +
						   src_offset),
						  &walk, cplen, 1);
		}
		len -= cplen;
		j++;
		src_offset = 0;
	}
	return 0;
}

static void sa_scatterwalk_copy(void *buf, struct scatterlist *sg,
				unsigned int start, unsigned int nbytes,
				int out)
{
	struct scatter_walk walk;
	unsigned int offset = 0;

	if (!nbytes)
		return;

	for (;;) {
		scatterwalk_start(&walk, sg);

		if (start < offset + sg->length)
			break;

		offset += sg->length;
		sg = sg_next(sg);
	}

	scatterwalk_advance(&walk, start - offset);
	sa_scatterwalk_copychunks(buf, &walk, nbytes, out);
}

