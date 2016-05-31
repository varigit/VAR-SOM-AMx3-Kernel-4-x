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

#define SA_CMDL_UPD_ENC		0x0001
#define SA_CMDL_UPD_AUTH	0x0002
#define SA_CMDL_UPD_ENC_IV	0x0004
#define SA_CMDL_UPD_AUTH_IV	0x0008
#define SA_CMDL_UPD_AUX_KEY	0x0010

/* Make 32-bit word from 4 bytes */
#define SA_MK_U32(b0, b1, b2, b3) (((b0) << 24) | ((b1) << 16) | \
				   ((b2) << 8) | (b3))

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

/* Command Label Definitions and utility functions */
struct sa_cmdl_cfg {
	int	enc1st;
	int	aalg;
	u8	enc_eng_id;
	u8	auth_eng_id;
	u8	iv_size;
	const u8 *akey;
	u16	akey_len;
};

/* Format general command label */
static int sa_format_cmdl_gen(struct sa_cmdl_cfg *cfg, u8 *cmdl,
			      struct sa_cmdl_upd_info *upd_info)
{
	u8 offset = 0;
	u32 *word_ptr = (u32 *)cmdl;
	int i;

	/* Clear the command label */
	memset(cmdl, 0, (SA_MAX_CMDL_WORDS * sizeof(u32)));

	/* Iniialize the command update structure */
	memset(upd_info, 0, sizeof(*upd_info));
	upd_info->enc_size.offset = 2;
	upd_info->enc_size.size = 2;
	upd_info->enc_offset.size = 1;
	upd_info->enc_size2.size = 4;
	upd_info->auth_size.offset = 2;
	upd_info->auth_size.size = 2;
	upd_info->auth_offset.size = 1;

	if (cfg->aalg == SA_AALG_ID_AES_XCBC) {
		/* Derive K2/K3 subkeys */
		if (sa_aes_xcbc_subkey(NULL, (u8 *)&upd_info->aux_key[0],
				       (u8 *)&upd_info->aux_key[AES_BLOCK_SIZE
				       / sizeof(u32)],
				       cfg->akey, cfg->akey_len))
			return -1;

		/*
		 * Format the key into 32bit CPU words
		 * from a big-endian stream
		 */
		for (i = 0; i < SA_MAX_AUX_DATA_WORDS; i++)
			upd_info->aux_key[i] =
				be32_to_cpu(upd_info->aux_key[i]);
	}

	if (cfg->enc1st) {
		if (cfg->enc_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_ENC;
			upd_info->enc_size.index = 0;
			upd_info->enc_offset.index = 1;

			if ((cfg->enc_eng_id == SA_ENG_ID_EM1) &&
			    (cfg->auth_eng_id == SA_ENG_ID_EM1))
				cfg->auth_eng_id = SA_ENG_ID_EM2;

			/* Encryption command label */
			if (cfg->auth_eng_id != SA_ENG_ID_NONE)
				cmdl[SA_CMDL_OFFSET_NESC] = cfg->auth_eng_id;
			else
				cmdl[SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Encryption modes requiring IV */
			if (cfg->iv_size) {
				upd_info->flags |= SA_CMDL_UPD_ENC_IV;
				upd_info->enc_iv.index =
					SA_CMDL_HEADER_SIZE_BYTES >> 2;
				upd_info->enc_iv.size = cfg->iv_size;

				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES +
					cfg->iv_size;

				cmdl[SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX2_OFFSET |
					 (cfg->iv_size >> 3));

				offset = SA_CMDL_HEADER_SIZE_BYTES +
						cfg->iv_size;
			} else {
				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset = SA_CMDL_HEADER_SIZE_BYTES;
			}
		}

		if (cfg->auth_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_AUTH;
			upd_info->auth_size.index = offset >> 2;
			upd_info->auth_offset.index =
				upd_info->auth_size.index + 1;

			cmdl[offset + SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Algorithm with subkeys */
			if ((cfg->aalg == SA_AALG_ID_AES_XCBC) ||
			    (cfg->aalg == SA_AALG_ID_CMAC)) {
				upd_info->flags |= SA_CMDL_UPD_AUX_KEY;
				upd_info->aux_key_info.index =
				(offset + SA_CMDL_HEADER_SIZE_BYTES) >> 2;

				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES + 16;
				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX1_OFFSET | (16 >> 3));

				offset += SA_CMDL_HEADER_SIZE_BYTES + 16;
			} else {
				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset += SA_CMDL_HEADER_SIZE_BYTES;
			}
		}
	} else {
		/* Auth first */
		if (cfg->auth_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_AUTH;
			upd_info->auth_size.index = 0;
			upd_info->auth_offset.index = 1;

			if ((cfg->auth_eng_id == SA_ENG_ID_EM1) &&
			    (cfg->enc_eng_id == SA_ENG_ID_EM1))
				cfg->enc_eng_id = SA_ENG_ID_EM2;

			/* Authentication command label */
			if (cfg->enc_eng_id != SA_ENG_ID_NONE)
				cmdl[SA_CMDL_OFFSET_NESC] = cfg->enc_eng_id;
			else
				cmdl[SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Algorithm with subkeys */
			if ((cfg->aalg == SA_AALG_ID_AES_XCBC) ||
			    (cfg->aalg == SA_AALG_ID_CMAC)) {
				upd_info->flags |= SA_CMDL_UPD_AUX_KEY;
				upd_info->aux_key_info.index =
					(SA_CMDL_HEADER_SIZE_BYTES) >> 2;

				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES + 16;
				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX1_OFFSET | (16 >> 3));

				offset = SA_CMDL_HEADER_SIZE_BYTES + 16;
			} else {
				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset = SA_CMDL_HEADER_SIZE_BYTES;
			}
		}

		if (cfg->enc_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_ENC;
			upd_info->enc_size.index = offset >> 2;
			upd_info->enc_offset.index =
				upd_info->enc_size.index + 1;

			cmdl[offset + SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Encryption modes requiring IV */
			if (cfg->iv_size) {
				upd_info->flags |= SA_CMDL_UPD_ENC_IV;
				upd_info->enc_iv.index =
				(offset + SA_CMDL_HEADER_SIZE_BYTES) >> 2;
				upd_info->enc_iv.size = cfg->iv_size;

				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
				SA_CMDL_HEADER_SIZE_BYTES + cfg->iv_size;

				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
				(SA_CTX_ENC_AUX2_OFFSET | (cfg->iv_size >> 3));

				offset += SA_CMDL_HEADER_SIZE_BYTES +
						cfg->iv_size;
			} else {
				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset += SA_CMDL_HEADER_SIZE_BYTES;
			}
		}
	}

	offset = roundup(offset, 8);

	for (i = 0; i < offset / 4; i++)
		word_ptr[i] = be32_to_cpu(word_ptr[i]);

	return offset;
}

/* Update Command label */
static inline void
sa_update_cmdl(struct device *dev, u8 enc_offset, u16 enc_size,	u8 *enc_iv,
	       u8 auth_offset, u16 auth_size, u8 *auth_iv, u8 aad_size,
	       u8 *aad,	struct sa_cmdl_upd_info	*upd_info, u32 *cmdl)
{
	switch (upd_info->submode) {
	case SA_MODE_GEN:
		if (likely(upd_info->flags & SA_CMDL_UPD_ENC)) {
			cmdl[upd_info->enc_size.index] &= 0xffff0000;
			cmdl[upd_info->enc_size.index] |= enc_size;
			cmdl[upd_info->enc_offset.index] &= 0x00ffffff;
			cmdl[upd_info->enc_offset.index] |=
						((u32)enc_offset << 24);

			if (likely(upd_info->flags & SA_CMDL_UPD_ENC_IV)) {
				u32 *data = &cmdl[upd_info->enc_iv.index];

				data[0] = SA_MK_U32(enc_iv[0], enc_iv[1],
						    enc_iv[2], enc_iv[3]);
				data[1] = SA_MK_U32(enc_iv[4], enc_iv[5],
						    enc_iv[6], enc_iv[7]);

				if (upd_info->enc_iv.size > 8) {
					data[2] = SA_MK_U32(enc_iv[8],
							    enc_iv[9],
							    enc_iv[10],
							    enc_iv[11]);
					data[3] = SA_MK_U32(enc_iv[12],
							    enc_iv[13],
							    enc_iv[14],
							    enc_iv[15]);
				}
			}
		}

		if (likely(upd_info->flags & SA_CMDL_UPD_AUTH)) {
			cmdl[upd_info->auth_size.index] &= 0xffff0000;
			cmdl[upd_info->auth_size.index] |= auth_size;
			cmdl[upd_info->auth_offset.index] &= 0x00ffffff;
			cmdl[upd_info->auth_offset.index] |=
					((u32)auth_offset << 24);

			if (upd_info->flags & SA_CMDL_UPD_AUTH_IV) {
				u32 *data = &cmdl[upd_info->auth_iv.index];

				data[0] = SA_MK_U32(auth_iv[0], auth_iv[1],
							auth_iv[2], auth_iv[3]);
				data[1] = SA_MK_U32(auth_iv[4], auth_iv[5],
							auth_iv[6], auth_iv[7]);

				if (upd_info->auth_iv.size > 8) {
					data[2] = SA_MK_U32(auth_iv[8],
					auth_iv[9], auth_iv[10], auth_iv[11]);
					data[3] = SA_MK_U32(auth_iv[12],
					auth_iv[13], auth_iv[14], auth_iv[15]);
				}
			}

			if (upd_info->flags & SA_CMDL_UPD_AUX_KEY) {
				int offset = (auth_size & 0xF) ? 4 : 0;

				memcpy(&cmdl[upd_info->aux_key_info.index],
				       &upd_info->aux_key[offset], 16);
			}
		}
		break;

	case SA_MODE_CCM:
	case SA_MODE_GCM:
	case SA_MODE_GMAC:
	default:
		dev_err(dev, "unsupported mode(%d)\n", upd_info->submode);
		break;
	}
}

