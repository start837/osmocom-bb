/*
 * OsmocomBB <-> SDR connection bridge
 *
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Vadim Yanitskiy <vyanitskiy@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gprs/rlcmac/gprs_rlcmac.h>
#include <osmocom/gprs/gprs_rlc.h>

#include <osmocom/bb/l1gprs/l1gprs.h>
#include <osmocom/bb/l1gprs/logging.h>

/* TODO: make logging category configurable */
int l1gprs_log_cat_grr = DLGLOBAL;

/* TODO: move to libosmo-gprs-rlcmac */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK		= 0x00,
	GPRS_RLCMAC_CONTROL_BLOCK	= 0x01,
	GPRS_RLCMAC_CONTROL_BLOCK_OPT	= 0x02,
	GPRS_RLCMAC_RESERVED		= 0x03,
};

struct l1gprs_grr_inst *l1gprs_grr_inst_alloc(void *ctx, const char *log_prefix, void *priv)
{
	struct l1gprs_grr_inst *grr;

	grr = talloc_zero(ctx, struct l1gprs_grr_inst);
	if (grr == NULL)
		return NULL;

	for (unsigned int tn = 0; tn < ARRAY_SIZE(grr->pdch); tn++) {
		struct l1gprs_pdch *pdch = &grr->pdch[tn];

		pdch->tn = tn;
		pdch->grr = grr;
	}

	if (log_prefix == NULL)
		grr->log_prefix = talloc_asprintf(grr, "l1gprs[0x%p]: ", grr);
	else
		grr->log_prefix = talloc_strdup(grr, log_prefix);
	grr->priv = priv;

	return grr;
}

void l1gprs_grr_inst_free(struct l1gprs_grr_inst *grr)
{
	if (grr == NULL)
		return;

	for (unsigned int tn = 0; tn < ARRAY_SIZE(grr->pdch); tn++)
		l1gprs_pdch_disable(&grr->pdch[tn]);
	talloc_free(grr);
}

int l1gprs_pdch_enable(struct l1gprs_pdch *pdch)
{
	if (pdch->enabled)
		return -EALREADY;

	pdch->enabled = true;
	return 0;
}

int l1gprs_pdch_disable(struct l1gprs_pdch *pdch)
{
	if (!pdch->enabled)
		return -EALREADY;

	pdch->enabled = false;
	return 0;
}

static void handle_pdtch_gprs_block(struct l1gprs_pdch *pdch,
				    const enum osmo_gprs_cs cs,
				    const uint8_t *data, size_t data_len)
{
	const uint8_t pt = data[0] >> 6;
	RlcMacDownlink_t *ctrl_block;
	struct bitvec *bv;

	ctrl_block = talloc_zero(pdch->grr, RlcMacDownlink_t);
	OSMO_ASSERT(ctrl_block != NULL);

	bv = bitvec_alloc(data_len, pdch->grr);
	OSMO_ASSERT(bv != NULL);
	bitvec_unpack(bv, data);

	switch (pt) {
	case GPRS_RLCMAC_CONTROL_BLOCK:
		osmo_gprs_rlcmac_decode_downlink(bv, ctrl_block);
		break;
	case GPRS_RLCMAC_DATA_BLOCK: /* TODO */
	default:
		break;
	}

	talloc_free(ctrl_block);
	talloc_free(bv);
}

int l1gprs_handle_pdtch_ind(struct l1gprs_pdch *pdch,
			    const struct l1gprs_prim_data_ind *ind)
{
	const enum osmo_gprs_cs cs = osmo_gprs_dl_cs_by_block_bytes(ind->data_len);

	if (!pdch->enabled) {
		LOGP_PDCH(pdch, LOGL_ERROR, "Rx PDTCH/D block for disabled PDCH\n");
		return -ENODEV;
	}

	switch (cs) {
	case OSMO_GPRS_CS1:
	case OSMO_GPRS_CS2:
	case OSMO_GPRS_CS3:
	case OSMO_GPRS_CS4:
		handle_pdtch_gprs_block(pdch, cs, &ind->data[0], ind->data_len);
		return 0;
	case OSMO_GPRS_CS_NONE:
		LOGP_PDCH(pdch, LOGL_ERROR,
			  "Failed to determine Coding Scheme (len=%zu)\n", ind->data_len);
		return -EINVAL;
	default:
		LOGP_PDCH(pdch, LOGL_NOTICE, "Coding Scheme %d is not supported\n", cs);
		return -ENOTSUP;
	}
}

int l1gprs_handle_ptcch_ind(struct l1gprs_pdch *pdch,
			    const struct l1gprs_prim_data_ind *ind)
{
	if (!pdch->enabled) {
		LOGP_PDCH(pdch, LOGL_ERROR, "Rx PTCCH/D block for disabled PDCH\n");
		return -ENODEV;
	}

	if (ind->data_len != GSM_MACBLOCK_LEN) {
		LOGP_PDCH(pdch, LOGL_ERROR,
			  "Rx PTCCH/D block with unexpected length=%zu (expected %u)\n",
			  ind->data_len, GSM_MACBLOCK_LEN);
		return -EINVAL;
	}

	LOGP_PDCH(pdch, LOGL_INFO, "Rx PTCCH/D block: %s\n",
		  osmo_hexdump(ind->data, ind->data_len));

	return 0;
}
