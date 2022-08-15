#pragma once

#include <stdbool.h>
#include <stdint.h>

struct l1gprs_prim_data_ind {
	uint32_t frame_nr;
	size_t data_len;
	const uint8_t *data;
};

struct l1gprs_grr_inst;

struct l1gprs_pdch {
	bool enabled;
	uint8_t tn;	/*!< Timeslot number */

	/*! Backpointer to l1gprs_state we belong to */
	struct l1gprs_grr_inst *grr;
};

struct l1gprs_grr_inst {
	/*! PDCH state for each timeslot */
	struct l1gprs_pdch pdch[8];
	/*! Logging context (used as prefix for messages) */
	const char *log_prefix;
	/*! Some private data for API user */
	void *priv;
};

struct l1gprs_grr_inst *l1gprs_grr_inst_alloc(void *ctx, const char *log_prefix, void *priv);
void l1gprs_grr_inst_free(struct l1gprs_grr_inst *grr);

int l1gprs_pdch_enable(struct l1gprs_pdch *pdch);
int l1gprs_pdch_disable(struct l1gprs_pdch *pdch);

int l1gprs_handle_pdtch_ind(struct l1gprs_pdch *pdch,
			    const struct l1gprs_prim_data_ind *ind);
int l1gprs_handle_ptcch_ind(struct l1gprs_pdch *pdch,
			    const struct l1gprs_prim_data_ind *ind);
