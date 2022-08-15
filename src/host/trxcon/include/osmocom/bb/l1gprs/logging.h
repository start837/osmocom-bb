#pragma once

extern int l1gprs_log_cat_grr;

#define LOGP_GRR(grr, level, fmt, args...) \
	LOGP(l1gprs_log_cat_grr, level, "%s" fmt, \
	     (grr)->log_prefix, ## args)

#define LOGP_PDCH(pdch, level, fmt, args...) \
	LOGP_GRR((pdch->grr), level, "(PDCH-%u) " fmt, \
		 (pdch->tn), ## args)
