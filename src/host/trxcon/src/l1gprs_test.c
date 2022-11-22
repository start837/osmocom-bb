/*
 * MS side L1 GPRS implementation (testing gate)
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/gsmtap.h>

#include <osmocom/bb/trxcon/l1ctl_server.h>
#include <osmocom/bb/trxcon/l1ctl_proto.h>
#include <osmocom/bb/trxcon/logging.h>
#include <osmocom/bb/l1gprs/l1gprs.h>

#define COPYRIGHT \
	"Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>\n" \
	"License GPLv2+: GNU GPL version 2 or later " \
	"<http://gnu.org/licenses/gpl.html>\n" \
	"This is free software: you are free to change and redistribute it.\n" \
	"There is NO WARRANTY, to the extent permitted by law.\n\n"

static struct {
	const char *debug_mask;
	int daemonize;
	int quit;

	/* L1CTL specific */
	unsigned int max_clients;
	const char *bind_socket;

	/* GSMTAP specific */
	struct gsmtap_inst *gsmtap;
	const char *gsmtap_ip;
} app_data = {
	.max_clients = 1, /* only one L1CTL client by default */
	.bind_socket = "/tmp/osmocom_l2",
};

static void *tall_ctx = NULL;

static int l1ctl_rx_cb(struct l1ctl_client *l1c, struct msgb *msg)
{
	struct l1gprs_grr_inst *grr = l1c->priv;
	const struct l1ctl_hdr *l1h;

	l1h = (const struct l1ctl_hdr *)msg->l1h;

	switch (l1h->msg_type) {
	case L1CTL_DATA_IND:
	{
		const struct l1ctl_info_dl *dlh = (void *)&l1h->data[0];
		const struct l1gprs_prim_data_ind grr_ind = {
			.frame_nr = dlh->frame_nr,
			.data_len = msg->tail - dlh->payload,
			.data = &dlh->payload[0],
		};

		if (dlh->link_id == 0x00)
			l1gprs_handle_pdtch_ind(&grr->pdch[dlh->chan_nr & 0x07], &grr_ind);
		else
			l1gprs_handle_ptcch_ind(&grr->pdch[dlh->chan_nr & 0x07], &grr_ind);

		/* TODO: send over GSMTAP */
		break;
	}
	default:
		LOGP(DAPP, LOGL_ERROR, "L1CTL message 0x%02x is not supported\n", l1h->msg_type);
		break;
	}

	msgb_free(msg);
	return 0;
}

static void l1ctl_conn_accept_cb(struct l1ctl_client *l1c)
{
	struct l1gprs_grr_inst *grr;

	grr = l1gprs_grr_inst_alloc(l1c, NULL, NULL);
	if (grr == NULL) {
		LOGP(DAPP, LOGL_ERROR, "l1gprs_grr_inst_alloc() failed\n");
		l1ctl_client_conn_close(l1c);
		return;
	}

	l1c->log_prefix = talloc_asprintf(l1c, "l1c[%p]: ", l1c);
	l1c->priv = grr;
}

static void l1ctl_conn_close_cb(struct l1ctl_client *l1c)
{
	struct l1gprs_grr_inst *grr = l1c->priv;

	l1gprs_grr_inst_free(grr);
}

static void print_usage(const char *app)
{
	printf("Usage: %s\n", app);
}

static void print_help(void)
{
	printf(" Some help...\n");
	printf("  -h --help         this text\n");
	printf("  -d --debug        Change debug flags (e.g. DL1C:DSCH)\n");
	printf("  -s --socket       Listening socket for layer23 (default /tmp/osmocom_l2)\n");
	printf("  -g --gsmtap-ip    The destination IP used for GSMTAP (disabled by default)\n");
	printf("  -D --daemonize    Run as daemon\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"socket", 1, 0, 's'},
			{"gsmtap-ip", 1, 0, 'g'},
			{"daemonize", 0, 0, 'D'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "d:s:g:Dh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage(argv[0]);
			print_help();
			exit(0);
			break;
		case 'd':
			app_data.debug_mask = optarg;
			break;
		case 's':
			app_data.bind_socket = optarg;
			break;
		case 'g':
			app_data.gsmtap_ip = optarg;
			break;
		case 'D':
			app_data.daemonize = 1;
			break;
		default:
			break;
		}
	}
}

static void signal_handler(int signum)
{
	fprintf(stderr, "signal %u received\n", signum);

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		app_data.quit++;
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report_full(tall_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(tall_ctx, stderr);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	struct l1ctl_server_cfg server_cfg;
	struct l1ctl_server *server = NULL;
	int rc = 0;

	printf("%s", COPYRIGHT);
	handle_options(argc, argv);

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	/* Init talloc memory management system */
	tall_ctx = talloc_init("l1gprs_test context");
	msgb_talloc_ctx_init(tall_ctx, 0);

	/* Setup signal handlers */
	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* Init logging system */
	trxcon_logging_init(tall_ctx, app_data.debug_mask);

	/* Configure pretty logging */
	log_set_print_extended_timestamp(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_level(osmo_stderr_target, 1);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);

	/* Optional GSMTAP  */
	if (app_data.gsmtap_ip != NULL) {
		app_data.gsmtap = gsmtap_source_init(app_data.gsmtap_ip, GSMTAP_UDP_PORT, 1);
		if (!app_data.gsmtap) {
			LOGP(DAPP, LOGL_ERROR, "Failed to init GSMTAP\n");
			goto exit;
		}
		/* Suppress ICMP "destination unreachable" errors */
		gsmtap_source_add_sink(app_data.gsmtap);
	}

	/* Start the L1CTL server */
	server_cfg = (struct l1ctl_server_cfg) {
		.sock_path = app_data.bind_socket,
		.num_clients_max = app_data.max_clients,
		.conn_read_cb = &l1ctl_rx_cb,
		.conn_accept_cb = &l1ctl_conn_accept_cb,
		.conn_close_cb = &l1ctl_conn_close_cb,
	};

	server = l1ctl_server_alloc(tall_ctx, &server_cfg);
	if (server == NULL) {
		rc = EXIT_FAILURE;
		goto exit;
	}

	LOGP(DAPP, LOGL_NOTICE, "Init complete\n");

	if (app_data.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			goto exit;
		}
	}

	/* Initialize pseudo-random generator */
	srand(time(NULL));

	while (!app_data.quit)
		osmo_select_main(0);

exit:
	if (server != NULL)
		l1ctl_server_free(server);

	/* Deinitialize logging */
	log_fini();

	/**
	 * Print report for the root talloc context in order
	 * to be able to find and fix potential memory leaks.
	 */
	talloc_report_full(tall_ctx, stderr);
	talloc_free(tall_ctx);

	/* Make both Valgrind and ASAN happy */
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return rc;
}
