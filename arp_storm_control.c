/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_rdline.h>
#include <cmdline_socket.h>

#include <dpdk_utils.h>
#include <sig_db.h>
#include <utils.h>
#include <doca_argp.h>

#include <doca_log.h>

#include "arp_storm_control_core.h"
#include "arp_storm_control_pkt.h"

DOCA_LOG_REGISTER(ARP_STORM_CONTROL);

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
	arp_sc_info->force_quit = true;
}

cmdline_parse_token_string_t cmd_quit_tok = TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed, /* function to call */
	.data = NULL,	      /* 2nd arg of func */
	.help_str = "Exit application",
	.tokens =
		{
			/* token list, NULL terminated */
			(void *)&cmd_quit_tok,
			NULL,
		},
};

struct cmd_show_entries_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t entries;
};

void
cmd_show_entries_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	arp_sc_entry_show();
}

cmdline_parse_token_string_t cmd_show_tok = TOKEN_STRING_INITIALIZER(struct cmd_show_entries_result, show, "show");

cmdline_parse_token_string_t cmd_show_entries_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_show_entries_result, entries, "entries");

cmdline_parse_inst_t cmd_show_entries = {
	.f = cmd_show_entries_parsed, /* function to call */
	.data = NULL,		      /* 2nd arg of func */
	.help_str = "show entries",
	.tokens =
		{
			/* token list, NULL terminated */
			(void *)&cmd_show_tok,
			(void *)&cmd_show_entries_tok,
			NULL,
		},
};

cmdline_parse_token_string_t cmd_show_mac_entries_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_show_entries_result, entries, "drop-entries");

void
cmd_show_mac_entries_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	arp_sc_mac_entry_show();
}

cmdline_parse_inst_t cmd_show_mac_entries = {
	.f = cmd_show_mac_entries_parsed, /* function to call */
	.data = NULL,			  /* 2nd arg of func */
	.help_str = "show drop-entries",
	.tokens =
		{
			/* token list, NULL terminated */
			(void *)&cmd_show_tok,
			(void *)&cmd_show_mac_entries_tok,
			NULL,
		},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_show_entries,
	(cmdline_parse_inst_t *)&cmd_show_mac_entries,
	NULL,
};

static int
initiate_cmdline(char *cl_shell_prompt)
{
	struct cmdline *cl;

	cl = cmdline_stdin_new(main_ctx, cl_shell_prompt);
	if (cl == NULL)
		return -1;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	return 0;
}

/*
 *  The main function, which does initialization
 *  of the rules and starts the process of ARP packets
 */
int
main(int argc, char **argv)
{
	int rc;
	pthread_t cmdline_thread;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 1,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {0},
	};

	/* init and start parsing */
	struct doca_argp_program_general_config *doca_general_config;
	struct doca_argp_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	doca_argp_init("arp_storm_control", &type_config, &arp_sc_info);
	arp_sc_register_params();
	doca_argp_start(argc, argv, &doca_general_config);

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	/* init the app */
	arp_sc_init(&dpdk_config);

	/* setup interactive CLI */
	if (arp_sc_info->interactive_mode) {
		rc = rte_ctrl_thread_create(&cmdline_thread, "cmdline_thread", NULL, (void *)initiate_cmdline,
					    "ARP_SC>> ");
		if (rc != 0)
			APP_EXIT("Thread creation failed");
	}

	/* process packets and timers in a loop */
	arp_sc_process_events();

	if (arp_sc_info->interactive_mode)
		pthread_kill(cmdline_thread, 0);

	/* closing and releasing resources */
	arp_sc_destroy();

	/* ARGP cleanup */
	doca_argp_destroy();

	return 0;
}
