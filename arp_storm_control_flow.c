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
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <bsd/string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>

#include <rte_compat.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_sft.h>

#include <doca_flow.h>
#include <doca_log.h>

#include <doca_argp.h>
#include <dpdk_utils.h>
#include <utils.h>

#include "arp_storm_control_core.h"
#include "arp_storm_control_flow.h"
#include "arp_storm_control_pkt.h"

#define SET_MAC_ADDR(addr, a, b, c, d, e, f)\
do {\
        addr[0] = a & 0xff;\
        addr[1] = b & 0xff;\
        addr[2] = c & 0xff;\
        addr[3] = d & 0xff;\
        addr[4] = e & 0xff;\
        addr[5] = f & 0xff;\
} while (0)

#define ARP_SC_MAX_COUNTERS 128
#define ARP_SC_MAX_PORT_STR_LEN 128 /* Maximal length of port name */

/* All of the flow pipes and entries are installed by a single thread */
#define ARP_SC_DROP_PIPE_Q 0
#define ARP_SC_TRAP_PIPE_Q 0
#define ARP_SC_HAIRPIN_PIPE_Q 0

#define ARP_SC_DROP_PIPE_NAME "ARP_DROP_PIPE"
#define ARP_SC_TRAP_PIPE_NAME "ARP_TRAP_PIPE"

DOCA_LOG_REGISTER(ARP_STORM_CONTROL::Flow);

__rte_unused static uint8_t bcast_mac[DOCA_ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
__rte_unused static uint8_t variable_mac[DOCA_ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/****************************************************************************
 * Three flow pipes are created and chained together -
 * drop-pipe ==(miss)==> trap-pipe ==(miss)==> hair-pin-pipe
 * 1. The hair-pin pipe is used to forward all non-ARP packets from port-0
 *    to port-1 and vice-versa.
 * 2. The trap-pipe is used to send all ARP broadcast packets to the ARM
 *    cores via HW RSS. The app then examines the packets and decides to
 *    forward or drop them.
 * 3. The drop-pipe is used to drop/dampen noisy senders in the hardware.
 ****************************************************************************/

/* Delete the flow entry from the drop pipe */
void
arp_sc_delete_drop_flow(struct doca_flow_pipe_entry *entry)
{
	__rte_unused void *user_ctx = NULL;

	DOCA_LOG_DBG("drop entry deleted");

	/* XXX - remove doca flow pipe entry
	 * API-Reference: doca_flow_pipe_rm_entry() */
	doca_flow_pipe_rm_entry(ARP_SC_DROP_PIPE_Q, NULL, entry);
}

/* Add a sender MAC to the drop flow pipe */
struct doca_flow_pipe_entry *
arp_sc_create_drop_flow(struct doca_flow_pipe *drop_pipe, uint8_t *smac)
{
	struct doca_flow_pipe_entry *entry = NULL;
	__rte_unused struct doca_flow_error err = {0};
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_monitor mon;
	struct doca_flow_fwd fw;
	__rte_unused void *user_ctx = NULL;
	__rte_unused uint32_t flags = 0;

	/* Init ARP drop pipe fields */
	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&mon, 0, sizeof(mon));
	memset(&fw, 0, sizeof(fw));

	/* Populate match -
	 * DMAC=bcast_mac, SMAC=variable_mac, eth_type=big_endian(0x806)
	 */
	/* XXX - populate match fields */
	SET_MAC_ADDR(match.in_dst_mac, bcast_mac[0], bcast_mac[1], bcast_mac[2], bcast_mac[3], bcast_mac[4], bcast_mac[5]);
	SET_MAC_ADDR(match.in_src_mac, smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	match.in_eth_type = rte_cpu_to_be_16(0x806);

	/* Count matching packets */
	mon.flags = DOCA_FLOW_MONITOR_COUNT;

	/* Populate fw -
	 * Drop matching packets */
	/* XXX - populate fwd */
	fw.type = DOCA_FLOW_FWD_DROP;
	/* Add entry to the drop pipe */
	/* XXX - add flow pipe entry using pipe_queue=ARP_SC_DROP_PIPE_Q
	 * API-Reference: doca_flow_pipe_add_entry() */
	entry = doca_flow_pipe_add_entry(ARP_SC_DROP_PIPE_Q, drop_pipe, &match, &actions, &mon, &fw, 0, NULL, &err);

	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

		arp_sc_mac_to_str(smac, smac_buf, sizeof(smac_buf));
		if (entry)
			DOCA_LOG_DBG("drop entry created for SMAC=%s", smac_buf);
		else
			DOCA_LOG_DBG("drop entry NOT created for SMAC=%s %s", smac_buf,
					err.message ? err.message : "-");
	}

	return entry;
}

/* Setup the ARP drop flow pipe */
struct doca_flow_pipe *
arp_sc_setup_drop_pipe(struct doca_flow_port *port, struct doca_flow_pipe *trap_pipe, uint16_t portid)
{
	struct doca_flow_pipe *pipe = NULL;
	struct doca_flow_error err = {0};
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_fwd fw;
	struct doca_flow_fwd miss_fw;
	struct doca_flow_pipe_cfg pipe_cfg;

	/* Init ARP drop pipe fields */
	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fw, 0, sizeof(fw));
	memset(&miss_fw, 0, sizeof(miss_fw));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	actions_array[0] = &actions;

	/* Populate pipe_cfg */
	pipe_cfg.attr.name = ARP_SC_DROP_PIPE_NAME;
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.attr.is_root = true; /* drop pipe is the root pipe */
	pipe_cfg.match = &match;
	pipe_cfg.actions = actions_array;
	pipe_cfg.port = port;

	/* Populate match -
	 * DMAC=bcast_mac, SMAC=variable_mac, eth_type=big_endian(0x806)
	 */
	/* XXX - populate match */
	/* 2-tuple Match */
	SET_MAC_ADDR(match.in_dst_mac, bcast_mac[0], bcast_mac[1], bcast_mac[2], bcast_mac[3], bcast_mac[4], bcast_mac[5]);
	SET_MAC_ADDR(match.in_src_mac, variable_mac[0], variable_mac[1], variable_mac[2], variable_mac[3], variable_mac[4], variable_mac[5]);
	match.in_eth_type = rte_cpu_to_be_16(0x806);

	/* Populate fw -
	 * Drop matching packets */
	/* XXX - populate fwd */
	/* last action if not forward action */
	fw.type = DOCA_FLOW_FWD_DROP;

	/* Populate miss_fw -
	 * Packets that don't match the entries in the drop-pipe are sent to
	 * the arp_trap_pipe
	 */
	/* XXX - populate pipe to jump to if there are no matching entries */
	/* not match any entries to forward*/
	miss_fw.type = DOCA_FLOW_FWD_PIPE;
	miss_fw.next_pipe = trap_pipe;

	/* Create DOCA flow pipe */
	/* XXX - create flow pipe
	 * API-Reference: doca_flow_pipe_create() */
	pipe = doca_flow_pipe_create(&pipe_cfg, &fw, &miss_fw, &err);

	if (pipe)
		DOCA_LOG_DBG("drop pipe created");
	else
		DOCA_LOG_DBG("drop pipe creation failed: %s",
				err.message ? err.message : "-");

	return pipe;
}

/* Setup the ARP trap flow pipe and flow entry */
struct doca_flow_pipe *
arp_sc_setup_trap_pipe(struct doca_flow_port *port, struct doca_flow_pipe *hairpin_pipe)
{
	int queue_index;
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_fwd fw, miss_fw, action_fw;
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *pipe = NULL;
	struct doca_flow_error err = {0};
	__rte_unused uint16_t rss_queues[arp_sc_info->nb_queues];
	struct doca_flow_pipe_entry *entry = NULL;
	__rte_unused struct doca_flow_monitor *mon = NULL;
	__rte_unused void *user_ctx = NULL;
	__rte_unused uint32_t flags = 0;

	/* Init ARP trap pipe fields */
	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fw, 0, sizeof(fw));
	memset(&miss_fw, 0, sizeof(miss_fw));
	memset(&action_fw, 0, sizeof(action_fw));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	actions_array[0] = &actions;

	/* Configure queues for RSS */
#define ARP_SC_TRAP_RSS_FLAGS DOCA_FLOW_RSS_IP
#define ARP_SC_TRAP_RSS_MARK ARP_PACKET_MARKER
	for (queue_index = 0; queue_index < arp_sc_info->nb_queues; queue_index++)
		rss_queues[queue_index] = queue_index;

	/* Populate pipe_cfg */
	pipe_cfg.attr.name = ARP_SC_TRAP_PIPE_NAME;
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;
	pipe_cfg.port = port;
	pipe_cfg.actions = actions_array;

	/* Populate match -
	 * DMAC=bcast_mac, eth_type=big_endian(0x806)
	 */
	/* XXX - populate match */
	/* 1-tuple match */
	/* 只看dst_mac 去過濾 */
	SET_MAC_ADDR(match.in_dst_mac, bcast_mac[0], bcast_mac[1], bcast_mac[2], bcast_mac[3], bcast_mac[4], bcast_mac[5]);
	match.in_eth_type = rte_cpu_to_be_16(0x806);

	/* Populate RSS -
	 * Send the packets to the rss_queues on the Arm cores.
	 * - Set rss_flags to ARP_SC_TRAP_RSS_FLAGS
	 * - Remember to set rss_mark to ARP_SC_TRAP_RSS_MARK so the app can easily
	 * identify the relevant packets.
	 */
	/* XXX - populate fwd */
	action_fw = DOCA_FLOW_FWD_RSS;
	action_fw.type = DOCA_FLOW_FWD_RSS;
	action_fw.rss_flags = ARP_SC_TRAP_RSS_FLAGS;
	action_fw.rss_queues = rss_queues;
    action_fw.num_of_queues = arp_sc_info->nb_queues;	

	/* Drop */
	fw.type = DOCA_FLOW_FWD_DROP;
	// fw.rss_flags = ARP_SC_TRAP_RSS_FLAGS;
	// fw.rss_queues = rss_queues;
    // fw.num_of_queues = arp_sc_info->nb_queues;
	
	/* actions - zero'ed, no packet modifications needed */
	actions.meta.mark = ARP_SC_TRAP_RSS_MARK;


	/* Populate miss_fw -
	 * Packets that don't match the entries in the drop-pipe are sent to
	 * the hairpin-pipe for port-0<=>port-1 forwarding.
	 */
	/* XXX - populate pipe to jump to if there no matching entries */
	miss_fw.type = DOCA_FLOW_FWD_PIPE;
	miss_fw.next_pipe = hairpin_pipe;

	/* Create DOCA flow pipe */
	/* XXX - create flow pipe
	 * API-Reference: doca_flow_pipe_create() */
	pipe = doca_flow_pipe_create(&pipe_cfg, &fw, &miss_fw, &err);

	if (pipe) {
		DOCA_LOG_DBG("trap pipe created");
	} else {
		DOCA_LOG_DBG("trap pipe creation failed: %s",
					err.message ? err.message : "-");
		return pipe;
	}

	/* Add HW offload ARP rule */
	/* XXX - add flow pipe entry with pipe_queue=ARP_SC_TRAP_PIPE_Q
	 * API-Reference: doca_flow_pipe_add_entry() */
	/* 如果是廣播封包  Tag RSS MARK than send to rss queue */
	entry = doca_flow_pipe_add_entry(ARP_SC_TRAP_PIPE_Q, pipe, &match, &actions, NULL, &action_fw, 0, NULL, &err);

	if (entry)
		DOCA_LOG_DBG("trap pipe entry created");
	else
		DOCA_LOG_DBG("trap pipe entry creation failed: %s",
					err.message ? err.message : "-");

	return pipe;
}

/* Setup the ARP hair pin pipe and flow enrty */
struct doca_flow_pipe *
arp_sc_setup_hairpin_pipe(struct doca_flow_port *port, uint16_t port_id)
{
	struct doca_flow_match match;
	struct doca_flow_fwd fw;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_pipe *pipe;
	struct doca_flow_error err = {0};
	struct doca_flow_pipe_entry *entry;

	/* Single wildcard entry is added to the pipe to match all packets */
	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fw, 0, sizeof(fw));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));
	actions_array[0] = &actions;

	pipe_cfg.attr.name = "HAIRPIN_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;

	/* Traffic is hairpinned port-1<=>port-2 */
	pipe_cfg.port = port;
	pipe_cfg.actions = actions_array;
	fw.type = DOCA_FLOW_FWD_PORT;
	fw.port_id = port_id ^ 1;

	pipe = doca_flow_pipe_create(&pipe_cfg, &fw, NULL, &err);
	if (pipe) {
		DOCA_LOG_DBG("hairpin pipe created");
	} else {
		DOCA_LOG_ERR("hairpin pipe creation failed: %s", err.message);
		return pipe;
	}

	entry = doca_flow_pipe_add_entry(ARP_SC_HAIRPIN_PIPE_Q, pipe, &match, &actions, NULL, NULL, 0, NULL, &err);
	if (entry)
		DOCA_LOG_DBG("hairpin pipe entry created");
	else
		DOCA_LOG_ERR("hairpin pipe entry creation failed: %s", err.message);
	return pipe;
}

/* Initialize doca flow ports */
static struct doca_flow_port *
arp_sc_port_init(struct doca_flow_port_cfg *port_cfg, uint8_t portid)
{
	char port_id_str[ARP_SC_MAX_PORT_STR_LEN];
	struct doca_flow_error err = {0};
	struct doca_flow_port *port;

	memset(port_cfg, 0, sizeof(*port_cfg));
	port_cfg->port_id = portid;
	port_cfg->type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, ARP_SC_MAX_PORT_STR_LEN, "%d", port_cfg->port_id);
	port_cfg->devargs = port_id_str;
	port = doca_flow_port_start(port_cfg, &err);
	if (port == NULL)
		APP_EXIT("failed to initialize doca flow port: %s", err.message);
	return port;
}

static void
arp_sc_close_port(uint16_t port_id)
{
	struct rte_flow_error error = {0};

	rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

int
arp_sc_flow_init(struct application_dpdk_config *dpdk_config)
{
	struct doca_flow_error err = {0};
	struct doca_flow_cfg arp_sc_flow_cfg;
	struct doca_flow_port *ports[dpdk_config->port_config.nb_ports];
	struct doca_flow_port_cfg port_cfg;
	struct doca_flow_pipe *hairpin_pipe;
	struct doca_flow_pipe *trap_pipe;
	uint16_t portid;

	memset(&arp_sc_flow_cfg, 0, sizeof(arp_sc_flow_cfg));
	arp_sc_flow_cfg.mode_args = "vnf";
	arp_sc_flow_cfg.queues = dpdk_config->port_config.nb_queues;
	arp_sc_flow_cfg.resource.nb_counters = ARP_SC_MAX_COUNTERS;

	if (doca_flow_init(&arp_sc_flow_cfg, &err) < 0) {
		DOCA_LOG_ERR("failed to init doca: %s", err.message);
		return -1;
	}
	DOCA_LOG_DBG("ARP SC DOCA flow init done");

	for (portid = 0; portid < dpdk_config->port_config.nb_ports; portid++) {
		/* Initialize doca flow port */
		ports[portid] = arp_sc_port_init(&port_cfg, portid);
	}

	/* pair the two ports together for hairpin forwarding */
	if (doca_flow_port_pair(ports[0], ports[1])) {
		DOCA_LOG_ERR("ARP SC DOCA Flow port pairing failed");
		return -1;
	}

	for (portid = 0; portid < dpdk_config->port_config.nb_ports; portid++) {
		/* Hairpin pipes for non-ARP packets */
		hairpin_pipe = arp_sc_setup_hairpin_pipe(ports[portid], portid);

		/* ARP trap pipe */
		trap_pipe = arp_sc_setup_trap_pipe(ports[portid], hairpin_pipe);

		/* drop pipe */
		arp_sc_info->drop_pipes[portid] = arp_sc_setup_drop_pipe(ports[portid], trap_pipe, portid);
	}
	DOCA_LOG_DBG("ARP SC DOCA flow init done");
	return 0;
}

void
arp_sc_flow_destroy(void)
{
	uint16_t portid;

	/* Closing ports */
	for (portid = 0; portid < arp_sc_info->nb_ports; portid++)
		arp_sc_close_port(portid);
	doca_flow_destroy();
}
