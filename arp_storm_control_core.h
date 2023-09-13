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

#ifndef _ARP_SC_CORE_H_
#define _ARP_SC_CORE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <doca_flow.h>
#include <offload_rules.h>

#define APP_EXIT(format, ...)                                   \
        do {                                                    \
                DOCA_LOG_ERR(format "\n", ##__VA_ARGS__);       \
                exit(1);                                        \
        } while (0)

#ifdef __cplusplus
extern "C" {
#endif

struct arp_sc_mac_entry_key {
	uint16_t port;			   /* ingress port */
	uint8_t smac[DOCA_ETHER_ADDR_LEN]; /* sender MAC */
};

struct arp_sc_mac_entry {
	struct arp_sc_mac_entry_key k;
	struct doca_flow_pipe_entry *drop_flow; /* drop flow installed in the
						 * HW */
	uint32_t ref_cnt;			/* number of dampened senders/arp_sc_entry
						 * using this SMAC */
};

struct arp_sc_entry_key {
	uint16_t port; /* ingress port */
	uint32_t sip;  /* sender-ip */
};

struct arp_sc_entry {
	struct arp_sc_entry_key k;
	uint8_t smac[DOCA_ETHER_ADDR_LEN];     /* sender MAC */
	uint32_t tx_arp_requests;	       /* number of ARP request forwarded */
	uint32_t rx_arp_requests;	       /* number of ARP requests received */
	uint32_t delta_rx_arp_requests;	       /* number of ARP requests received
						* in the last minute */
	uint64_t updated_tsc;		       /* time when the entry was last updated
						* (ArpReq was received) */
	uint64_t drop_tsc;		       /* time when the entry was dampened */
	bool drop;			       /* entry has been dampened and requests
						* will no longer be forwared by the app */
	struct arp_sc_mac_entry *drop_mac_ent; /* MAC entry used to install the
						* drop flow */
};

struct arp_sc_info {
	bool force_quit;
	bool interactive_mode; /* enable CLI for displaying entries/stats */

	uint32_t nb_ports;
	uint32_t nb_queues;

	struct rte_hash *ent_ht;      /* A hash table of ARP senders is
				       * maintained to track activity and
				       * penalize noisy senders */
	struct rte_hash *mac_ent_ht;  /* A hash table of ARP sender MAC
				       * is maintained to install drop
				       * flows for dampened senders */
	uint64_t stats_clear_period;  /* Delta ARP stats are cleared
				       * every 1 minute */
	uint64_t entry_expiry_period; /* Entry is deleted if ARP requests are
				       * not rxed for 10 minutes */
	uint64_t dampen_clear_period; /* Entry is undampened after 3 minutes */

	/* Drop pipe is the root pipe and cached per-port for subsequent cleanup */
	struct doca_flow_pipe **drop_pipes;
};

extern struct arp_sc_info *arp_sc_info;

void arp_sc_init(struct application_dpdk_config *dpdk_config);
void arp_sc_destroy();
void arp_sc_register_params(void);
void arp_sc_entry_show(void);
void arp_sc_mac_entry_show(void);
void arp_sc_entry_periodic_proc(uint64_t curr_tsc);
void arp_sc_entry_update(uint16_t port, uint32_t sip, uint8_t *smac, uint64_t curr_tsc, bool *drop);
char *arp_sc_mac_to_str(uint8_t *mac, char *buf, int buf_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ARP_SC_CORE_H_ */
