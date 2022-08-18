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
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_sft.h>

#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>
#include <doca_argp.h>

#include "arp_storm_control_core.h"
#include "arp_storm_control_flow.h"
#include "arp_storm_control_pkt.h"

#define ARP_SC_EXPIRY_PERIOD \
	(10 * 60) /* an entry that is inactive for 10 \
		   * minutes is deleted */
#define ARP_SC_REQ_DAMPEN_LIMIT \
	100 /* an entry that receives more than 100 \
	     * requests per-minutes is dampened */
#define ARP_SC_DAMPEN_CLEAR_PERIOD \
	(3 * 60) /* entry is un-dampened after 3 \
		  * minutes*/

#define ARP_SC_HASH_ENTRIES 1024
#define ARP_SC_PKT_CNT_BUF 32
#define ARP_SC_ENT_FLAGS_BUF 32
#define ARP_SC_MAC_ENT_FLAGS_BUF 32

DOCA_LOG_REGISTER(ARP_STORM_CONTROL::Core);

struct arp_sc_info arp_sc_info_buf, *arp_sc_info = &arp_sc_info_buf;

static char *
arp_sc_ip_to_str(uint32_t ip, char *buf, int buf_len)
{
	struct in_addr addr;

	addr.s_addr = ip;
	inet_ntop(AF_INET, &addr, buf, buf_len);

	return buf;
}

char *
arp_sc_mac_to_str(uint8_t *mac, char *buf, int buf_len)
{
	snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

/* A hash table of sender MAC is maintained for setting up drop flows for
 * dampened senders
 */
static uint32_t
arp_sc_mac_entry_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const struct arp_sc_mac_entry_key *k;

	k = data;

	init_val = rte_jhash_1word(k->port, init_val);
	init_val = rte_jhash(k->smac, DOCA_ETHER_ADDR_LEN, init_val);

	return init_val;
}

struct rte_hash_parameters arp_sc_mac_entry_ht_params = {
	.name = "arp_sc_mac_ht",
	.entries = ARP_SC_HASH_ENTRIES,
	.key_len = sizeof(struct arp_sc_mac_entry_key),
	.hash_func = arp_sc_mac_entry_hash_crc,
	.hash_func_init_val = 0,
};

static char *
arp_sc_mac_entry_flags_to_str(struct arp_sc_mac_entry *sc_mac_ent, char *buf, int buf_len)
{
	buf[0] = '\0';
	if (sc_mac_ent->drop_flow)
		snprintf(buf + strlen(buf), buf_len - strlen(buf), "%s", "H");

	return buf;
}
void
arp_sc_mac_entry_show(void)
{
	FILE *f = stdout;
	uint32_t next = 0;
	int *key;
	struct arp_sc_mac_entry *sc_mac_ent;
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	char flags_buf[ARP_SC_MAC_ENT_FLAGS_BUF];
	struct doca_flow_query query_stats;

	fprintf(f, "Flags: H=ARP Requests dropped in HW\n");
	fprintf(f, "%4s  %18s  %10s  %5s %5s\n", "Port", "Sender-MAC", "RefCnt", "Flags", "HW-Pkts");
	while (rte_hash_iterate(arp_sc_info->mac_ent_ht, (const void **)&key, (void **)&sc_mac_ent, &next) != -ENOENT) {
		if (!sc_mac_ent)
			continue;

		arp_sc_mac_to_str(sc_mac_ent->k.smac, smac_buf, sizeof(smac_buf));
		arp_sc_mac_entry_flags_to_str(sc_mac_ent, flags_buf, sizeof(flags_buf));
		memset(&query_stats, 0, sizeof(query_stats));
		if (sc_mac_ent->drop_flow)
			doca_flow_query(sc_mac_ent->drop_flow, &query_stats);

		fprintf(f, "%4u  %18s  %10u  %5s %5" PRIu64 "\n", sc_mac_ent->k.port, smac_buf, sc_mac_ent->ref_cnt, flags_buf, query_stats.total_pkts);
	}
}
static struct arp_sc_mac_entry *
arp_sc_mac_entry_find(struct arp_sc_mac_entry_key *k)
{
	struct arp_sc_mac_entry *sc_mac_ent = NULL;

	rte_hash_lookup_data(arp_sc_info->mac_ent_ht, k, (void **)&sc_mac_ent);

	return sc_mac_ent;
}

static void
arp_sc_mac_entry_delete(struct arp_sc_mac_entry *sc_mac_ent)
{
	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

		arp_sc_mac_to_str(sc_mac_ent->k.smac, smac_buf, sizeof(smac_buf));
		DOCA_LOG_DBG("mac entry deleted, Port=%u SIP=%s", sc_mac_ent->k.port, smac_buf);
	}

	arp_sc_delete_drop_flow(sc_mac_ent->drop_flow);
	rte_hash_del_key(arp_sc_info->mac_ent_ht, &sc_mac_ent->k);
	rte_free(sc_mac_ent);
}

static struct arp_sc_mac_entry *
arp_sc_mac_entry_new(struct arp_sc_mac_entry_key *k)
{
	struct arp_sc_mac_entry *sc_mac_ent;
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

	sc_mac_ent = rte_zmalloc(NULL, sizeof(*sc_mac_ent), 0);
	memcpy(&sc_mac_ent->k, k, sizeof(sc_mac_ent->k));

	if (rte_hash_add_key_data(arp_sc_info->mac_ent_ht, &sc_mac_ent->k, sc_mac_ent) < 0) {
		free(sc_mac_ent);
		return NULL;
	}

	sc_mac_ent->drop_flow =
		arp_sc_create_drop_flow(arp_sc_info->drop_pipes[sc_mac_ent->k.port], sc_mac_ent->k.smac);
	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		arp_sc_mac_to_str(sc_mac_ent->k.smac, smac_buf, sizeof(smac_buf));
		DOCA_LOG_DBG("mac entry created, Port=%u, SMAC=%s", sc_mac_ent->k.port, smac_buf);
	}
	return sc_mac_ent;
}

static void
arp_sc_mac_entry_deref(struct arp_sc_mac_entry *sc_mac_ent)
{
	if (sc_mac_ent->ref_cnt)
		--sc_mac_ent->ref_cnt;

	/* If there are no dampened senders referencing this MAC delete it */
	if (!sc_mac_ent->ref_cnt)
		arp_sc_mac_entry_delete(sc_mac_ent);
}

static struct arp_sc_mac_entry *
arp_sc_mac_entry_ref(uint16_t port, uint8_t *smac)
{
	struct arp_sc_mac_entry *sc_mac_ent;
	struct arp_sc_mac_entry_key k;

	k.port = port;
	memcpy(k.smac, smac, DOCA_ETHER_ADDR_LEN);

	/* The MAC entry is created on first reference by a dampened sender */
	sc_mac_ent = arp_sc_mac_entry_find(&k);
	if (!sc_mac_ent)
		sc_mac_ent = arp_sc_mac_entry_new(&k);
	if (!sc_mac_ent)
		return sc_mac_ent;

	++sc_mac_ent->ref_cnt;
	return sc_mac_ent;
}

/* A hash table of ARP senders is maintained to track activity and penalize
 * noisy senders
 */
static uint32_t
arp_sc_entry_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	const struct arp_sc_entry_key *k;

	k = data;

	init_val = rte_jhash_1word(k->port, init_val);
	init_val = rte_jhash_1word(k->sip, init_val);

	return init_val;
}

struct rte_hash_parameters arp_sc_entry_ht_params = {
	.name = "arp_sc_ht",
	.entries = ARP_SC_HASH_ENTRIES,
	.key_len = sizeof(struct arp_sc_entry_key),
	.hash_func = arp_sc_entry_hash_crc,
	.hash_func_init_val = 0,
};

static char *
arp_sc_entry_flags_to_str(struct arp_sc_entry *sc_ent, char *buf, int buf_len)
{
	buf[0] = '\0';
	if (sc_ent->drop)
		snprintf(buf + strlen(buf), buf_len - strlen(buf), "%s", "D");
	if (sc_ent->drop_mac_ent && sc_ent->drop_mac_ent->drop_flow)
		snprintf(buf + strlen(buf), buf_len - strlen(buf), "%s", "H");

	return buf;
}

void
arp_sc_entry_show(void)
{
	FILE *f = stdout;
	uint32_t next = 0;
	int *key;
	struct arp_sc_entry *sc_ent;
	char sip_buf[INET_ADDRSTRLEN];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	char cnt_buf[ARP_SC_PKT_CNT_BUF];
	char flags_buf[ARP_SC_ENT_FLAGS_BUF];

	fprintf(f, "Flags: D=Dampened entry, H=ARP Requests dropped in HW\n");
	fprintf(f, "%4s  %15s  %18s  %21s  %10s  %5s\n", "Port", "Sender-IP", "Sender-MAC", "RxReqCnt", "TxReqCnt",
		"Flags");
	while (rte_hash_iterate(arp_sc_info->ent_ht, (const void **)&key, (void **)&sc_ent, &next) != -ENOENT) {
		if (!sc_ent)
			continue;

		arp_sc_ip_to_str(sc_ent->k.sip, sip_buf, sizeof(sip_buf));
		arp_sc_mac_to_str(sc_ent->smac, smac_buf, sizeof(smac_buf));
		arp_sc_entry_flags_to_str(sc_ent, flags_buf, sizeof(flags_buf));
		snprintf(cnt_buf, sizeof(cnt_buf), "%u/%u", sc_ent->rx_arp_requests, sc_ent->delta_rx_arp_requests);

		fprintf(f, "%4u  %15s  %18s  %21s  %10u  %5s\n", sc_ent->k.port, sip_buf, smac_buf, cnt_buf,
			sc_ent->tx_arp_requests, flags_buf);
	}
}

static struct arp_sc_entry *
arp_sc_entry_find(struct arp_sc_entry_key *k)
{
	struct arp_sc_entry *sc_ent = NULL;

	rte_hash_lookup_data(arp_sc_info->ent_ht, k, (void **)&sc_ent);

	return sc_ent;
}

static void
arp_sc_entry_delete(struct arp_sc_entry *sc_ent)
{
	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		char sip_buf[INET_ADDRSTRLEN];

		arp_sc_ip_to_str(sc_ent->k.sip, sip_buf, sizeof(sip_buf));
		DOCA_LOG_DBG("entry deleted, Port=%u SIP=%s", sc_ent->k.port, sip_buf);
	}

	if (sc_ent->drop_mac_ent)
		arp_sc_mac_entry_deref(sc_ent->drop_mac_ent);
	rte_hash_del_key(arp_sc_info->ent_ht, &sc_ent->k);
	rte_free(sc_ent);
}

static struct arp_sc_entry *
arp_sc_entry_new(struct arp_sc_entry_key *k, uint8_t *smac)
{
	struct arp_sc_entry *sc_ent;
	char sip_buf[INET_ADDRSTRLEN];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

	sc_ent = rte_zmalloc(NULL, sizeof(*sc_ent), 0);
	memcpy(&sc_ent->k, k, sizeof(sc_ent->k));
	memcpy(sc_ent->smac, smac, DOCA_ETHER_ADDR_LEN);

	if (rte_hash_add_key_data(arp_sc_info->ent_ht, &sc_ent->k, sc_ent) < 0) {
		free(sc_ent);
		return NULL;
	}

	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		arp_sc_ip_to_str(sc_ent->k.sip, sip_buf, sizeof(sip_buf));
		arp_sc_mac_to_str(sc_ent->smac, smac_buf, sizeof(smac_buf));
		DOCA_LOG_DBG("entry created, Port=%u, SIP=%s, SMAC=%s", sc_ent->k.port, sip_buf, smac_buf);
	}
	return sc_ent;
}

static void
arp_sc_entry_dampen_sender(struct arp_sc_entry *sc_ent, uint64_t curr_tsc)
{
	struct doca_flow_pipe *drop_pipe = arp_sc_info->drop_pipes[sc_ent->k.port];
	char sip_buf[INET_ADDRSTRLEN];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

	if (sc_ent->drop)
		return;

	sc_ent->drop = true;
	sc_ent->drop_tsc = curr_tsc;

	if (!drop_pipe)
		return;

	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		arp_sc_ip_to_str(sc_ent->k.sip, sip_buf, sizeof(sip_buf));
		arp_sc_mac_to_str(sc_ent->smac, smac_buf, sizeof(smac_buf));
		DOCA_LOG_DBG("dampen sender, Port=%u, SIP=%s, SMAC=%s", sc_ent->k.port, sip_buf, smac_buf);
	}

	sc_ent->drop_mac_ent = arp_sc_mac_entry_ref(sc_ent->k.port, sc_ent->smac);
}

static void
arp_sc_entry_undampen_sender(struct arp_sc_entry *sc_ent)
{
	char sip_buf[INET_ADDRSTRLEN];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

	if (!sc_ent->drop)
		return;

	sc_ent->drop = false;
	sc_ent->drop_tsc = 0;

	if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG) {
		arp_sc_ip_to_str(sc_ent->k.sip, sip_buf, sizeof(sip_buf));
		arp_sc_mac_to_str(sc_ent->smac, smac_buf, sizeof(smac_buf));
		DOCA_LOG_DBG("un-dampen sender, Port=%u, SIP=%s, SMAC=%s", sc_ent->k.port, sip_buf, smac_buf);
	}

	if (sc_ent->drop_mac_ent) {
		arp_sc_mac_entry_deref(sc_ent->drop_mac_ent);
		sc_ent->drop_mac_ent = NULL;
	}
}
void
arp_sc_entry_update(uint16_t port, uint32_t sip, uint8_t *smac, uint64_t curr_tsc, bool *drop)
{
	struct arp_sc_entry *sc_ent;
	struct arp_sc_entry_key k;

	memset(&k, 0, sizeof(k));
	k.port = port;
	k.sip = sip;
	sc_ent = arp_sc_entry_find(&k);
	if (sc_ent) {
		/* update SMAC */
		if (memcmp(sc_ent->smac, smac, DOCA_ETHER_ADDR_LEN)) {
			memcpy(sc_ent->smac, smac, DOCA_ETHER_ADDR_LEN);
			if (sc_ent->drop_mac_ent) {
				/* if the mac changes the old drop-ent needs to be replaced */
				arp_sc_mac_entry_deref(sc_ent->drop_mac_ent);
				sc_ent->drop_mac_ent = arp_sc_mac_entry_ref(sc_ent->k.port, sc_ent->smac);
			}
		}
	} else {
		sc_ent = arp_sc_entry_new(&k, smac);
		if (!sc_ent)
			return;
	}

	sc_ent->updated_tsc = curr_tsc;
	++sc_ent->rx_arp_requests;
	++sc_ent->delta_rx_arp_requests;

	if (sc_ent->delta_rx_arp_requests >= ARP_SC_REQ_DAMPEN_LIMIT)
		arp_sc_entry_dampen_sender(sc_ent, curr_tsc);

	if (!sc_ent->drop)
		++sc_ent->tx_arp_requests;

	*drop = sc_ent->drop;
}

static void
arp_sc_entry_expire(uint64_t curr_tsc)
{
	uint32_t next = 0;
	int *key;
	struct arp_sc_entry *sc_ent;
	uint64_t diff_tsc;

	while (rte_hash_iterate(arp_sc_info->ent_ht, (const void **)&key, (void **)&sc_ent, &next) != -ENOENT) {
		if (!sc_ent)
			continue;

		diff_tsc = curr_tsc - sc_ent->updated_tsc;
		if (unlikely(diff_tsc >= arp_sc_info->entry_expiry_period)) {
			arp_sc_entry_delete(sc_ent);
			continue;
		}
		if (sc_ent->drop) {
			if (unlikely(diff_tsc >= arp_sc_info->dampen_clear_period)) {
				arp_sc_entry_undampen_sender(sc_ent);
			}
		}
	}
}

static void
arp_sc_entry_stats_clear(void)
{
	uint32_t next = 0;
	int *key;
	struct arp_sc_entry *sc_ent;

	while (rte_hash_iterate(arp_sc_info->ent_ht, (const void **)&key, (void **)&sc_ent, &next) != -ENOENT) {
		if (!sc_ent)
			continue;

		sc_ent->delta_rx_arp_requests = 0;
	}
}

void
arp_sc_entry_periodic_proc(uint64_t curr_tsc)
{
	arp_sc_entry_stats_clear();
	arp_sc_entry_expire(curr_tsc);
}

static void
arp_sc_entry_ht_free(void)
{
	uint32_t next = 0;
	int *key;
	struct arp_sc_entry *sc_ent;

	while (rte_hash_iterate(arp_sc_info->ent_ht, (const void **)&key, (void **)&sc_ent, &next) != -ENOENT) {
		if (!sc_ent)
			continue;

		rte_free(sc_ent);
	}
	rte_hash_free(arp_sc_info->ent_ht);
}

static void
arp_sc_mac_entry_ht_free(void)
{
	uint32_t next = 0;
	int *key;
	struct arp_sc_mac_entry *sc_mac_ent;

	while (rte_hash_iterate(arp_sc_info->mac_ent_ht, (const void **)&key, (void **)&sc_mac_ent, &next) != -ENOENT) {
		if (!sc_mac_ent)
			continue;

		rte_free(sc_mac_ent);
	}
	rte_hash_free(arp_sc_info->mac_ent_ht);
}

void
arp_sc_init(struct application_dpdk_config *dpdk_config)
{
	arp_sc_info->nb_ports = dpdk_config->port_config.nb_ports;
	arp_sc_info->nb_queues = dpdk_config->port_config.nb_queues;

	/* create a hash table of ARP storm control entries */
	arp_sc_info->ent_ht = rte_hash_create(&arp_sc_entry_ht_params);

	/* create a hash table of ARP storm control MAC entries */
	arp_sc_info->mac_ent_ht = rte_hash_create(&arp_sc_mac_entry_ht_params);

	/* ARP entries are expired if there is no activity for 10 minutes */
	arp_sc_info->entry_expiry_period = ARP_SC_EXPIRY_PERIOD * rte_get_timer_hz();

	/* Dampened entries are activated for forwarding after 3 minutes */
	arp_sc_info->dampen_clear_period = ARP_SC_DAMPEN_CLEAR_PERIOD * rte_get_timer_hz();

	/* allocate memory for caching the root pipe per-port */
	arp_sc_info->drop_pipes = malloc(sizeof(struct doca_flow_pipe *) * dpdk_config->port_config.nb_ports);
	if (arp_sc_info->drop_pipes == NULL) {
		arp_sc_entry_ht_free();
		arp_sc_mac_entry_ht_free();
		APP_EXIT("failed to allocate drop pipes");
	}

	/* Initialize flows */
	if (arp_sc_flow_init(dpdk_config) < 0) {
		free(arp_sc_info->drop_pipes);
		arp_sc_entry_ht_free();
		arp_sc_mac_entry_ht_free();
		APP_EXIT("failed to initialize flows");
	}

	DOCA_LOG_DBG("ARP SC init done");
}

void
arp_sc_destroy(void)
{
	arp_sc_flow_destroy();

	if (arp_sc_info->drop_pipes != NULL)
		free(arp_sc_info->drop_pipes);

	arp_sc_entry_ht_free();
	arp_sc_mac_entry_ht_free();
}

static doca_error_t
arp_sc_interactive_callback(void *config, void *param)
{
	arp_sc_info->interactive_mode = *(bool *)param;
	return DOCA_SUCCESS;
}

void
arp_sc_register_params(void)
{
	struct doca_argp_param * interactive_param = NULL;

	int ret = doca_argp_param_create(&interactive_param);
	if (ret != DOCA_SUCCESS)
		APP_EXIT("Failed to create ARGP param: %s", doca_get_error_string(ret));

	doca_argp_param_set_short_name(interactive_param, "i");
	doca_argp_param_set_long_name(interactive_param, "interactive");
	doca_argp_param_set_description(interactive_param, "Adds interactive mode for display");
	doca_argp_param_set_callback(interactive_param, arp_sc_interactive_callback);
	doca_argp_param_set_type(interactive_param, DOCA_ARGP_TYPE_BOOLEAN);
	ret = doca_argp_register_param(interactive_param);
	if (ret != DOCA_SUCCESS)
		APP_EXIT("Failed to register program param: %s", doca_get_error_string(ret));
}
