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
#include <rte_arp.h>

#include <doca_flow.h>
#include <doca_log.h>

#include <doca_argp.h>
#include <dpdk_utils.h>
#include <utils.h>

#include "arp_storm_control_core.h"
#include "arp_storm_control_pkt.h"

#define ARP_SC_PERIODIC 60     /* seconds */
#define ARP_SC_PACKET_BURST 32 /* The number of packets in the rx queue */
#define ARP_OP_CODE_REQ 1

DOCA_LOG_REGISTER(ARP_STORM_CONTROL::Pkt);

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		arp_sc_info->force_quit = true;
	}
}

/* Parse the ARP request */
static int
arp_sc_parse_packet(const struct rte_mbuf *packet, uint32_t *sip, uint8_t *smac, uint16_t *op_code)
{
	struct rte_ether_hdr *eth_hdr;
	uint16_t ether_type;
	struct rte_arp_hdr *arp_hdr;
	struct rte_arp_ipv4 *arp_data;

	eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	ether_type = htonl(eth_hdr->ether_type) >> 16;

	if (ether_type != RTE_ETHER_TYPE_ARP)
		return -1;

	arp_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	arp_data = &arp_hdr->arp_data;

	*op_code = rte_be_to_cpu_16(arp_hdr->arp_opcode);
	*sip = arp_data->arp_sip;
	memcpy(smac, arp_data->arp_sha.addr_bytes, DOCA_ETHER_ADDR_LEN);

	return 0;
}

/* Handle received ARP requests */
static void
arp_sc_handle_arp_req(const struct rte_mbuf *packet, bool *drop, uint64_t curr_tsc)
{
	uint16_t op_code;
	uint32_t sip;
	uint8_t smac[DOCA_ETHER_ADDR_LEN];

	*drop = false;
	if (arp_sc_parse_packet(packet, &sip, smac, &op_code) < 0) {
		DOCA_LOG_DBG("not an ARP packet");
		return;
	}

	if (op_code != ARP_OP_CODE_REQ) {
		DOCA_LOG_DBG("not an ARP request %d", op_code);
		return;
	}

	arp_sc_entry_update(packet->port, sip, smac, curr_tsc, drop);
}

/* While application uploading and before adding offload rules for ARP packets,
 * non-ARP packets may be received to RX queues and the application will read
 * them when calling (rte_eth_rx_burst ()). Marking mode for matched packets is
 * enabled in order to classify if the received packets were already in the Rx
 * queues before adding the rules.
 *
 * This function filters packet array to include only the marked packets.
 */
static void
arp_sc_check_packets_marking(struct rte_mbuf **packets, uint16_t *packets_received)
{
	struct rte_mbuf *packet;
	uint32_t current_packet, index = 0;

	for (current_packet = 0; current_packet < *packets_received; current_packet++) {
		packet = packets[current_packet];
		if (packet->hash.fdir.hi == ARP_PACKET_MARKER) {
			/* Packet matched by one of pipe entries(rules) */
			packets[index] = packets[current_packet];
			index++;
			continue;
		}
		/* Packet didn't match by one of pipe entries(rules) */
		DOCA_LOG_DBG("Packet received before rules offload");
	}
	/* Packets array will contain marked packets in places < index */
	*packets_received = index;
}

static void
print_arp_header(const struct rte_mbuf *packet, bool rx)
{
	char sip_buf[INET_ADDRSTRLEN];
	char tip_buf[INET_ADDRSTRLEN];
	struct in_addr sip;
	struct in_addr tip;
	char tmac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	uint16_t ether_type;

	ether_type = htonl(eth_hdr->ether_type) >> 16;
	if (ether_type == RTE_ETHER_TYPE_ARP) {
		struct rte_arp_hdr *arp_hdr =
			rte_pktmbuf_mtod_offset(packet, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
		struct rte_arp_ipv4 *arp_data = &arp_hdr->arp_data;

		sip.s_addr = arp_data->arp_sip;
		tip.s_addr = arp_data->arp_tip;
		inet_ntop(AF_INET, &sip, sip_buf, sizeof(sip_buf));
		inet_ntop(AF_INET, &tip, tip_buf, sizeof(tip_buf));
		rte_ether_format_addr(smac_buf, sizeof(smac_buf), &arp_data->arp_sha);
		rte_ether_format_addr(tmac_buf, sizeof(tmac_buf), &arp_data->arp_tha);

		DOCA_LOG_DBG("%s ARP SIP=%s, SMAC=%s, DIP=%s, DMAC=%s, op-code=%u", rx ? "RX" : "TX", sip_buf, smac_buf,
			     tip_buf, tmac_buf, rte_be_to_cpu_16(arp_hdr->arp_opcode));
	} else {
		DOCA_LOG_DBG("unexpected ether_type %u", ether_type);
	}
}

static void
arp_sc_handle_rx_packets(uint16_t packets_received, struct rte_mbuf **packets, uint64_t curr_tsc)
{
	uint8_t out_port;
	uint32_t current_packet;
	uint32_t send_packet_count = 0;
	struct rte_mbuf *packet = NULL;
	bool drop;

	/* Use packet marking to ignore non-arp packets */
	arp_sc_check_packets_marking(packets, &packets_received);
	if (packets_received == 0)
		return;

	for (current_packet = 0; current_packet < packets_received; current_packet++) {
		packet = packets[current_packet];

		/* Deciding the port to send the packet to */
		out_port = packet->port ^ 1;

		/*  print arp header */
		if (doca_log_global_level_get() == DOCA_LOG_LEVEL_DEBUG)
			print_arp_header(packet, true);

		arp_sc_handle_arp_req(packet, &drop, curr_tsc);

		/* Send the packet out if the sender has not been dampened */
		if (!drop) {
			packets[send_packet_count] = packets[current_packet];
			send_packet_count++;
			print_arp_header(packet, false);
		}
	}
	/* Packet received on port-0 aer sent to port-1 and viceversa */
	if (send_packet_count > 0)
		rte_eth_tx_burst(out_port, 0, packets, send_packet_count);
}

/* Process periodic events and received packets */
void
arp_sc_process_events(void)
{
	struct rte_mbuf *packets[ARP_SC_PACKET_BURST];
	uint16_t nb_packets, queue;
	uint8_t ingress_port;
	uint64_t timer_period;
	uint64_t timer_tsc = 0, prev_tsc = 0, curr_tsc, diff_tsc;
	unsigned lcore_id;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	lcore_id = rte_lcore_id();
	/* convert seconds to cycles */
	timer_period = ARP_SC_PERIODIC * rte_get_timer_hz();

	while (!arp_sc_info->force_quit) {
		curr_tsc = rte_rdtsc();
		diff_tsc = curr_tsc - prev_tsc;
		prev_tsc = curr_tsc;
		timer_tsc += diff_tsc;

		if (unlikely(timer_tsc >= timer_period)) {
			if (lcore_id == rte_get_main_lcore()) {
				arp_sc_entry_periodic_proc(curr_tsc);
				timer_tsc = 0;
			}
		}

		for (ingress_port = 0; ingress_port < arp_sc_info->nb_ports; ingress_port++) {
			for (queue = 0; queue < arp_sc_info->nb_queues; queue++) {
				/* Get number of packets received on rx queue */
				nb_packets = rte_eth_rx_burst(ingress_port, queue, packets, ARP_SC_PACKET_BURST);

				/* Check if packets received and handle them */
				if (nb_packets)
					arp_sc_handle_rx_packets(nb_packets, packets, curr_tsc);
			}
		}
	}
}
