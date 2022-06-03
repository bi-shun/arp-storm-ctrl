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

#ifndef _ARP_SC_FLOW_H_
#define _ARP_SC_FLOW_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <doca_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

void arp_sc_delete_drop_flow(struct doca_flow_pipe_entry *entry);
struct doca_flow_pipe_entry *arp_sc_create_drop_flow(struct doca_flow_pipe *drop_pipe, uint8_t *smac);
struct doca_flow_pipe *arp_sc_setup_drop_pipe(struct doca_flow_port *port, struct doca_flow_pipe *arp_pipe,
					      uint16_t portid);
struct doca_flow_pipe *arp_sc_setup_trap_pipe(struct doca_flow_port *port, struct doca_flow_pipe *hairpin_pipe);
struct doca_flow_pipe *arp_sc_setup_hairpin_pipe(struct doca_flow_port *port, uint16_t port_id);
int arp_sc_flow_init(struct application_dpdk_config *dpdk_config);
void arp_sc_flow_destroy(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ARP_SC_FLOW_H_ */
