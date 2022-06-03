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

#ifndef _ARP_SC_PKT_H_
#define _ARP_SC_PKT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARP_PACKET_MARKER 7 /* Value for marking the matched packets */

void arp_sc_process_events();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _ARP_SC_PKT_H_ */
