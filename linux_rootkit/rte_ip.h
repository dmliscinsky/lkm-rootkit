/*
 * Author: Daniel Liscinsky
 */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */


#ifndef _RTE_IP_H_
#define _RTE_IP_H_


#ifdef __cplusplus
extern "C" {
#endif


struct ipv4_hdr {
	uint8_t  version_ihl;           
	uint8_t  type_of_service;       
	uint16_t total_length;          
	uint16_t packet_id;             
	uint16_t fragment_offset;       
	uint8_t  time_to_live;          
	uint8_t  next_proto_id;         
	uint16_t hdr_checksum;          
	uint32_t src_addr;              
	uint32_t dst_addr;              
} __attribute__((__packed__));

#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
								 (((b) & 0xff) << 16) | \
								 (((c) & 0xff) << 8)  | \
								 ((d) & 0xff))

#define IPV4_MAX_PKT_LEN        65535
#define IPV4_HDR_IHL_MASK       (0x0f)
#define IPV4_IHL_MULTIPLIER     (4)

/* Fragment Offset * Flags. */
#define IPV4_HDR_DF_SHIFT       14
#define IPV4_HDR_MF_SHIFT       13
#define IPV4_HDR_FO_SHIFT       3

#define IPV4_HDR_DF_FLAG        (1 << IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_MF_FLAG        (1 << IPV4_HDR_MF_SHIFT)
 
#define IPV4_HDR_OFFSET_MASK    ((1 << IPV4_HDR_MF_SHIFT) - 1)

#define IPV4_HDR_OFFSET_UNITS   8



#ifdef __cplusplus
}
#endif

#endif /* _RTE_IP_H_ */