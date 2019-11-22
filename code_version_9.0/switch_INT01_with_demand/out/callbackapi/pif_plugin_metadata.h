/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_metadata_H__
#define __PIF_PLUGIN_metadata_H__
/*
 * Access function prototypes
 */

/* get report_udp.sourcePort */
uint32_t pif_plugin_meta_get__report_udp__sourcePort(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_udp.sourcePort */
void pif_plugin_meta_set__report_udp__sourcePort(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_udp.destinationPort */
uint32_t pif_plugin_meta_get__report_udp__destinationPort(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_udp.destinationPort */
void pif_plugin_meta_set__report_udp__destinationPort(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_udp.lengthUDP */
uint32_t pif_plugin_meta_get__report_udp__lengthUDP(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_udp.lengthUDP */
void pif_plugin_meta_set__report_udp__lengthUDP(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_udp.checksum */
uint32_t pif_plugin_meta_get__report_udp__checksum(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_udp.checksum */
void pif_plugin_meta_set__report_udp__checksum(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get intrinsic_metadata.ingress_global_tstamp [32;0] */
uint32_t pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get intrinsic_metadata.ingress_global_tstamp [32;32] */
uint32_t pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set intrinsic_metadata.ingress_global_tstamp [32;0] */
void pif_plugin_meta_set__intrinsic_metadata__ingress_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set intrinsic_metadata.ingress_global_tstamp [32;32] */
void pif_plugin_meta_set__intrinsic_metadata__ingress_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get intrinsic_metadata.current_global_tstamp [32;0] */
uint32_t pif_plugin_meta_get__intrinsic_metadata__current_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get intrinsic_metadata.current_global_tstamp [32;32] */
uint32_t pif_plugin_meta_get__intrinsic_metadata__current_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set intrinsic_metadata.current_global_tstamp [32;0] */
void pif_plugin_meta_set__intrinsic_metadata__current_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set intrinsic_metadata.current_global_tstamp [32;32] */
void pif_plugin_meta_set__intrinsic_metadata__current_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ethernet.destinationAddress [32;0] */
uint32_t pif_plugin_meta_get__report_ethernet__destinationAddress__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get report_ethernet.destinationAddress [16;32] */
uint32_t pif_plugin_meta_get__report_ethernet__destinationAddress__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ethernet.destinationAddress [32;0] */
void pif_plugin_meta_set__report_ethernet__destinationAddress__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set report_ethernet.destinationAddress [16;32] */
void pif_plugin_meta_set__report_ethernet__destinationAddress__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ethernet.sourceAddress [32;0] */
uint32_t pif_plugin_meta_get__report_ethernet__sourceAddress__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get report_ethernet.sourceAddress [16;32] */
uint32_t pif_plugin_meta_get__report_ethernet__sourceAddress__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ethernet.sourceAddress [32;0] */
void pif_plugin_meta_set__report_ethernet__sourceAddress__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set report_ethernet.sourceAddress [16;32] */
void pif_plugin_meta_set__report_ethernet__sourceAddress__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ethernet.etherType */
uint32_t pif_plugin_meta_get__report_ethernet__etherType(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ethernet.etherType */
void pif_plugin_meta_set__report_ethernet__etherType(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.version */
uint32_t pif_plugin_meta_get__report_ipv4__version(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.version */
void pif_plugin_meta_set__report_ipv4__version(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.headerLength */
uint32_t pif_plugin_meta_get__report_ipv4__headerLength(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.headerLength */
void pif_plugin_meta_set__report_ipv4__headerLength(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.typeServiceDiffServ */
uint32_t pif_plugin_meta_get__report_ipv4__typeServiceDiffServ(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.typeServiceDiffServ */
void pif_plugin_meta_set__report_ipv4__typeServiceDiffServ(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.totalLength */
uint32_t pif_plugin_meta_get__report_ipv4__totalLength(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.totalLength */
void pif_plugin_meta_set__report_ipv4__totalLength(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.identification */
uint32_t pif_plugin_meta_get__report_ipv4__identification(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.identification */
void pif_plugin_meta_set__report_ipv4__identification(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.fragmentOffset */
uint32_t pif_plugin_meta_get__report_ipv4__fragmentOffset(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.fragmentOffset */
void pif_plugin_meta_set__report_ipv4__fragmentOffset(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.timeToLive */
uint32_t pif_plugin_meta_get__report_ipv4__timeToLive(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.timeToLive */
void pif_plugin_meta_set__report_ipv4__timeToLive(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.protocol */
uint32_t pif_plugin_meta_get__report_ipv4__protocol(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.protocol */
void pif_plugin_meta_set__report_ipv4__protocol(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.headerChecksum */
uint32_t pif_plugin_meta_get__report_ipv4__headerChecksum(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.headerChecksum */
void pif_plugin_meta_set__report_ipv4__headerChecksum(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.sourceAddress */
uint32_t pif_plugin_meta_get__report_ipv4__sourceAddress(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.sourceAddress */
void pif_plugin_meta_set__report_ipv4__sourceAddress(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report_ipv4.destinationAddress */
uint32_t pif_plugin_meta_get__report_ipv4__destinationAddress(EXTRACTED_HEADERS_T *extracted_headers);

/* set report_ipv4.destinationAddress */
void pif_plugin_meta_set__report_ipv4__destinationAddress(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.switch_id */
uint32_t pif_plugin_meta_get__switch_local__switch_id(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.switch_id */
void pif_plugin_meta_set__switch_local__switch_id(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.port_in */
uint32_t pif_plugin_meta_get__switch_local__port_in(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.port_in */
void pif_plugin_meta_set__switch_local__port_in(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.port_out */
uint32_t pif_plugin_meta_get__switch_local__port_out(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.port_out */
void pif_plugin_meta_set__switch_local__port_out(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.shimINTlength */
uint32_t pif_plugin_meta_get__switch_local__shimINTlength(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.shimINTlength */
void pif_plugin_meta_set__switch_local__shimINTlength(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.instruction */
uint32_t pif_plugin_meta_get__switch_local__instruction(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.instruction */
void pif_plugin_meta_set__switch_local__instruction(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.ingresststamp [32;0] */
uint32_t pif_plugin_meta_get__switch_local__ingresststamp__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get switch_local.ingresststamp [32;32] */
uint32_t pif_plugin_meta_get__switch_local__ingresststamp__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.ingresststamp [32;0] */
void pif_plugin_meta_set__switch_local__ingresststamp__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set switch_local.ingresststamp [32;32] */
void pif_plugin_meta_set__switch_local__ingresststamp__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.egresststamp [32;0] */
uint32_t pif_plugin_meta_get__switch_local__egresststamp__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get switch_local.egresststamp [32;32] */
uint32_t pif_plugin_meta_get__switch_local__egresststamp__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.egresststamp [32;0] */
void pif_plugin_meta_set__switch_local__egresststamp__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set switch_local.egresststamp [32;32] */
void pif_plugin_meta_set__switch_local__egresststamp__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_version */
uint32_t pif_plugin_meta_get__report__f_version(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_version */
void pif_plugin_meta_set__report__f_version(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_next_proto */
uint32_t pif_plugin_meta_get__report__f_next_proto(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_next_proto */
void pif_plugin_meta_set__report__f_next_proto(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_drop */
uint32_t pif_plugin_meta_get__report__f_drop(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_drop */
void pif_plugin_meta_set__report__f_drop(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_queue */
uint32_t pif_plugin_meta_get__report__f_queue(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_queue */
void pif_plugin_meta_set__report__f_queue(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_flow */
uint32_t pif_plugin_meta_get__report__f_flow(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_flow */
void pif_plugin_meta_set__report__f_flow(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_rsvd */
uint32_t pif_plugin_meta_get__report__f_rsvd(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_rsvd */
void pif_plugin_meta_set__report__f_rsvd(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_hw_id */
uint32_t pif_plugin_meta_get__report__f_hw_id(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_hw_id */
void pif_plugin_meta_set__report__f_hw_id(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_seq_num */
uint32_t pif_plugin_meta_get__report__f_seq_num(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_seq_num */
void pif_plugin_meta_set__report__f_seq_num(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report.f_ingress_ts [32;0] */
uint32_t pif_plugin_meta_get__report__f_ingress_ts__0(EXTRACTED_HEADERS_T *extracted_headers);

/* get report.f_ingress_ts [32;32] */
uint32_t pif_plugin_meta_get__report__f_ingress_ts__1(EXTRACTED_HEADERS_T *extracted_headers);

/* set report.f_ingress_ts [32;0] */
void pif_plugin_meta_set__report__f_ingress_ts__0(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* set report.f_ingress_ts [32;32] */
void pif_plugin_meta_set__report__f_ingress_ts__1(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get report._padding */
uint32_t pif_plugin_meta_get__report___padding(EXTRACTED_HEADERS_T *extracted_headers);

/* set report._padding */
void pif_plugin_meta_set__report___padding(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.clone_spec */
uint32_t pif_plugin_meta_get__standard_metadata__clone_spec(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.clone_spec */
void pif_plugin_meta_set__standard_metadata__clone_spec(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.egress_spec */
uint32_t pif_plugin_meta_get__standard_metadata__egress_spec(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.egress_spec */
void pif_plugin_meta_set__standard_metadata__egress_spec(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.egress_port */
uint32_t pif_plugin_meta_get__standard_metadata__egress_port(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.egress_port */
void pif_plugin_meta_set__standard_metadata__egress_port(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.ingress_port */
uint32_t pif_plugin_meta_get__standard_metadata__ingress_port(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.ingress_port */
void pif_plugin_meta_set__standard_metadata__ingress_port(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.packet_length */
uint32_t pif_plugin_meta_get__standard_metadata__packet_length(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.packet_length */
void pif_plugin_meta_set__standard_metadata__packet_length(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.checksum_error */
uint32_t pif_plugin_meta_get__standard_metadata__checksum_error(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.checksum_error */
void pif_plugin_meta_set__standard_metadata__checksum_error(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.egress_instance */
uint32_t pif_plugin_meta_get__standard_metadata__egress_instance(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.egress_instance */
void pif_plugin_meta_set__standard_metadata__egress_instance(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.parser_error_location */
uint32_t pif_plugin_meta_get__standard_metadata__parser_error_location(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.parser_error_location */
void pif_plugin_meta_set__standard_metadata__parser_error_location(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.instance_type */
uint32_t pif_plugin_meta_get__standard_metadata__instance_type(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.instance_type */
void pif_plugin_meta_set__standard_metadata__instance_type(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get standard_metadata.parser_status */
uint32_t pif_plugin_meta_get__standard_metadata__parser_status(EXTRACTED_HEADERS_T *extracted_headers);

/* set standard_metadata.parser_status */
void pif_plugin_meta_set__standard_metadata__parser_status(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);






/*
 * Access function implementations
 */

#include "pif_parrep.h"
#include "pif_headers.h"

__forceinline uint32_t pif_plugin_meta_get__report_udp__sourcePort(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    return PIF_HEADER_GET_report_udp___sourcePort(md);
}

__forceinline void pif_plugin_meta_set__report_udp__sourcePort(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    PIF_HEADER_SET_report_udp___sourcePort(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_udp__destinationPort(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    return PIF_HEADER_GET_report_udp___destinationPort(md);
}

__forceinline void pif_plugin_meta_set__report_udp__destinationPort(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    PIF_HEADER_SET_report_udp___destinationPort(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_udp__lengthUDP(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    return PIF_HEADER_GET_report_udp___lengthUDP(md);
}

__forceinline void pif_plugin_meta_set__report_udp__lengthUDP(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    PIF_HEADER_SET_report_udp___lengthUDP(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_udp__checksum(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    return PIF_HEADER_GET_report_udp___checksum(md);
}

__forceinline void pif_plugin_meta_set__report_udp__checksum(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_udp *md = (__lmem struct pif_header_report_udp *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
    PIF_HEADER_SET_report_udp___checksum(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    return PIF_HEADER_GET_intrinsic_metadata___ingress_global_tstamp___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    return PIF_HEADER_GET_intrinsic_metadata___ingress_global_tstamp___1(md);
}

__forceinline void pif_plugin_meta_set__intrinsic_metadata__ingress_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_HEADER_SET_intrinsic_metadata___ingress_global_tstamp___0(md, val);
}

__forceinline void pif_plugin_meta_set__intrinsic_metadata__ingress_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_HEADER_SET_intrinsic_metadata___ingress_global_tstamp___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__intrinsic_metadata__current_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    return PIF_HEADER_GET_intrinsic_metadata___current_global_tstamp___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__intrinsic_metadata__current_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    return PIF_HEADER_GET_intrinsic_metadata___current_global_tstamp___1(md);
}

__forceinline void pif_plugin_meta_set__intrinsic_metadata__current_global_tstamp__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(md, val);
}

__forceinline void pif_plugin_meta_set__intrinsic_metadata__current_global_tstamp__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_intrinsic_metadata *md = (__lmem struct pif_header_intrinsic_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ethernet__destinationAddress__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    return PIF_HEADER_GET_report_ethernet___destinationAddress___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__report_ethernet__destinationAddress__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    return PIF_HEADER_GET_report_ethernet___destinationAddress___1(md);
}

__forceinline void pif_plugin_meta_set__report_ethernet__destinationAddress__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    PIF_HEADER_SET_report_ethernet___destinationAddress___0(md, val);
}

__forceinline void pif_plugin_meta_set__report_ethernet__destinationAddress__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    PIF_HEADER_SET_report_ethernet___destinationAddress___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ethernet__sourceAddress__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    return PIF_HEADER_GET_report_ethernet___sourceAddress___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__report_ethernet__sourceAddress__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    return PIF_HEADER_GET_report_ethernet___sourceAddress___1(md);
}

__forceinline void pif_plugin_meta_set__report_ethernet__sourceAddress__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    PIF_HEADER_SET_report_ethernet___sourceAddress___0(md, val);
}

__forceinline void pif_plugin_meta_set__report_ethernet__sourceAddress__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    PIF_HEADER_SET_report_ethernet___sourceAddress___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ethernet__etherType(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    return PIF_HEADER_GET_report_ethernet___etherType(md);
}

__forceinline void pif_plugin_meta_set__report_ethernet__etherType(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ethernet *md = (__lmem struct pif_header_report_ethernet *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
    PIF_HEADER_SET_report_ethernet___etherType(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__version(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___version(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__version(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___version(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__headerLength(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___headerLength(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__headerLength(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___headerLength(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__typeServiceDiffServ(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___typeServiceDiffServ(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__typeServiceDiffServ(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___typeServiceDiffServ(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__totalLength(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___totalLength(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__totalLength(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___totalLength(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__identification(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___identification(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__identification(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___identification(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__fragmentOffset(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___fragmentOffset(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__fragmentOffset(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___fragmentOffset(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__timeToLive(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___timeToLive(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__timeToLive(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___timeToLive(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__protocol(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___protocol(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__protocol(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___protocol(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__headerChecksum(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___headerChecksum(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__headerChecksum(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___headerChecksum(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__sourceAddress(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___sourceAddress(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__sourceAddress(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___sourceAddress(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report_ipv4__destinationAddress(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    return PIF_HEADER_GET_report_ipv4___destinationAddress(md);
}

__forceinline void pif_plugin_meta_set__report_ipv4__destinationAddress(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report_ipv4 *md = (__lmem struct pif_header_report_ipv4 *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ipv4_OFF_LW);
    PIF_HEADER_SET_report_ipv4___destinationAddress(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__switch_id(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___switch_id(md);
}

__forceinline void pif_plugin_meta_set__switch_local__switch_id(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___switch_id(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__port_in(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___port_in(md);
}

__forceinline void pif_plugin_meta_set__switch_local__port_in(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___port_in(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__port_out(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___port_out(md);
}

__forceinline void pif_plugin_meta_set__switch_local__port_out(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___port_out(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__shimINTlength(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___shimINTlength(md);
}

__forceinline void pif_plugin_meta_set__switch_local__shimINTlength(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___shimINTlength(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__instruction(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___instruction(md);
}

__forceinline void pif_plugin_meta_set__switch_local__instruction(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___instruction(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__ingresststamp__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___ingresststamp___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__ingresststamp__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___ingresststamp___1(md);
}

__forceinline void pif_plugin_meta_set__switch_local__ingresststamp__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___ingresststamp___0(md, val);
}

__forceinline void pif_plugin_meta_set__switch_local__ingresststamp__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___ingresststamp___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__egresststamp__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___egresststamp___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__egresststamp__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___egresststamp___1(md);
}

__forceinline void pif_plugin_meta_set__switch_local__egresststamp__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___egresststamp___0(md, val);
}

__forceinline void pif_plugin_meta_set__switch_local__egresststamp__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___egresststamp___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_version(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_version(md);
}

__forceinline void pif_plugin_meta_set__report__f_version(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_version(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_next_proto(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_next_proto(md);
}

__forceinline void pif_plugin_meta_set__report__f_next_proto(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_next_proto(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_drop(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_drop(md);
}

__forceinline void pif_plugin_meta_set__report__f_drop(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_drop(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_queue(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_queue(md);
}

__forceinline void pif_plugin_meta_set__report__f_queue(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_queue(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_flow(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_flow(md);
}

__forceinline void pif_plugin_meta_set__report__f_flow(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_flow(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_rsvd(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_rsvd(md);
}

__forceinline void pif_plugin_meta_set__report__f_rsvd(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_rsvd(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_hw_id(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_hw_id(md);
}

__forceinline void pif_plugin_meta_set__report__f_hw_id(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_hw_id(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_seq_num(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_seq_num(md);
}

__forceinline void pif_plugin_meta_set__report__f_seq_num(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_seq_num(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_ingress_ts__0(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_ingress_ts___0(md);
}

__forceinline uint32_t pif_plugin_meta_get__report__f_ingress_ts__1(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report___f_ingress_ts___1(md);
}

__forceinline void pif_plugin_meta_set__report__f_ingress_ts__0(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_ingress_ts___0(md, val);
}

__forceinline void pif_plugin_meta_set__report__f_ingress_ts__1(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report___f_ingress_ts___1(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__report___padding(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    return PIF_HEADER_GET_report____padding(md);
}

__forceinline void pif_plugin_meta_set__report___padding(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_report *md = (__lmem struct pif_header_report *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
    PIF_HEADER_SET_report____padding(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__clone_spec(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___clone_spec(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__clone_spec(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___clone_spec(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__egress_spec(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___egress_spec(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__egress_spec(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___egress_spec(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__egress_port(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___egress_port(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__egress_port(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___egress_port(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__ingress_port(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___ingress_port(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__ingress_port(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___ingress_port(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__packet_length(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___packet_length(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__packet_length(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___packet_length(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__checksum_error(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___checksum_error(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__checksum_error(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___checksum_error(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__egress_instance(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___egress_instance(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__egress_instance(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___egress_instance(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__parser_error_location(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___parser_error_location(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__parser_error_location(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___parser_error_location(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__instance_type(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___instance_type(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__instance_type(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___instance_type(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__standard_metadata__parser_status(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    return PIF_HEADER_GET_standard_metadata___parser_status(md);
}

__forceinline void pif_plugin_meta_set__standard_metadata__parser_status(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_standard_metadata *md = (__lmem struct pif_header_standard_metadata *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_standard_metadata_OFF_LW);
    PIF_HEADER_SET_standard_metadata___parser_status(md, val);
}

#endif /* __PIF_PLUGIN_metadata_H__ */
