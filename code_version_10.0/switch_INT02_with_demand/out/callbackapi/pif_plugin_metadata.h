/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_metadata_H__
#define __PIF_PLUGIN_metadata_H__
/*
 * Access function prototypes
 */

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

/* get switch_local.ingressbyte */
uint32_t pif_plugin_meta_get__switch_local__ingressbyte(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.ingressbyte */
void pif_plugin_meta_set__switch_local__ingressbyte(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

/* get switch_local.ingresspackage */
uint32_t pif_plugin_meta_get__switch_local__ingresspackage(EXTRACTED_HEADERS_T *extracted_headers);

/* set switch_local.ingresspackage */
void pif_plugin_meta_set__switch_local__ingresspackage(EXTRACTED_HEADERS_T *extracted_headers, uint32_t val);

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

__forceinline uint32_t pif_plugin_meta_get__switch_local__ingressbyte(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___ingressbyte(md);
}

__forceinline void pif_plugin_meta_set__switch_local__ingressbyte(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___ingressbyte(md, val);
}

__forceinline uint32_t pif_plugin_meta_get__switch_local__ingresspackage(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    return PIF_HEADER_GET_switch_local___ingresspackage(md);
}

__forceinline void pif_plugin_meta_set__switch_local__ingresspackage(EXTRACTED_HEADERS_T *extracted_headers,uint32_t val)
{
    __lmem struct pif_header_switch_local *md = (__lmem struct pif_header_switch_local *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_local_OFF_LW);
    PIF_HEADER_SET_switch_local___ingresspackage(md, val);
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
