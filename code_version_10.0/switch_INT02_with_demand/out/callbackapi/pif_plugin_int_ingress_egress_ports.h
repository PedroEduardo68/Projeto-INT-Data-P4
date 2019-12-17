/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_INT_INGRESS_EGRESS_PORTS_H__
#define __PIF_PLUGIN_INT_INGRESS_EGRESS_PORTS_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* int_ingress_egress_ports (4B) */
struct pif_plugin_int_ingress_egress_ports {
    unsigned int int_ingress_id:16;
    unsigned int int_egress_id:16;
};

/* int_ingress_egress_ports field accessor macros */
#define PIF_HEADER_GET_int_ingress_egress_ports___int_ingress_id(_hdr_p) (((_hdr_p)->int_ingress_id)) /* int_ingress_egress_ports.int_ingress_id [16;0] */

#define PIF_HEADER_SET_int_ingress_egress_ports___int_ingress_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_ingress_id = (unsigned)(((_val))); \
    } while (0) /* int_ingress_egress_ports.int_ingress_id[16;0] */

#define PIF_HEADER_GET_int_ingress_egress_ports___int_egress_id(_hdr_p) (((_hdr_p)->int_egress_id)) /* int_ingress_egress_ports.int_egress_id [16;0] */

#define PIF_HEADER_SET_int_ingress_egress_ports___int_egress_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_egress_id = (unsigned)(((_val))); \
    } while (0) /* int_ingress_egress_ports.int_egress_id[16;0] */



#define PIF_PLUGIN_int_ingress_egress_ports_T __lmem struct pif_plugin_int_ingress_egress_ports

/*
 * Access function prototypes
 */

int pif_plugin_hdr_int_ingress_egress_ports_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_int_ingress_egress_ports_T *pif_plugin_hdr_get_int_ingress_egress_ports(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_int_ingress_egress_ports_T *pif_plugin_hdr_readonly_get_int_ingress_egress_ports(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_int_ingress_egress_ports_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_int_ingress_egress_ports_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_int_ingress_egress_ports_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_int_ingress_egress_ports_VALID(_ctl);
}

__forceinline PIF_PLUGIN_int_ingress_egress_ports_T *pif_plugin_hdr_get_int_ingress_egress_ports(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_ctl);
    return (PIF_PLUGIN_int_ingress_egress_ports_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
}

__forceinline PIF_PLUGIN_int_ingress_egress_ports_T *pif_plugin_hdr_readonly_get_int_ingress_egress_ports(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_int_ingress_egress_ports_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
}

__forceinline int pif_plugin_hdr_int_ingress_egress_ports_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T11_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_int_ingress_egress_ports_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_int_ingress_egress_ports_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_INT_INGRESS_EGRESS_PORTS_H__ */
