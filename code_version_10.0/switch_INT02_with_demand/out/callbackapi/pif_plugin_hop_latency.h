/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_HOP_LATENCY_H__
#define __PIF_PLUGIN_HOP_LATENCY_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* hop_latency (8B) */
struct pif_plugin_hop_latency {
    /* int_hop_latency [32;32] */
    unsigned int int_hop_latency:32;
    /* int_hop_latency [32;0] */
    unsigned int __int_hop_latency_1:32;
};

/* hop_latency field accessor macros */
#define PIF_HEADER_GET_hop_latency___int_hop_latency___0(_hdr_p) (((_hdr_p)->__int_hop_latency_1)) /* hop_latency.int_hop_latency [32;0] */

#define PIF_HEADER_SET_hop_latency___int_hop_latency___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_hop_latency_1 = (unsigned)(((_val))); \
    } while (0) /* hop_latency.int_hop_latency[32;0] */

#define PIF_HEADER_GET_hop_latency___int_hop_latency___1(_hdr_p) (((_hdr_p)->int_hop_latency)) /* hop_latency.int_hop_latency [32;32] */

#define PIF_HEADER_SET_hop_latency___int_hop_latency___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_hop_latency = (unsigned)(((_val))); \
    } while (0) /* hop_latency.int_hop_latency[32;32] */



#define PIF_PLUGIN_hop_latency_T __lmem struct pif_plugin_hop_latency

/*
 * Access function prototypes
 */

int pif_plugin_hdr_hop_latency_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_hop_latency_T *pif_plugin_hdr_get_hop_latency(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_hop_latency_T *pif_plugin_hdr_readonly_get_hop_latency(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_hop_latency_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_hop_latency_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_hop_latency_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_hop_latency_VALID(_ctl);
}

__forceinline PIF_PLUGIN_hop_latency_T *pif_plugin_hdr_get_hop_latency(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_hop_latency_DIRTY(_ctl);
    return (PIF_PLUGIN_hop_latency_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_hop_latency_OFF_LW);
}

__forceinline PIF_PLUGIN_hop_latency_T *pif_plugin_hdr_readonly_get_hop_latency(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_hop_latency_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_hop_latency_OFF_LW);
}

__forceinline int pif_plugin_hdr_hop_latency_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T12_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_hop_latency_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_hop_latency_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_HOP_LATENCY_H__ */
