/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_QUEUE_OCC_H__
#define __PIF_PLUGIN_QUEUE_OCC_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* queue_occ (4B) */
struct pif_plugin_queue_occ {
    unsigned int int_queue_occ:32;
};

/* queue_occ field accessor macros */
#define PIF_HEADER_GET_queue_occ___int_queue_occ(_hdr_p) (((_hdr_p)->int_queue_occ)) /* queue_occ.int_queue_occ [32;0] */

#define PIF_HEADER_SET_queue_occ___int_queue_occ(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_queue_occ = (unsigned)(((_val))); \
    } while (0) /* queue_occ.int_queue_occ[32;0] */



#define PIF_PLUGIN_queue_occ_T __lmem struct pif_plugin_queue_occ

/*
 * Access function prototypes
 */

int pif_plugin_hdr_queue_occ_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_queue_occ_T *pif_plugin_hdr_get_queue_occ(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_queue_occ_T *pif_plugin_hdr_readonly_get_queue_occ(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_queue_occ_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_queue_occ_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_queue_occ_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_queue_occ_VALID(_ctl);
}

__forceinline PIF_PLUGIN_queue_occ_T *pif_plugin_hdr_get_queue_occ(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_queue_occ_DIRTY(_ctl);
    return (PIF_PLUGIN_queue_occ_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_queue_occ_OFF_LW);
}

__forceinline PIF_PLUGIN_queue_occ_T *pif_plugin_hdr_readonly_get_queue_occ(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_queue_occ_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_queue_occ_OFF_LW);
}

__forceinline int pif_plugin_hdr_queue_occ_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T14_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_queue_occ_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_queue_occ_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_QUEUE_OCC_H__ */
