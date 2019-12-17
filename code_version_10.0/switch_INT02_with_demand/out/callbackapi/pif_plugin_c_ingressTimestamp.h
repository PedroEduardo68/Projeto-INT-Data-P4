/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_C_INGRESSTIMESTAMP_H__
#define __PIF_PLUGIN_C_INGRESSTIMESTAMP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* c_ingressTimestamp (8B) */
struct pif_plugin_c_ingressTimestamp {
    /* int_ingressTimestamp [32;32] */
    unsigned int int_ingressTimestamp:32;
    /* int_ingressTimestamp [32;0] */
    unsigned int __int_ingressTimestamp_1:32;
};

/* c_ingressTimestamp field accessor macros */
#define PIF_HEADER_GET_c_ingressTimestamp___int_ingressTimestamp___0(_hdr_p) (((_hdr_p)->__int_ingressTimestamp_1)) /* c_ingressTimestamp.int_ingressTimestamp [32;0] */

#define PIF_HEADER_SET_c_ingressTimestamp___int_ingressTimestamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_ingressTimestamp_1 = (unsigned)(((_val))); \
    } while (0) /* c_ingressTimestamp.int_ingressTimestamp[32;0] */

#define PIF_HEADER_GET_c_ingressTimestamp___int_ingressTimestamp___1(_hdr_p) (((_hdr_p)->int_ingressTimestamp)) /* c_ingressTimestamp.int_ingressTimestamp [32;32] */

#define PIF_HEADER_SET_c_ingressTimestamp___int_ingressTimestamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_ingressTimestamp = (unsigned)(((_val))); \
    } while (0) /* c_ingressTimestamp.int_ingressTimestamp[32;32] */



#define PIF_PLUGIN_c_ingressTimestamp_T __lmem struct pif_plugin_c_ingressTimestamp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_c_ingressTimestamp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_ingressTimestamp_T *pif_plugin_hdr_get_c_ingressTimestamp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_ingressTimestamp_T *pif_plugin_hdr_readonly_get_c_ingressTimestamp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_ingressTimestamp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_ingressTimestamp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_c_ingressTimestamp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_c_ingressTimestamp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_c_ingressTimestamp_T *pif_plugin_hdr_get_c_ingressTimestamp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_c_ingressTimestamp_DIRTY(_ctl);
    return (PIF_PLUGIN_c_ingressTimestamp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_ingressTimestamp_OFF_LW);
}

__forceinline PIF_PLUGIN_c_ingressTimestamp_T *pif_plugin_hdr_readonly_get_c_ingressTimestamp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_c_ingressTimestamp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_ingressTimestamp_OFF_LW);
}

__forceinline int pif_plugin_hdr_c_ingressTimestamp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_c_ingressTimestamp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_C_INGRESSTIMESTAMP_H__ */
