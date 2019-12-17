/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_C_EGRESSTIMESTAMP_H__
#define __PIF_PLUGIN_C_EGRESSTIMESTAMP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* c_egressTimestamp (8B) */
struct pif_plugin_c_egressTimestamp {
    /* int_egressTimestamp [32;32] */
    unsigned int int_egressTimestamp:32;
    /* int_egressTimestamp [32;0] */
    unsigned int __int_egressTimestamp_1:32;
};

/* c_egressTimestamp field accessor macros */
#define PIF_HEADER_GET_c_egressTimestamp___int_egressTimestamp___0(_hdr_p) (((_hdr_p)->__int_egressTimestamp_1)) /* c_egressTimestamp.int_egressTimestamp [32;0] */

#define PIF_HEADER_SET_c_egressTimestamp___int_egressTimestamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_egressTimestamp_1 = (unsigned)(((_val))); \
    } while (0) /* c_egressTimestamp.int_egressTimestamp[32;0] */

#define PIF_HEADER_GET_c_egressTimestamp___int_egressTimestamp___1(_hdr_p) (((_hdr_p)->int_egressTimestamp)) /* c_egressTimestamp.int_egressTimestamp [32;32] */

#define PIF_HEADER_SET_c_egressTimestamp___int_egressTimestamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_egressTimestamp = (unsigned)(((_val))); \
    } while (0) /* c_egressTimestamp.int_egressTimestamp[32;32] */



#define PIF_PLUGIN_c_egressTimestamp_T __lmem struct pif_plugin_c_egressTimestamp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_c_egressTimestamp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_egressTimestamp_T *pif_plugin_hdr_get_c_egressTimestamp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_egressTimestamp_T *pif_plugin_hdr_readonly_get_c_egressTimestamp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_egressTimestamp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_egressTimestamp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_c_egressTimestamp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_c_egressTimestamp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_c_egressTimestamp_T *pif_plugin_hdr_get_c_egressTimestamp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_c_egressTimestamp_DIRTY(_ctl);
    return (PIF_PLUGIN_c_egressTimestamp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_egressTimestamp_OFF_LW);
}

__forceinline PIF_PLUGIN_c_egressTimestamp_T *pif_plugin_hdr_readonly_get_c_egressTimestamp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_c_egressTimestamp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_egressTimestamp_OFF_LW);
}

__forceinline int pif_plugin_hdr_c_egressTimestamp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_c_egressTimestamp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_C_EGRESSTIMESTAMP_H__ */
