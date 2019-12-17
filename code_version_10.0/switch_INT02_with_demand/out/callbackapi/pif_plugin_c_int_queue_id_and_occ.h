/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_C_INT_QUEUE_ID_AND_OCC_H__
#define __PIF_PLUGIN_C_INT_QUEUE_ID_AND_OCC_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* c_int_queue_id_and_occ (8B) */
struct pif_plugin_c_int_queue_id_and_occ {
    unsigned int int_queue_id_and_occ:32;
    unsigned int int_queue_id:16;
    unsigned int int_queue_occ:16;
};

/* c_int_queue_id_and_occ field accessor macros */
#define PIF_HEADER_GET_c_int_queue_id_and_occ___int_queue_id_and_occ(_hdr_p) (((_hdr_p)->int_queue_id_and_occ)) /* c_int_queue_id_and_occ.int_queue_id_and_occ [32;0] */

#define PIF_HEADER_SET_c_int_queue_id_and_occ___int_queue_id_and_occ(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_queue_id_and_occ = (unsigned)(((_val))); \
    } while (0) /* c_int_queue_id_and_occ.int_queue_id_and_occ[32;0] */

#define PIF_HEADER_GET_c_int_queue_id_and_occ___int_queue_id(_hdr_p) (((_hdr_p)->int_queue_id)) /* c_int_queue_id_and_occ.int_queue_id [16;0] */

#define PIF_HEADER_SET_c_int_queue_id_and_occ___int_queue_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_queue_id = (unsigned)(((_val))); \
    } while (0) /* c_int_queue_id_and_occ.int_queue_id[16;0] */

#define PIF_HEADER_GET_c_int_queue_id_and_occ___int_queue_occ(_hdr_p) (((_hdr_p)->int_queue_occ)) /* c_int_queue_id_and_occ.int_queue_occ [16;0] */

#define PIF_HEADER_SET_c_int_queue_id_and_occ___int_queue_occ(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_queue_occ = (unsigned)(((_val))); \
    } while (0) /* c_int_queue_id_and_occ.int_queue_occ[16;0] */



#define PIF_PLUGIN_c_int_queue_id_and_occ_T __lmem struct pif_plugin_c_int_queue_id_and_occ

/*
 * Access function prototypes
 */

int pif_plugin_hdr_c_int_queue_id_and_occ_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_int_queue_id_and_occ_T *pif_plugin_hdr_get_c_int_queue_id_and_occ(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_c_int_queue_id_and_occ_T *pif_plugin_hdr_readonly_get_c_int_queue_id_and_occ(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_int_queue_id_and_occ_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_c_int_queue_id_and_occ_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_c_int_queue_id_and_occ_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_c_int_queue_id_and_occ_VALID(_ctl);
}

__forceinline PIF_PLUGIN_c_int_queue_id_and_occ_T *pif_plugin_hdr_get_c_int_queue_id_and_occ(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_c_int_queue_id_and_occ_DIRTY(_ctl);
    return (PIF_PLUGIN_c_int_queue_id_and_occ_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_int_queue_id_and_occ_OFF_LW);
}

__forceinline PIF_PLUGIN_c_int_queue_id_and_occ_T *pif_plugin_hdr_readonly_get_c_int_queue_id_and_occ(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_c_int_queue_id_and_occ_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_c_int_queue_id_and_occ_OFF_LW);
}

__forceinline int pif_plugin_hdr_c_int_queue_id_and_occ_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_c_int_queue_id_and_occ_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_C_INT_QUEUE_ID_AND_OCC_H__ */
