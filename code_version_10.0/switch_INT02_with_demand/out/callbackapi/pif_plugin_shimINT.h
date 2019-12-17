/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_SHIMINT_H__
#define __PIF_PLUGIN_SHIMINT_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* shimINT (4B) */
struct pif_plugin_shimINT {
    unsigned int shim_type:8;
    unsigned int shim_reserved1:8;
    unsigned int shim_length:8;
    unsigned int shim_rsvd2:8;
};

/* shimINT field accessor macros */
#define PIF_HEADER_GET_shimINT___shim_type(_hdr_p) (((_hdr_p)->shim_type)) /* shimINT.shim_type [8;0] */

#define PIF_HEADER_SET_shimINT___shim_type(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_type = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_type[8;0] */

#define PIF_HEADER_GET_shimINT___shim_reserved1(_hdr_p) (((_hdr_p)->shim_reserved1)) /* shimINT.shim_reserved1 [8;0] */

#define PIF_HEADER_SET_shimINT___shim_reserved1(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_reserved1 = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_reserved1[8;0] */

#define PIF_HEADER_GET_shimINT___shim_length(_hdr_p) (((_hdr_p)->shim_length)) /* shimINT.shim_length [8;0] */

#define PIF_HEADER_SET_shimINT___shim_length(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_length = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_length[8;0] */

#define PIF_HEADER_GET_shimINT___shim_rsvd2(_hdr_p) (((_hdr_p)->shim_rsvd2)) /* shimINT.shim_rsvd2 [8;0] */

#define PIF_HEADER_SET_shimINT___shim_rsvd2(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_rsvd2 = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_rsvd2[8;0] */



#define PIF_PLUGIN_shimINT_T __lmem struct pif_plugin_shimINT

/*
 * Access function prototypes
 */

int pif_plugin_hdr_shimINT_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_shimINT_T *pif_plugin_hdr_get_shimINT(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_shimINT_T *pif_plugin_hdr_readonly_get_shimINT(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_shimINT_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_shimINT_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_shimINT_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_shimINT_VALID(_ctl);
}

__forceinline PIF_PLUGIN_shimINT_T *pif_plugin_hdr_get_shimINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_shimINT_DIRTY(_ctl);
    return (PIF_PLUGIN_shimINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_shimINT_OFF_LW);
}

__forceinline PIF_PLUGIN_shimINT_T *pif_plugin_hdr_readonly_get_shimINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_shimINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_shimINT_OFF_LW);
}

__forceinline int pif_plugin_hdr_shimINT_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_shimINT_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (!PIF_PARREP_shimINT_VALID(_ctl))
        return -1; /* header is not present */
    PIF_PARREP_CLEAR_shimINT_VALID(_ctl);
    return 0;
}

#endif /* __PIF_PLUGIN_SHIMINT_H__ */
