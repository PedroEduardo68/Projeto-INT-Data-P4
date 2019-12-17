/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_SWITCH_ID_H__
#define __PIF_PLUGIN_SWITCH_ID_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* switch_id (4B) */
struct pif_plugin_switch_id {
    unsigned int int_switch_id:32;
};

/* switch_id field accessor macros */
#define PIF_HEADER_GET_switch_id___int_switch_id(_hdr_p) (((_hdr_p)->int_switch_id)) /* switch_id.int_switch_id [32;0] */

#define PIF_HEADER_SET_switch_id___int_switch_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_switch_id = (unsigned)(((_val))); \
    } while (0) /* switch_id.int_switch_id[32;0] */



#define PIF_PLUGIN_switch_id_T __lmem struct pif_plugin_switch_id

/*
 * Access function prototypes
 */

int pif_plugin_hdr_switch_id_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_switch_id_T *pif_plugin_hdr_get_switch_id(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_switch_id_T *pif_plugin_hdr_readonly_get_switch_id(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_switch_id_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_switch_id_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_switch_id_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_switch_id_VALID(_ctl);
}

__forceinline PIF_PLUGIN_switch_id_T *pif_plugin_hdr_get_switch_id(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_switch_id_DIRTY(_ctl);
    return (PIF_PLUGIN_switch_id_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_id_OFF_LW);
}

__forceinline PIF_PLUGIN_switch_id_T *pif_plugin_hdr_readonly_get_switch_id(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_switch_id_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_switch_id_OFF_LW);
}

__forceinline int pif_plugin_hdr_switch_id_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T6_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_switch_id_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_switch_id_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_SWITCH_ID_H__ */
