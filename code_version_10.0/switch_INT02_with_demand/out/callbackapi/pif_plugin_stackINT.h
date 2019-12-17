/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_STACKINT_H__
#define __PIF_PLUGIN_STACKINT_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* stackINT (0B) */
struct pif_plugin_stackINT {
};

/* stackINT field accessor macros */


#define PIF_PLUGIN_stackINT_T __lmem struct pif_plugin_stackINT

/*
 * Access function prototypes
 */

int pif_plugin_hdr_stackINT_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_stackINT_T *pif_plugin_hdr_get_stackINT(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_stackINT_T *pif_plugin_hdr_readonly_get_stackINT(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_stackINT_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_stackINT_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_stackINT_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_stackINT_VALID(_ctl);
}

__forceinline PIF_PLUGIN_stackINT_T *pif_plugin_hdr_get_stackINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_stackINT_DIRTY(_ctl);
    return (PIF_PLUGIN_stackINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_stackINT_OFF_LW);
}

__forceinline PIF_PLUGIN_stackINT_T *pif_plugin_hdr_readonly_get_stackINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_stackINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_stackINT_OFF_LW);
}

__forceinline int pif_plugin_hdr_stackINT_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_stackINT_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_STACKINT_H__ */
