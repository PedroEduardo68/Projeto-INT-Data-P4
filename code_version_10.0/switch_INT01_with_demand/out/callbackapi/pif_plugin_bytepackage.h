/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_BYTEPACKAGE_H__
#define __PIF_PLUGIN_BYTEPACKAGE_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* bytepackage (4B) */
struct pif_plugin_bytepackage {
    unsigned int int_bytepackageingress:32;
};

/* bytepackage field accessor macros */
#define PIF_HEADER_GET_bytepackage___int_bytepackageingress(_hdr_p) (((_hdr_p)->int_bytepackageingress)) /* bytepackage.int_bytepackageingress [32;0] */

#define PIF_HEADER_SET_bytepackage___int_bytepackageingress(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_bytepackageingress = (unsigned)(((_val))); \
    } while (0) /* bytepackage.int_bytepackageingress[32;0] */



#define PIF_PLUGIN_bytepackage_T __lmem struct pif_plugin_bytepackage

/*
 * Access function prototypes
 */

int pif_plugin_hdr_bytepackage_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_bytepackage_T *pif_plugin_hdr_get_bytepackage(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_bytepackage_T *pif_plugin_hdr_readonly_get_bytepackage(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_bytepackage_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_bytepackage_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_bytepackage_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_bytepackage_VALID(_ctl);
}

__forceinline PIF_PLUGIN_bytepackage_T *pif_plugin_hdr_get_bytepackage(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_bytepackage_DIRTY(_ctl);
    return (PIF_PLUGIN_bytepackage_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_bytepackage_OFF_LW);
}

__forceinline PIF_PLUGIN_bytepackage_T *pif_plugin_hdr_readonly_get_bytepackage(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_bytepackage_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_bytepackage_OFF_LW);
}

__forceinline int pif_plugin_hdr_bytepackage_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T12_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_bytepackage_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_bytepackage_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_BYTEPACKAGE_H__ */
