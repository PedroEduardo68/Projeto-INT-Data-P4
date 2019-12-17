/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_TAILINT_H__
#define __PIF_PLUGIN_TAILINT_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* tailINT (8B) */
struct pif_plugin_tailINT {
    unsigned int tail_header:32;
    unsigned int tail_proto:8;
    unsigned int tail_port:16;
    unsigned int tail_dscp:8;
};

/* tailINT field accessor macros */
#define PIF_HEADER_GET_tailINT___tail_header(_hdr_p) (((_hdr_p)->tail_header)) /* tailINT.tail_header [32;0] */

#define PIF_HEADER_SET_tailINT___tail_header(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_header = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_header[32;0] */

#define PIF_HEADER_GET_tailINT___tail_proto(_hdr_p) (((_hdr_p)->tail_proto)) /* tailINT.tail_proto [8;0] */

#define PIF_HEADER_SET_tailINT___tail_proto(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_proto = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_proto[8;0] */

#define PIF_HEADER_GET_tailINT___tail_port(_hdr_p) (((_hdr_p)->tail_port)) /* tailINT.tail_port [16;0] */

#define PIF_HEADER_SET_tailINT___tail_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_port = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_port[16;0] */

#define PIF_HEADER_GET_tailINT___tail_dscp(_hdr_p) (((_hdr_p)->tail_dscp)) /* tailINT.tail_dscp [8;0] */

#define PIF_HEADER_SET_tailINT___tail_dscp(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_dscp = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_dscp[8;0] */



#define PIF_PLUGIN_tailINT_T __lmem struct pif_plugin_tailINT

/*
 * Access function prototypes
 */

int pif_plugin_hdr_tailINT_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_tailINT_T *pif_plugin_hdr_get_tailINT(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_tailINT_T *pif_plugin_hdr_readonly_get_tailINT(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_tailINT_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_tailINT_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_tailINT_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_tailINT_VALID(_ctl);
}

__forceinline PIF_PLUGIN_tailINT_T *pif_plugin_hdr_get_tailINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_tailINT_DIRTY(_ctl);
    return (PIF_PLUGIN_tailINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_tailINT_OFF_LW);
}

__forceinline PIF_PLUGIN_tailINT_T *pif_plugin_hdr_readonly_get_tailINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_tailINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_tailINT_OFF_LW);
}

__forceinline int pif_plugin_hdr_tailINT_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T13_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_tailINT_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_tailINT_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_TAILINT_H__ */
