/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_ETHERNET_H__
#define __PIF_PLUGIN_ETHERNET_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* ethernet (14B) */
struct pif_plugin_ethernet {
    /* destinationAddress [32;16] */
    unsigned int destinationAddress:32;
    /* destinationAddress [16;0] */
    unsigned int __destinationAddress_1:16;
    /* sourceAddress [16;32] */
    unsigned int sourceAddress:16;
    /* sourceAddress [32;0] */
    unsigned int __sourceAddress_1:32;
    unsigned int etherType:16;
};

/* ethernet field accessor macros */
#define PIF_HEADER_GET_ethernet___destinationAddress___0(_hdr_p) ((((_hdr_p)->destinationAddress & 0xffff) << 16) | ((_hdr_p)->__destinationAddress_1)) /* ethernet.destinationAddress [32;0] */

#define PIF_HEADER_SET_ethernet___destinationAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress &= (unsigned)(0xffff0000); \
        (_hdr_p)->destinationAddress |= (unsigned)((((_val) >> 16) & 0xffff)); \
        (_hdr_p)->__destinationAddress_1 = (unsigned)(((_val))); \
    } while (0) /* ethernet.destinationAddress[32;0] */

#define PIF_HEADER_GET_ethernet___destinationAddress___1(_hdr_p) ((((_hdr_p)->destinationAddress >> 16) & 0xffff)) /* ethernet.destinationAddress [16;32] */

#define PIF_HEADER_SET_ethernet___destinationAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress &= (unsigned)(0xffff); \
        (_hdr_p)->destinationAddress |= (unsigned)((((_val) & 0xffff) << 16)); \
    } while (0) /* ethernet.destinationAddress[16;32] */

#define PIF_HEADER_GET_ethernet___sourceAddress___0(_hdr_p) (((_hdr_p)->__sourceAddress_1)) /* ethernet.sourceAddress [32;0] */

#define PIF_HEADER_SET_ethernet___sourceAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__sourceAddress_1 = (unsigned)(((_val))); \
    } while (0) /* ethernet.sourceAddress[32;0] */

#define PIF_HEADER_GET_ethernet___sourceAddress___1(_hdr_p) (((_hdr_p)->sourceAddress)) /* ethernet.sourceAddress [16;32] */

#define PIF_HEADER_SET_ethernet___sourceAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourceAddress = (unsigned)(((_val))); \
    } while (0) /* ethernet.sourceAddress[16;32] */

#define PIF_HEADER_GET_ethernet___etherType(_hdr_p) (((_hdr_p)->etherType)) /* ethernet.etherType [16;0] */

#define PIF_HEADER_SET_ethernet___etherType(_hdr_p, _val) \
    do { \
        (_hdr_p)->etherType = (unsigned)(((_val))); \
    } while (0) /* ethernet.etherType[16;0] */



#define PIF_PLUGIN_ethernet_T __lmem struct pif_plugin_ethernet

/*
 * Access function prototypes
 */

int pif_plugin_hdr_ethernet_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_ethernet_T *pif_plugin_hdr_get_ethernet(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_ethernet_T *pif_plugin_hdr_readonly_get_ethernet(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_ethernet_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_ethernet_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_ethernet_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_ethernet_VALID(_ctl);
}

__forceinline PIF_PLUGIN_ethernet_T *pif_plugin_hdr_get_ethernet(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_ethernet_DIRTY(_ctl);
    return (PIF_PLUGIN_ethernet_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_ethernet_OFF_LW);
}

__forceinline PIF_PLUGIN_ethernet_T *pif_plugin_hdr_readonly_get_ethernet(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_ethernet_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_ethernet_OFF_LW);
}

__forceinline int pif_plugin_hdr_ethernet_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_ethernet_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_ETHERNET_H__ */
