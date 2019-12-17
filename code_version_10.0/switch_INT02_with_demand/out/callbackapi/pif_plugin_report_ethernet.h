/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_REPORT_ETHERNET_H__
#define __PIF_PLUGIN_REPORT_ETHERNET_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* report_ethernet (14B) */
struct pif_plugin_report_ethernet {
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

/* report_ethernet field accessor macros */
#define PIF_HEADER_GET_report_ethernet___destinationAddress___0(_hdr_p) ((((_hdr_p)->destinationAddress & 0xffff) << 16) | ((_hdr_p)->__destinationAddress_1)) /* report_ethernet.destinationAddress [32;0] */

#define PIF_HEADER_SET_report_ethernet___destinationAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress &= (unsigned)(0xffff0000); \
        (_hdr_p)->destinationAddress |= (unsigned)((((_val) >> 16) & 0xffff)); \
        (_hdr_p)->__destinationAddress_1 = (unsigned)(((_val))); \
    } while (0) /* report_ethernet.destinationAddress[32;0] */

#define PIF_HEADER_GET_report_ethernet___destinationAddress___1(_hdr_p) ((((_hdr_p)->destinationAddress >> 16) & 0xffff)) /* report_ethernet.destinationAddress [16;32] */

#define PIF_HEADER_SET_report_ethernet___destinationAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress &= (unsigned)(0xffff); \
        (_hdr_p)->destinationAddress |= (unsigned)((((_val) & 0xffff) << 16)); \
    } while (0) /* report_ethernet.destinationAddress[16;32] */

#define PIF_HEADER_GET_report_ethernet___sourceAddress___0(_hdr_p) (((_hdr_p)->__sourceAddress_1)) /* report_ethernet.sourceAddress [32;0] */

#define PIF_HEADER_SET_report_ethernet___sourceAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__sourceAddress_1 = (unsigned)(((_val))); \
    } while (0) /* report_ethernet.sourceAddress[32;0] */

#define PIF_HEADER_GET_report_ethernet___sourceAddress___1(_hdr_p) (((_hdr_p)->sourceAddress)) /* report_ethernet.sourceAddress [16;32] */

#define PIF_HEADER_SET_report_ethernet___sourceAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourceAddress = (unsigned)(((_val))); \
    } while (0) /* report_ethernet.sourceAddress[16;32] */

#define PIF_HEADER_GET_report_ethernet___etherType(_hdr_p) (((_hdr_p)->etherType)) /* report_ethernet.etherType [16;0] */

#define PIF_HEADER_SET_report_ethernet___etherType(_hdr_p, _val) \
    do { \
        (_hdr_p)->etherType = (unsigned)(((_val))); \
    } while (0) /* report_ethernet.etherType[16;0] */



#define PIF_PLUGIN_report_ethernet_T __lmem struct pif_plugin_report_ethernet

/*
 * Access function prototypes
 */

int pif_plugin_hdr_report_ethernet_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_ethernet_T *pif_plugin_hdr_get_report_ethernet(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_ethernet_T *pif_plugin_hdr_readonly_get_report_ethernet(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_ethernet_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_ethernet_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_report_ethernet_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_report_ethernet_VALID(_ctl);
}

__forceinline PIF_PLUGIN_report_ethernet_T *pif_plugin_hdr_get_report_ethernet(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_report_ethernet_DIRTY(_ctl);
    return (PIF_PLUGIN_report_ethernet_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
}

__forceinline PIF_PLUGIN_report_ethernet_T *pif_plugin_hdr_readonly_get_report_ethernet(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_report_ethernet_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_ethernet_OFF_LW);
}

__forceinline int pif_plugin_hdr_report_ethernet_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T0_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_report_ethernet_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_report_ethernet_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_REPORT_ETHERNET_H__ */
