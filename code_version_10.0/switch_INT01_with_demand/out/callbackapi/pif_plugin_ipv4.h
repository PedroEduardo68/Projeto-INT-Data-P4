/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_IPV4_H__
#define __PIF_PLUGIN_IPV4_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* ipv4 (20B) */
struct pif_plugin_ipv4 {
    unsigned int version:4;
    unsigned int headerLength:4;
    unsigned int typeServiceDiffServ:8;
    unsigned int totalLength:16;
    unsigned int identification:16;
    unsigned int fragmentOffset:16;
    unsigned int timeToLive:8;
    unsigned int protocol:8;
    unsigned int headerChecksum:16;
    unsigned int sourceAddress:32;
    unsigned int destinationAddress:32;
};

/* ipv4 field accessor macros */
#define PIF_HEADER_GET_ipv4___version(_hdr_p) (((_hdr_p)->version)) /* ipv4.version [4;0] */

#define PIF_HEADER_SET_ipv4___version(_hdr_p, _val) \
    do { \
        (_hdr_p)->version = (unsigned)(((_val))); \
    } while (0) /* ipv4.version[4;0] */

#define PIF_HEADER_GET_ipv4___headerLength(_hdr_p) (((_hdr_p)->headerLength)) /* ipv4.headerLength [4;0] */

#define PIF_HEADER_SET_ipv4___headerLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->headerLength = (unsigned)(((_val))); \
    } while (0) /* ipv4.headerLength[4;0] */

#define PIF_HEADER_GET_ipv4___typeServiceDiffServ(_hdr_p) (((_hdr_p)->typeServiceDiffServ)) /* ipv4.typeServiceDiffServ [8;0] */

#define PIF_HEADER_SET_ipv4___typeServiceDiffServ(_hdr_p, _val) \
    do { \
        (_hdr_p)->typeServiceDiffServ = (unsigned)(((_val))); \
    } while (0) /* ipv4.typeServiceDiffServ[8;0] */

#define PIF_HEADER_GET_ipv4___totalLength(_hdr_p) (((_hdr_p)->totalLength)) /* ipv4.totalLength [16;0] */

#define PIF_HEADER_SET_ipv4___totalLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->totalLength = (unsigned)(((_val))); \
    } while (0) /* ipv4.totalLength[16;0] */

#define PIF_HEADER_GET_ipv4___identification(_hdr_p) (((_hdr_p)->identification)) /* ipv4.identification [16;0] */

#define PIF_HEADER_SET_ipv4___identification(_hdr_p, _val) \
    do { \
        (_hdr_p)->identification = (unsigned)(((_val))); \
    } while (0) /* ipv4.identification[16;0] */

#define PIF_HEADER_GET_ipv4___fragmentOffset(_hdr_p) (((_hdr_p)->fragmentOffset)) /* ipv4.fragmentOffset [16;0] */

#define PIF_HEADER_SET_ipv4___fragmentOffset(_hdr_p, _val) \
    do { \
        (_hdr_p)->fragmentOffset = (unsigned)(((_val))); \
    } while (0) /* ipv4.fragmentOffset[16;0] */

#define PIF_HEADER_GET_ipv4___timeToLive(_hdr_p) (((_hdr_p)->timeToLive)) /* ipv4.timeToLive [8;0] */

#define PIF_HEADER_SET_ipv4___timeToLive(_hdr_p, _val) \
    do { \
        (_hdr_p)->timeToLive = (unsigned)(((_val))); \
    } while (0) /* ipv4.timeToLive[8;0] */

#define PIF_HEADER_GET_ipv4___protocol(_hdr_p) (((_hdr_p)->protocol)) /* ipv4.protocol [8;0] */

#define PIF_HEADER_SET_ipv4___protocol(_hdr_p, _val) \
    do { \
        (_hdr_p)->protocol = (unsigned)(((_val))); \
    } while (0) /* ipv4.protocol[8;0] */

#define PIF_HEADER_GET_ipv4___headerChecksum(_hdr_p) (((_hdr_p)->headerChecksum)) /* ipv4.headerChecksum [16;0] */

#define PIF_HEADER_SET_ipv4___headerChecksum(_hdr_p, _val) \
    do { \
        (_hdr_p)->headerChecksum = (unsigned)(((_val))); \
    } while (0) /* ipv4.headerChecksum[16;0] */

#define PIF_HEADER_GET_ipv4___sourceAddress(_hdr_p) (((_hdr_p)->sourceAddress)) /* ipv4.sourceAddress [32;0] */

#define PIF_HEADER_SET_ipv4___sourceAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourceAddress = (unsigned)(((_val))); \
    } while (0) /* ipv4.sourceAddress[32;0] */

#define PIF_HEADER_GET_ipv4___destinationAddress(_hdr_p) (((_hdr_p)->destinationAddress)) /* ipv4.destinationAddress [32;0] */

#define PIF_HEADER_SET_ipv4___destinationAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress = (unsigned)(((_val))); \
    } while (0) /* ipv4.destinationAddress[32;0] */



#define PIF_PLUGIN_ipv4_T __lmem struct pif_plugin_ipv4

/*
 * Access function prototypes
 */

int pif_plugin_hdr_ipv4_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_ipv4_T *pif_plugin_hdr_get_ipv4(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_ipv4_T *pif_plugin_hdr_readonly_get_ipv4(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_ipv4_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_ipv4_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_ipv4_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_ipv4_VALID(_ctl);
}

__forceinline PIF_PLUGIN_ipv4_T *pif_plugin_hdr_get_ipv4(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_ipv4_DIRTY(_ctl);
    return (PIF_PLUGIN_ipv4_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_ipv4_OFF_LW);
}

__forceinline PIF_PLUGIN_ipv4_T *pif_plugin_hdr_readonly_get_ipv4(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_ipv4_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_ipv4_OFF_LW);
}

__forceinline int pif_plugin_hdr_ipv4_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_ipv4_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_IPV4_H__ */
