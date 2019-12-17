/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_TCP_H__
#define __PIF_PLUGIN_TCP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* tcp (20B) */
struct pif_plugin_tcp {
    unsigned int sourcePort:16;
    unsigned int destinationPort:16;
    unsigned int sequenceNumber:32;
    unsigned int acknowledgementNumber:32;
    unsigned int dataOffset:4;
    unsigned int reserved:4;
    unsigned int flags:8;
    unsigned int windowSize:16;
    unsigned int checksum:16;
    unsigned int urgentPointers:16;
};

/* tcp field accessor macros */
#define PIF_HEADER_GET_tcp___sourcePort(_hdr_p) (((_hdr_p)->sourcePort)) /* tcp.sourcePort [16;0] */

#define PIF_HEADER_SET_tcp___sourcePort(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourcePort = (unsigned)(((_val))); \
    } while (0) /* tcp.sourcePort[16;0] */

#define PIF_HEADER_GET_tcp___destinationPort(_hdr_p) (((_hdr_p)->destinationPort)) /* tcp.destinationPort [16;0] */

#define PIF_HEADER_SET_tcp___destinationPort(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationPort = (unsigned)(((_val))); \
    } while (0) /* tcp.destinationPort[16;0] */

#define PIF_HEADER_GET_tcp___sequenceNumber(_hdr_p) (((_hdr_p)->sequenceNumber)) /* tcp.sequenceNumber [32;0] */

#define PIF_HEADER_SET_tcp___sequenceNumber(_hdr_p, _val) \
    do { \
        (_hdr_p)->sequenceNumber = (unsigned)(((_val))); \
    } while (0) /* tcp.sequenceNumber[32;0] */

#define PIF_HEADER_GET_tcp___acknowledgementNumber(_hdr_p) (((_hdr_p)->acknowledgementNumber)) /* tcp.acknowledgementNumber [32;0] */

#define PIF_HEADER_SET_tcp___acknowledgementNumber(_hdr_p, _val) \
    do { \
        (_hdr_p)->acknowledgementNumber = (unsigned)(((_val))); \
    } while (0) /* tcp.acknowledgementNumber[32;0] */

#define PIF_HEADER_GET_tcp___dataOffset(_hdr_p) (((_hdr_p)->dataOffset)) /* tcp.dataOffset [4;0] */

#define PIF_HEADER_SET_tcp___dataOffset(_hdr_p, _val) \
    do { \
        (_hdr_p)->dataOffset = (unsigned)(((_val))); \
    } while (0) /* tcp.dataOffset[4;0] */

#define PIF_HEADER_GET_tcp___reserved(_hdr_p) (((_hdr_p)->reserved)) /* tcp.reserved [4;0] */

#define PIF_HEADER_SET_tcp___reserved(_hdr_p, _val) \
    do { \
        (_hdr_p)->reserved = (unsigned)(((_val))); \
    } while (0) /* tcp.reserved[4;0] */

#define PIF_HEADER_GET_tcp___flags(_hdr_p) (((_hdr_p)->flags)) /* tcp.flags [8;0] */

#define PIF_HEADER_SET_tcp___flags(_hdr_p, _val) \
    do { \
        (_hdr_p)->flags = (unsigned)(((_val))); \
    } while (0) /* tcp.flags[8;0] */

#define PIF_HEADER_GET_tcp___windowSize(_hdr_p) (((_hdr_p)->windowSize)) /* tcp.windowSize [16;0] */

#define PIF_HEADER_SET_tcp___windowSize(_hdr_p, _val) \
    do { \
        (_hdr_p)->windowSize = (unsigned)(((_val))); \
    } while (0) /* tcp.windowSize[16;0] */

#define PIF_HEADER_GET_tcp___checksum(_hdr_p) (((_hdr_p)->checksum)) /* tcp.checksum [16;0] */

#define PIF_HEADER_SET_tcp___checksum(_hdr_p, _val) \
    do { \
        (_hdr_p)->checksum = (unsigned)(((_val))); \
    } while (0) /* tcp.checksum[16;0] */

#define PIF_HEADER_GET_tcp___urgentPointers(_hdr_p) (((_hdr_p)->urgentPointers)) /* tcp.urgentPointers [16;0] */

#define PIF_HEADER_SET_tcp___urgentPointers(_hdr_p, _val) \
    do { \
        (_hdr_p)->urgentPointers = (unsigned)(((_val))); \
    } while (0) /* tcp.urgentPointers[16;0] */



#define PIF_PLUGIN_tcp_T __lmem struct pif_plugin_tcp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_tcp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_tcp_T *pif_plugin_hdr_get_tcp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_tcp_T *pif_plugin_hdr_readonly_get_tcp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_tcp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_tcp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_tcp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_tcp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_tcp_T *pif_plugin_hdr_get_tcp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_tcp_DIRTY(_ctl);
    return (PIF_PLUGIN_tcp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_tcp_OFF_LW);
}

__forceinline PIF_PLUGIN_tcp_T *pif_plugin_hdr_readonly_get_tcp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_tcp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_tcp_OFF_LW);
}

__forceinline int pif_plugin_hdr_tcp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_tcp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_TCP_H__ */
