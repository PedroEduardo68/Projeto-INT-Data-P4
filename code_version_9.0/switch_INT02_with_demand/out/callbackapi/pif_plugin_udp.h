/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_UDP_H__
#define __PIF_PLUGIN_UDP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* udp (8B) */
struct pif_plugin_udp {
    unsigned int sourcePort:16;
    unsigned int destinationPort:16;
    unsigned int lengthUDP:16;
    unsigned int checksum:16;
};

/* udp field accessor macros */
#define PIF_HEADER_GET_udp___sourcePort(_hdr_p) (((_hdr_p)->sourcePort)) /* udp.sourcePort [16;0] */

#define PIF_HEADER_SET_udp___sourcePort(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourcePort = (unsigned)(((_val))); \
    } while (0) /* udp.sourcePort[16;0] */

#define PIF_HEADER_GET_udp___destinationPort(_hdr_p) (((_hdr_p)->destinationPort)) /* udp.destinationPort [16;0] */

#define PIF_HEADER_SET_udp___destinationPort(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationPort = (unsigned)(((_val))); \
    } while (0) /* udp.destinationPort[16;0] */

#define PIF_HEADER_GET_udp___lengthUDP(_hdr_p) (((_hdr_p)->lengthUDP)) /* udp.lengthUDP [16;0] */

#define PIF_HEADER_SET_udp___lengthUDP(_hdr_p, _val) \
    do { \
        (_hdr_p)->lengthUDP = (unsigned)(((_val))); \
    } while (0) /* udp.lengthUDP[16;0] */

#define PIF_HEADER_GET_udp___checksum(_hdr_p) (((_hdr_p)->checksum)) /* udp.checksum [16;0] */

#define PIF_HEADER_SET_udp___checksum(_hdr_p, _val) \
    do { \
        (_hdr_p)->checksum = (unsigned)(((_val))); \
    } while (0) /* udp.checksum[16;0] */



#define PIF_PLUGIN_udp_T __lmem struct pif_plugin_udp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_udp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_udp_T *pif_plugin_hdr_get_udp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_udp_T *pif_plugin_hdr_readonly_get_udp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_udp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_udp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_udp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_udp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_udp_T *pif_plugin_hdr_get_udp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_udp_DIRTY(_ctl);
    return (PIF_PLUGIN_udp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_udp_OFF_LW);
}

__forceinline PIF_PLUGIN_udp_T *pif_plugin_hdr_readonly_get_udp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_udp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_udp_OFF_LW);
}

__forceinline int pif_plugin_hdr_udp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_udp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_UDP_H__ */
