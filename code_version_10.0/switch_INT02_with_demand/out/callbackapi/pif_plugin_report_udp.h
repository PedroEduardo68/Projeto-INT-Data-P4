/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_REPORT_UDP_H__
#define __PIF_PLUGIN_REPORT_UDP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* report_udp (8B) */
struct pif_plugin_report_udp {
    unsigned int sourcePort:16;
    unsigned int destinationPort:16;
    unsigned int lengthUDP:16;
    unsigned int checksum:16;
};

/* report_udp field accessor macros */
#define PIF_HEADER_GET_report_udp___sourcePort(_hdr_p) (((_hdr_p)->sourcePort)) /* report_udp.sourcePort [16;0] */

#define PIF_HEADER_SET_report_udp___sourcePort(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourcePort = (unsigned)(((_val))); \
    } while (0) /* report_udp.sourcePort[16;0] */

#define PIF_HEADER_GET_report_udp___destinationPort(_hdr_p) (((_hdr_p)->destinationPort)) /* report_udp.destinationPort [16;0] */

#define PIF_HEADER_SET_report_udp___destinationPort(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationPort = (unsigned)(((_val))); \
    } while (0) /* report_udp.destinationPort[16;0] */

#define PIF_HEADER_GET_report_udp___lengthUDP(_hdr_p) (((_hdr_p)->lengthUDP)) /* report_udp.lengthUDP [16;0] */

#define PIF_HEADER_SET_report_udp___lengthUDP(_hdr_p, _val) \
    do { \
        (_hdr_p)->lengthUDP = (unsigned)(((_val))); \
    } while (0) /* report_udp.lengthUDP[16;0] */

#define PIF_HEADER_GET_report_udp___checksum(_hdr_p) (((_hdr_p)->checksum)) /* report_udp.checksum [16;0] */

#define PIF_HEADER_SET_report_udp___checksum(_hdr_p, _val) \
    do { \
        (_hdr_p)->checksum = (unsigned)(((_val))); \
    } while (0) /* report_udp.checksum[16;0] */



#define PIF_PLUGIN_report_udp_T __lmem struct pif_plugin_report_udp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_report_udp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_udp_T *pif_plugin_hdr_get_report_udp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_udp_T *pif_plugin_hdr_readonly_get_report_udp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_udp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_udp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_report_udp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_report_udp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_report_udp_T *pif_plugin_hdr_get_report_udp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_report_udp_DIRTY(_ctl);
    return (PIF_PLUGIN_report_udp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
}

__forceinline PIF_PLUGIN_report_udp_T *pif_plugin_hdr_readonly_get_report_udp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_report_udp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_udp_OFF_LW);
}

__forceinline int pif_plugin_hdr_report_udp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T2_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_report_udp_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_report_udp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_REPORT_UDP_H__ */
