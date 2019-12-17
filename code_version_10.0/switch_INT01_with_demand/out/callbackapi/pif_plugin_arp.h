/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_ARP_H__
#define __PIF_PLUGIN_ARP_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* arp (28B) */
struct pif_plugin_arp {
    unsigned int hardwareType:16;
    unsigned int protocoloType:16;
    unsigned int hardwareAddressLength:8;
    unsigned int protocolAddressLength:8;
    unsigned int opcode:16;
    /* senderHardwareAddress [32;16] */
    unsigned int senderHardwareAddress:32;
    /* senderHardwareAddress [16;0] */
    unsigned int __senderHardwareAddress_1:16;
    /* senderProtocolAddress [16;16] */
    unsigned int senderProtocolAddress:16;
    /* senderProtocolAddress [16;0] */
    unsigned int __senderProtocolAddress_1:16;
    /* targetHardwareAddress [16;32] */
    unsigned int targetHardwareAddress:16;
    /* targetHardwareAddress [32;0] */
    unsigned int __targetHardwareAddress_1:32;
    unsigned int targetProtocolAddress:32;
};

/* arp field accessor macros */
#define PIF_HEADER_GET_arp___hardwareType(_hdr_p) (((_hdr_p)->hardwareType)) /* arp.hardwareType [16;0] */

#define PIF_HEADER_SET_arp___hardwareType(_hdr_p, _val) \
    do { \
        (_hdr_p)->hardwareType = (unsigned)(((_val))); \
    } while (0) /* arp.hardwareType[16;0] */

#define PIF_HEADER_GET_arp___protocoloType(_hdr_p) (((_hdr_p)->protocoloType)) /* arp.protocoloType [16;0] */

#define PIF_HEADER_SET_arp___protocoloType(_hdr_p, _val) \
    do { \
        (_hdr_p)->protocoloType = (unsigned)(((_val))); \
    } while (0) /* arp.protocoloType[16;0] */

#define PIF_HEADER_GET_arp___hardwareAddressLength(_hdr_p) (((_hdr_p)->hardwareAddressLength)) /* arp.hardwareAddressLength [8;0] */

#define PIF_HEADER_SET_arp___hardwareAddressLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->hardwareAddressLength = (unsigned)(((_val))); \
    } while (0) /* arp.hardwareAddressLength[8;0] */

#define PIF_HEADER_GET_arp___protocolAddressLength(_hdr_p) (((_hdr_p)->protocolAddressLength)) /* arp.protocolAddressLength [8;0] */

#define PIF_HEADER_SET_arp___protocolAddressLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->protocolAddressLength = (unsigned)(((_val))); \
    } while (0) /* arp.protocolAddressLength[8;0] */

#define PIF_HEADER_GET_arp___opcode(_hdr_p) (((_hdr_p)->opcode)) /* arp.opcode [16;0] */

#define PIF_HEADER_SET_arp___opcode(_hdr_p, _val) \
    do { \
        (_hdr_p)->opcode = (unsigned)(((_val))); \
    } while (0) /* arp.opcode[16;0] */

#define PIF_HEADER_GET_arp___senderHardwareAddress___0(_hdr_p) ((((_hdr_p)->senderHardwareAddress & 0xffff) << 16) | ((_hdr_p)->__senderHardwareAddress_1)) /* arp.senderHardwareAddress [32;0] */

#define PIF_HEADER_SET_arp___senderHardwareAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->senderHardwareAddress &= (unsigned)(0xffff0000); \
        (_hdr_p)->senderHardwareAddress |= (unsigned)((((_val) >> 16) & 0xffff)); \
        (_hdr_p)->__senderHardwareAddress_1 = (unsigned)(((_val))); \
    } while (0) /* arp.senderHardwareAddress[32;0] */

#define PIF_HEADER_GET_arp___senderHardwareAddress___1(_hdr_p) ((((_hdr_p)->senderHardwareAddress >> 16) & 0xffff)) /* arp.senderHardwareAddress [16;32] */

#define PIF_HEADER_SET_arp___senderHardwareAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->senderHardwareAddress &= (unsigned)(0xffff); \
        (_hdr_p)->senderHardwareAddress |= (unsigned)((((_val) & 0xffff) << 16)); \
    } while (0) /* arp.senderHardwareAddress[16;32] */

#define PIF_HEADER_GET_arp___senderProtocolAddress(_hdr_p) (((_hdr_p)->senderProtocolAddress << 16) | ((_hdr_p)->__senderProtocolAddress_1)) /* arp.senderProtocolAddress [32;0] */

#define PIF_HEADER_SET_arp___senderProtocolAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->senderProtocolAddress = (unsigned)(((_val) >> 16)); \
        (_hdr_p)->__senderProtocolAddress_1 = (unsigned)(((_val))); \
    } while (0) /* arp.senderProtocolAddress[32;0] */

#define PIF_HEADER_GET_arp___targetHardwareAddress___0(_hdr_p) (((_hdr_p)->__targetHardwareAddress_1)) /* arp.targetHardwareAddress [32;0] */

#define PIF_HEADER_SET_arp___targetHardwareAddress___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__targetHardwareAddress_1 = (unsigned)(((_val))); \
    } while (0) /* arp.targetHardwareAddress[32;0] */

#define PIF_HEADER_GET_arp___targetHardwareAddress___1(_hdr_p) (((_hdr_p)->targetHardwareAddress)) /* arp.targetHardwareAddress [16;32] */

#define PIF_HEADER_SET_arp___targetHardwareAddress___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->targetHardwareAddress = (unsigned)(((_val))); \
    } while (0) /* arp.targetHardwareAddress[16;32] */

#define PIF_HEADER_GET_arp___targetProtocolAddress(_hdr_p) (((_hdr_p)->targetProtocolAddress)) /* arp.targetProtocolAddress [32;0] */

#define PIF_HEADER_SET_arp___targetProtocolAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->targetProtocolAddress = (unsigned)(((_val))); \
    } while (0) /* arp.targetProtocolAddress[32;0] */



#define PIF_PLUGIN_arp_T __lmem struct pif_plugin_arp

/*
 * Access function prototypes
 */

int pif_plugin_hdr_arp_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_arp_T *pif_plugin_hdr_get_arp(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_arp_T *pif_plugin_hdr_readonly_get_arp(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_arp_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_arp_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_arp_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_arp_VALID(_ctl);
}

__forceinline PIF_PLUGIN_arp_T *pif_plugin_hdr_get_arp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_arp_DIRTY(_ctl);
    return (PIF_PLUGIN_arp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_arp_OFF_LW);
}

__forceinline PIF_PLUGIN_arp_T *pif_plugin_hdr_readonly_get_arp(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_arp_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_arp_OFF_LW);
}

__forceinline int pif_plugin_hdr_arp_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_arp_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_ARP_H__ */
