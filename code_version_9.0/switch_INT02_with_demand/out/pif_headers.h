/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_HEADERS_H__
#define __PIF_HEADERS_H__

/* Generated C source defining PIF headers, metadata and registers */
/* Warning: your edits to this file may be lost */

/*
 * Packet headers
 */

/* arp (28B) */
struct pif_header_arp {
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


/* egressTimestamp (8B) */
struct pif_header_egressTimestamp {
    /* int_egressTimestamp [32;32] */
    unsigned int int_egressTimestamp:32;
    /* int_egressTimestamp [32;0] */
    unsigned int __int_egressTimestamp_1:32;
};

/* egressTimestamp field accessor macros */
#define PIF_HEADER_GET_egressTimestamp___int_egressTimestamp___0(_hdr_p) (((_hdr_p)->__int_egressTimestamp_1)) /* egressTimestamp.int_egressTimestamp [32;0] */

#define PIF_HEADER_SET_egressTimestamp___int_egressTimestamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_egressTimestamp_1 = (unsigned)(((_val))); \
    } while (0) /* egressTimestamp.int_egressTimestamp[32;0] */

#define PIF_HEADER_GET_egressTimestamp___int_egressTimestamp___1(_hdr_p) (((_hdr_p)->int_egressTimestamp)) /* egressTimestamp.int_egressTimestamp [32;32] */

#define PIF_HEADER_SET_egressTimestamp___int_egressTimestamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_egressTimestamp = (unsigned)(((_val))); \
    } while (0) /* egressTimestamp.int_egressTimestamp[32;32] */


/* udp (8B) */
struct pif_header_udp {
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


/* hopINT (8B) */
struct pif_header_hopINT {
    unsigned int int_version:8;
    unsigned int int_replication:8;
    unsigned int int_copy:1;
    unsigned int int_exceeded:1;
    unsigned int int_rsvd_1:8;
    /* int_ins_cnt [6;2] */
    unsigned int int_ins_cnt:6;
    /* int_ins_cnt [2;0] */
    unsigned int __int_ins_cnt_1:2;
    unsigned int int_max_hops:8;
    unsigned int int_total_hops:8;
    unsigned int int_instruction_bit:8;
    unsigned int int_rsvd_instructions:6;
};

/* hopINT field accessor macros */
#define PIF_HEADER_GET_hopINT___int_version(_hdr_p) (((_hdr_p)->int_version)) /* hopINT.int_version [8;0] */

#define PIF_HEADER_SET_hopINT___int_version(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_version = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_version[8;0] */

#define PIF_HEADER_GET_hopINT___int_replication(_hdr_p) (((_hdr_p)->int_replication)) /* hopINT.int_replication [8;0] */

#define PIF_HEADER_SET_hopINT___int_replication(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_replication = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_replication[8;0] */

#define PIF_HEADER_GET_hopINT___int_copy(_hdr_p) (((_hdr_p)->int_copy)) /* hopINT.int_copy [1;0] */

#define PIF_HEADER_SET_hopINT___int_copy(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_copy = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_copy[1;0] */

#define PIF_HEADER_GET_hopINT___int_exceeded(_hdr_p) (((_hdr_p)->int_exceeded)) /* hopINT.int_exceeded [1;0] */

#define PIF_HEADER_SET_hopINT___int_exceeded(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_exceeded = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_exceeded[1;0] */

#define PIF_HEADER_GET_hopINT___int_rsvd_1(_hdr_p) (((_hdr_p)->int_rsvd_1)) /* hopINT.int_rsvd_1 [8;0] */

#define PIF_HEADER_SET_hopINT___int_rsvd_1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_rsvd_1 = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_rsvd_1[8;0] */

#define PIF_HEADER_GET_hopINT___int_ins_cnt(_hdr_p) (((_hdr_p)->int_ins_cnt << 2) | ((_hdr_p)->__int_ins_cnt_1)) /* hopINT.int_ins_cnt [8;0] */

#define PIF_HEADER_SET_hopINT___int_ins_cnt(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_ins_cnt = (unsigned)(((_val) >> 2)); \
        (_hdr_p)->__int_ins_cnt_1 = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_ins_cnt[8;0] */

#define PIF_HEADER_GET_hopINT___int_max_hops(_hdr_p) (((_hdr_p)->int_max_hops)) /* hopINT.int_max_hops [8;0] */

#define PIF_HEADER_SET_hopINT___int_max_hops(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_max_hops = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_max_hops[8;0] */

#define PIF_HEADER_GET_hopINT___int_total_hops(_hdr_p) (((_hdr_p)->int_total_hops)) /* hopINT.int_total_hops [8;0] */

#define PIF_HEADER_SET_hopINT___int_total_hops(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_total_hops = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_total_hops[8;0] */

#define PIF_HEADER_GET_hopINT___int_instruction_bit(_hdr_p) (((_hdr_p)->int_instruction_bit)) /* hopINT.int_instruction_bit [8;0] */

#define PIF_HEADER_SET_hopINT___int_instruction_bit(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_instruction_bit = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_instruction_bit[8;0] */

#define PIF_HEADER_GET_hopINT___int_rsvd_instructions(_hdr_p) (((_hdr_p)->int_rsvd_instructions)) /* hopINT.int_rsvd_instructions [6;0] */

#define PIF_HEADER_SET_hopINT___int_rsvd_instructions(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_rsvd_instructions = (unsigned)(((_val))); \
    } while (0) /* hopINT.int_rsvd_instructions[6;0] */


/* report_udp (8B) */
struct pif_header_report_udp {
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


/* report_ethernet (14B) */
struct pif_header_report_ethernet {
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


/* switch_id (4B) */
struct pif_header_switch_id {
    unsigned int int_switch_id:32;
};

/* switch_id field accessor macros */
#define PIF_HEADER_GET_switch_id___int_switch_id(_hdr_p) (((_hdr_p)->int_switch_id)) /* switch_id.int_switch_id [32;0] */

#define PIF_HEADER_SET_switch_id___int_switch_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_switch_id = (unsigned)(((_val))); \
    } while (0) /* switch_id.int_switch_id[32;0] */


/* tcp (20B) */
struct pif_header_tcp {
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


/* report_ipv4 (20B) */
struct pif_header_report_ipv4 {
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

/* report_ipv4 field accessor macros */
#define PIF_HEADER_GET_report_ipv4___version(_hdr_p) (((_hdr_p)->version)) /* report_ipv4.version [4;0] */

#define PIF_HEADER_SET_report_ipv4___version(_hdr_p, _val) \
    do { \
        (_hdr_p)->version = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.version[4;0] */

#define PIF_HEADER_GET_report_ipv4___headerLength(_hdr_p) (((_hdr_p)->headerLength)) /* report_ipv4.headerLength [4;0] */

#define PIF_HEADER_SET_report_ipv4___headerLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->headerLength = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.headerLength[4;0] */

#define PIF_HEADER_GET_report_ipv4___typeServiceDiffServ(_hdr_p) (((_hdr_p)->typeServiceDiffServ)) /* report_ipv4.typeServiceDiffServ [8;0] */

#define PIF_HEADER_SET_report_ipv4___typeServiceDiffServ(_hdr_p, _val) \
    do { \
        (_hdr_p)->typeServiceDiffServ = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.typeServiceDiffServ[8;0] */

#define PIF_HEADER_GET_report_ipv4___totalLength(_hdr_p) (((_hdr_p)->totalLength)) /* report_ipv4.totalLength [16;0] */

#define PIF_HEADER_SET_report_ipv4___totalLength(_hdr_p, _val) \
    do { \
        (_hdr_p)->totalLength = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.totalLength[16;0] */

#define PIF_HEADER_GET_report_ipv4___identification(_hdr_p) (((_hdr_p)->identification)) /* report_ipv4.identification [16;0] */

#define PIF_HEADER_SET_report_ipv4___identification(_hdr_p, _val) \
    do { \
        (_hdr_p)->identification = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.identification[16;0] */

#define PIF_HEADER_GET_report_ipv4___fragmentOffset(_hdr_p) (((_hdr_p)->fragmentOffset)) /* report_ipv4.fragmentOffset [16;0] */

#define PIF_HEADER_SET_report_ipv4___fragmentOffset(_hdr_p, _val) \
    do { \
        (_hdr_p)->fragmentOffset = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.fragmentOffset[16;0] */

#define PIF_HEADER_GET_report_ipv4___timeToLive(_hdr_p) (((_hdr_p)->timeToLive)) /* report_ipv4.timeToLive [8;0] */

#define PIF_HEADER_SET_report_ipv4___timeToLive(_hdr_p, _val) \
    do { \
        (_hdr_p)->timeToLive = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.timeToLive[8;0] */

#define PIF_HEADER_GET_report_ipv4___protocol(_hdr_p) (((_hdr_p)->protocol)) /* report_ipv4.protocol [8;0] */

#define PIF_HEADER_SET_report_ipv4___protocol(_hdr_p, _val) \
    do { \
        (_hdr_p)->protocol = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.protocol[8;0] */

#define PIF_HEADER_GET_report_ipv4___headerChecksum(_hdr_p) (((_hdr_p)->headerChecksum)) /* report_ipv4.headerChecksum [16;0] */

#define PIF_HEADER_SET_report_ipv4___headerChecksum(_hdr_p, _val) \
    do { \
        (_hdr_p)->headerChecksum = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.headerChecksum[16;0] */

#define PIF_HEADER_GET_report_ipv4___sourceAddress(_hdr_p) (((_hdr_p)->sourceAddress)) /* report_ipv4.sourceAddress [32;0] */

#define PIF_HEADER_SET_report_ipv4___sourceAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->sourceAddress = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.sourceAddress[32;0] */

#define PIF_HEADER_GET_report_ipv4___destinationAddress(_hdr_p) (((_hdr_p)->destinationAddress)) /* report_ipv4.destinationAddress [32;0] */

#define PIF_HEADER_SET_report_ipv4___destinationAddress(_hdr_p, _val) \
    do { \
        (_hdr_p)->destinationAddress = (unsigned)(((_val))); \
    } while (0) /* report_ipv4.destinationAddress[32;0] */


/* ipv4 (20B) */
struct pif_header_ipv4 {
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


/* int_ingress_egress_ports (4B) */
struct pif_header_int_ingress_egress_ports {
    unsigned int int_ingress_id:16;
    unsigned int int_egress_id:16;
};

/* int_ingress_egress_ports field accessor macros */
#define PIF_HEADER_GET_int_ingress_egress_ports___int_ingress_id(_hdr_p) (((_hdr_p)->int_ingress_id)) /* int_ingress_egress_ports.int_ingress_id [16;0] */

#define PIF_HEADER_SET_int_ingress_egress_ports___int_ingress_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_ingress_id = (unsigned)(((_val))); \
    } while (0) /* int_ingress_egress_ports.int_ingress_id[16;0] */

#define PIF_HEADER_GET_int_ingress_egress_ports___int_egress_id(_hdr_p) (((_hdr_p)->int_egress_id)) /* int_ingress_egress_ports.int_egress_id [16;0] */

#define PIF_HEADER_SET_int_ingress_egress_ports___int_egress_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_egress_id = (unsigned)(((_val))); \
    } while (0) /* int_ingress_egress_ports.int_egress_id[16;0] */


/* ethernet (14B) */
struct pif_header_ethernet {
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


/* report (16B) */
struct pif_header_report {
    unsigned int f_version:8;
    unsigned int f_next_proto:8;
    unsigned int f_drop:1;
    unsigned int f_queue:1;
    unsigned int f_flow:1;
    unsigned int f_rsvd:5;
    unsigned int f_hw_id:8;
    unsigned int f_seq_num:32;
    /* f_ingress_ts [32;32] */
    unsigned int f_ingress_ts:32;
    /* f_ingress_ts [32;0] */
    unsigned int __f_ingress_ts_1:32;
};

/* report field accessor macros */
#define PIF_HEADER_GET_report___f_version(_hdr_p) (((_hdr_p)->f_version)) /* report.f_version [8;0] */

#define PIF_HEADER_SET_report___f_version(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_version = (unsigned)(((_val))); \
    } while (0) /* report.f_version[8;0] */

#define PIF_HEADER_GET_report___f_next_proto(_hdr_p) (((_hdr_p)->f_next_proto)) /* report.f_next_proto [8;0] */

#define PIF_HEADER_SET_report___f_next_proto(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_next_proto = (unsigned)(((_val))); \
    } while (0) /* report.f_next_proto[8;0] */

#define PIF_HEADER_GET_report___f_drop(_hdr_p) (((_hdr_p)->f_drop)) /* report.f_drop [1;0] */

#define PIF_HEADER_SET_report___f_drop(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_drop = (unsigned)(((_val))); \
    } while (0) /* report.f_drop[1;0] */

#define PIF_HEADER_GET_report___f_queue(_hdr_p) (((_hdr_p)->f_queue)) /* report.f_queue [1;0] */

#define PIF_HEADER_SET_report___f_queue(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_queue = (unsigned)(((_val))); \
    } while (0) /* report.f_queue[1;0] */

#define PIF_HEADER_GET_report___f_flow(_hdr_p) (((_hdr_p)->f_flow)) /* report.f_flow [1;0] */

#define PIF_HEADER_SET_report___f_flow(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_flow = (unsigned)(((_val))); \
    } while (0) /* report.f_flow[1;0] */

#define PIF_HEADER_GET_report___f_rsvd(_hdr_p) (((_hdr_p)->f_rsvd)) /* report.f_rsvd [5;0] */

#define PIF_HEADER_SET_report___f_rsvd(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_rsvd = (unsigned)(((_val))); \
    } while (0) /* report.f_rsvd[5;0] */

#define PIF_HEADER_GET_report___f_hw_id(_hdr_p) (((_hdr_p)->f_hw_id)) /* report.f_hw_id [8;0] */

#define PIF_HEADER_SET_report___f_hw_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_hw_id = (unsigned)(((_val))); \
    } while (0) /* report.f_hw_id[8;0] */

#define PIF_HEADER_GET_report___f_seq_num(_hdr_p) (((_hdr_p)->f_seq_num)) /* report.f_seq_num [32;0] */

#define PIF_HEADER_SET_report___f_seq_num(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_seq_num = (unsigned)(((_val))); \
    } while (0) /* report.f_seq_num[32;0] */

#define PIF_HEADER_GET_report___f_ingress_ts___0(_hdr_p) (((_hdr_p)->__f_ingress_ts_1)) /* report.f_ingress_ts [32;0] */

#define PIF_HEADER_SET_report___f_ingress_ts___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__f_ingress_ts_1 = (unsigned)(((_val))); \
    } while (0) /* report.f_ingress_ts[32;0] */

#define PIF_HEADER_GET_report___f_ingress_ts___1(_hdr_p) (((_hdr_p)->f_ingress_ts)) /* report.f_ingress_ts [32;32] */

#define PIF_HEADER_SET_report___f_ingress_ts___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_ingress_ts = (unsigned)(((_val))); \
    } while (0) /* report.f_ingress_ts[32;32] */


/* shimINT (4B) */
struct pif_header_shimINT {
    unsigned int shim_type:8;
    unsigned int shim_reserved1:8;
    unsigned int shim_length:8;
    unsigned int shim_rsvd2:8;
};

/* shimINT field accessor macros */
#define PIF_HEADER_GET_shimINT___shim_type(_hdr_p) (((_hdr_p)->shim_type)) /* shimINT.shim_type [8;0] */

#define PIF_HEADER_SET_shimINT___shim_type(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_type = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_type[8;0] */

#define PIF_HEADER_GET_shimINT___shim_reserved1(_hdr_p) (((_hdr_p)->shim_reserved1)) /* shimINT.shim_reserved1 [8;0] */

#define PIF_HEADER_SET_shimINT___shim_reserved1(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_reserved1 = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_reserved1[8;0] */

#define PIF_HEADER_GET_shimINT___shim_length(_hdr_p) (((_hdr_p)->shim_length)) /* shimINT.shim_length [8;0] */

#define PIF_HEADER_SET_shimINT___shim_length(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_length = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_length[8;0] */

#define PIF_HEADER_GET_shimINT___shim_rsvd2(_hdr_p) (((_hdr_p)->shim_rsvd2)) /* shimINT.shim_rsvd2 [8;0] */

#define PIF_HEADER_SET_shimINT___shim_rsvd2(_hdr_p, _val) \
    do { \
        (_hdr_p)->shim_rsvd2 = (unsigned)(((_val))); \
    } while (0) /* shimINT.shim_rsvd2[8;0] */


/* ingressTimestamp (8B) */
struct pif_header_ingressTimestamp {
    /* int_ingressTimestamp [32;32] */
    unsigned int int_ingressTimestamp:32;
    /* int_ingressTimestamp [32;0] */
    unsigned int __int_ingressTimestamp_1:32;
};

/* ingressTimestamp field accessor macros */
#define PIF_HEADER_GET_ingressTimestamp___int_ingressTimestamp___0(_hdr_p) (((_hdr_p)->__int_ingressTimestamp_1)) /* ingressTimestamp.int_ingressTimestamp [32;0] */

#define PIF_HEADER_SET_ingressTimestamp___int_ingressTimestamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_ingressTimestamp_1 = (unsigned)(((_val))); \
    } while (0) /* ingressTimestamp.int_ingressTimestamp[32;0] */

#define PIF_HEADER_GET_ingressTimestamp___int_ingressTimestamp___1(_hdr_p) (((_hdr_p)->int_ingressTimestamp)) /* ingressTimestamp.int_ingressTimestamp [32;32] */

#define PIF_HEADER_SET_ingressTimestamp___int_ingressTimestamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_ingressTimestamp = (unsigned)(((_val))); \
    } while (0) /* ingressTimestamp.int_ingressTimestamp[32;32] */


/* tailINT (7B) */
struct pif_header_tailINT {
    unsigned int tail_header:32;
    unsigned int tail_proto:8;
    unsigned int tail_port:8;
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

#define PIF_HEADER_GET_tailINT___tail_port(_hdr_p) (((_hdr_p)->tail_port)) /* tailINT.tail_port [8;0] */

#define PIF_HEADER_SET_tailINT___tail_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_port = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_port[8;0] */

#define PIF_HEADER_GET_tailINT___tail_dscp(_hdr_p) (((_hdr_p)->tail_dscp)) /* tailINT.tail_dscp [8;0] */

#define PIF_HEADER_SET_tailINT___tail_dscp(_hdr_p, _val) \
    do { \
        (_hdr_p)->tail_dscp = (unsigned)(((_val))); \
    } while (0) /* tailINT.tail_dscp[8;0] */


/* hop_latency (8B) */
struct pif_header_hop_latency {
    /* int_hop_latency [32;32] */
    unsigned int int_hop_latency:32;
    /* int_hop_latency [32;0] */
    unsigned int __int_hop_latency_1:32;
};

/* hop_latency field accessor macros */
#define PIF_HEADER_GET_hop_latency___int_hop_latency___0(_hdr_p) (((_hdr_p)->__int_hop_latency_1)) /* hop_latency.int_hop_latency [32;0] */

#define PIF_HEADER_SET_hop_latency___int_hop_latency___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__int_hop_latency_1 = (unsigned)(((_val))); \
    } while (0) /* hop_latency.int_hop_latency[32;0] */

#define PIF_HEADER_GET_hop_latency___int_hop_latency___1(_hdr_p) (((_hdr_p)->int_hop_latency)) /* hop_latency.int_hop_latency [32;32] */

#define PIF_HEADER_SET_hop_latency___int_hop_latency___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->int_hop_latency = (unsigned)(((_val))); \
    } while (0) /* hop_latency.int_hop_latency[32;32] */


/*
 * Metadata
 */

/* intrinsic_metadata (16B) */
struct pif_header_intrinsic_metadata {
    /* ingress_global_tstamp [32;32] */
    unsigned int ingress_global_tstamp:32;
    /* ingress_global_tstamp [32;0] */
    unsigned int __ingress_global_tstamp_1:32;
    /* current_global_tstamp [32;32] */
    unsigned int current_global_tstamp:32;
    /* current_global_tstamp [32;0] */
    unsigned int __current_global_tstamp_1:32;
};

/* intrinsic_metadata field accessor macros */
#define PIF_HEADER_GET_intrinsic_metadata___ingress_global_tstamp___0(_hdr_p) (((_hdr_p)->__ingress_global_tstamp_1)) /* intrinsic_metadata.ingress_global_tstamp [32;0] */

#define PIF_HEADER_SET_intrinsic_metadata___ingress_global_tstamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__ingress_global_tstamp_1 = (unsigned)(((_val))); \
    } while (0) /* intrinsic_metadata.ingress_global_tstamp[32;0] */

#define PIF_HEADER_GET_intrinsic_metadata___ingress_global_tstamp___1(_hdr_p) (((_hdr_p)->ingress_global_tstamp)) /* intrinsic_metadata.ingress_global_tstamp [32;32] */

#define PIF_HEADER_SET_intrinsic_metadata___ingress_global_tstamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->ingress_global_tstamp = (unsigned)(((_val))); \
    } while (0) /* intrinsic_metadata.ingress_global_tstamp[32;32] */

#define PIF_HEADER_GET_intrinsic_metadata___current_global_tstamp___0(_hdr_p) (((_hdr_p)->__current_global_tstamp_1)) /* intrinsic_metadata.current_global_tstamp [32;0] */

#define PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__current_global_tstamp_1 = (unsigned)(((_val))); \
    } while (0) /* intrinsic_metadata.current_global_tstamp[32;0] */

#define PIF_HEADER_GET_intrinsic_metadata___current_global_tstamp___1(_hdr_p) (((_hdr_p)->current_global_tstamp)) /* intrinsic_metadata.current_global_tstamp [32;32] */

#define PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->current_global_tstamp = (unsigned)(((_val))); \
    } while (0) /* intrinsic_metadata.current_global_tstamp[32;32] */


/* switch_local (25B) */
struct pif_header_switch_local {
    unsigned int switch_id:16;
    unsigned int port_in:16;
    unsigned int port_out:16;
    unsigned int shimINTlength:16;
    unsigned int instruction:8;
    /* ingresststamp [24;40] */
    unsigned int ingresststamp:24;
    /* ingresststamp [32;8] */
    unsigned int __ingresststamp_1:32;
    /* ingresststamp [8;0] */
    unsigned int __ingresststamp_2:8;
    /* egresststamp [24;40] */
    unsigned int egresststamp:24;
    /* egresststamp [32;8] */
    unsigned int __egresststamp_1:32;
    /* egresststamp [8;0] */
    unsigned int __egresststamp_2:8;
};

/* switch_local field accessor macros */
#define PIF_HEADER_GET_switch_local___switch_id(_hdr_p) (((_hdr_p)->switch_id)) /* switch_local.switch_id [16;0] */

#define PIF_HEADER_SET_switch_local___switch_id(_hdr_p, _val) \
    do { \
        (_hdr_p)->switch_id = (unsigned)(((_val))); \
    } while (0) /* switch_local.switch_id[16;0] */

#define PIF_HEADER_GET_switch_local___port_in(_hdr_p) (((_hdr_p)->port_in)) /* switch_local.port_in [16;0] */

#define PIF_HEADER_SET_switch_local___port_in(_hdr_p, _val) \
    do { \
        (_hdr_p)->port_in = (unsigned)(((_val))); \
    } while (0) /* switch_local.port_in[16;0] */

#define PIF_HEADER_GET_switch_local___port_out(_hdr_p) (((_hdr_p)->port_out)) /* switch_local.port_out [16;0] */

#define PIF_HEADER_SET_switch_local___port_out(_hdr_p, _val) \
    do { \
        (_hdr_p)->port_out = (unsigned)(((_val))); \
    } while (0) /* switch_local.port_out[16;0] */

#define PIF_HEADER_GET_switch_local___shimINTlength(_hdr_p) (((_hdr_p)->shimINTlength)) /* switch_local.shimINTlength [16;0] */

#define PIF_HEADER_SET_switch_local___shimINTlength(_hdr_p, _val) \
    do { \
        (_hdr_p)->shimINTlength = (unsigned)(((_val))); \
    } while (0) /* switch_local.shimINTlength[16;0] */

#define PIF_HEADER_GET_switch_local___instruction(_hdr_p) (((_hdr_p)->instruction)) /* switch_local.instruction [8;0] */

#define PIF_HEADER_SET_switch_local___instruction(_hdr_p, _val) \
    do { \
        (_hdr_p)->instruction = (unsigned)(((_val))); \
    } while (0) /* switch_local.instruction[8;0] */

#define PIF_HEADER_GET_switch_local___ingresststamp___0(_hdr_p) ((((_hdr_p)->__ingresststamp_1 & 0xffffff) << 8) | ((_hdr_p)->__ingresststamp_2)) /* switch_local.ingresststamp [32;0] */

#define PIF_HEADER_SET_switch_local___ingresststamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__ingresststamp_1 &= (unsigned)(0xff000000); \
        (_hdr_p)->__ingresststamp_1 |= (unsigned)((((_val) >> 8) & 0xffffff)); \
        (_hdr_p)->__ingresststamp_2 = (unsigned)(((_val))); \
    } while (0) /* switch_local.ingresststamp[32;0] */

#define PIF_HEADER_GET_switch_local___ingresststamp___1(_hdr_p) (((_hdr_p)->ingresststamp << 8) | (((_hdr_p)->__ingresststamp_1 >> 24) & 0xff)) /* switch_local.ingresststamp [32;32] */

#define PIF_HEADER_SET_switch_local___ingresststamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->ingresststamp = (unsigned)(((_val) >> 8)); \
        (_hdr_p)->__ingresststamp_1 &= (unsigned)(0xffffff); \
        (_hdr_p)->__ingresststamp_1 |= (unsigned)((((_val) & 0xff) << 24)); \
    } while (0) /* switch_local.ingresststamp[32;32] */

#define PIF_HEADER_GET_switch_local___egresststamp___0(_hdr_p) ((((_hdr_p)->__egresststamp_1 & 0xffffff) << 8) | ((_hdr_p)->__egresststamp_2)) /* switch_local.egresststamp [32;0] */

#define PIF_HEADER_SET_switch_local___egresststamp___0(_hdr_p, _val) \
    do { \
        (_hdr_p)->__egresststamp_1 &= (unsigned)(0xff000000); \
        (_hdr_p)->__egresststamp_1 |= (unsigned)((((_val) >> 8) & 0xffffff)); \
        (_hdr_p)->__egresststamp_2 = (unsigned)(((_val))); \
    } while (0) /* switch_local.egresststamp[32;0] */

#define PIF_HEADER_GET_switch_local___egresststamp___1(_hdr_p) (((_hdr_p)->egresststamp << 8) | (((_hdr_p)->__egresststamp_1 >> 24) & 0xff)) /* switch_local.egresststamp [32;32] */

#define PIF_HEADER_SET_switch_local___egresststamp___1(_hdr_p, _val) \
    do { \
        (_hdr_p)->egresststamp = (unsigned)(((_val) >> 8)); \
        (_hdr_p)->__egresststamp_1 &= (unsigned)(0xffffff); \
        (_hdr_p)->__egresststamp_1 |= (unsigned)((((_val) & 0xff) << 24)); \
    } while (0) /* switch_local.egresststamp[32;32] */


/* standard_metadata (16B) */
struct pif_header_standard_metadata {
    unsigned int clone_spec:32;
    unsigned int egress_spec:16;
    unsigned int egress_port:16;
    unsigned int ingress_port:16;
    unsigned int packet_length:14;
    unsigned int checksum_error:1;
    unsigned int _padding_0:1;
    unsigned int egress_instance:10;
    unsigned int parser_error_location:8;
    unsigned int instance_type:4;
    unsigned int parser_status:3;
    unsigned int _padding_1:7;
};

/* standard_metadata field accessor macros */
#define PIF_HEADER_GET_standard_metadata___clone_spec(_hdr_p) (((_hdr_p)->clone_spec)) /* standard_metadata.clone_spec [32;0] */

#define PIF_HEADER_SET_standard_metadata___clone_spec(_hdr_p, _val) \
    do { \
        (_hdr_p)->clone_spec = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.clone_spec[32;0] */

#define PIF_HEADER_GET_standard_metadata___egress_spec(_hdr_p) (((_hdr_p)->egress_spec)) /* standard_metadata.egress_spec [16;0] */

#define PIF_HEADER_SET_standard_metadata___egress_spec(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_spec = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_spec[16;0] */

#define PIF_HEADER_GET_standard_metadata___egress_port(_hdr_p) (((_hdr_p)->egress_port)) /* standard_metadata.egress_port [16;0] */

#define PIF_HEADER_SET_standard_metadata___egress_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_port = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_port[16;0] */

#define PIF_HEADER_GET_standard_metadata___ingress_port(_hdr_p) (((_hdr_p)->ingress_port)) /* standard_metadata.ingress_port [16;0] */

#define PIF_HEADER_SET_standard_metadata___ingress_port(_hdr_p, _val) \
    do { \
        (_hdr_p)->ingress_port = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.ingress_port[16;0] */

#define PIF_HEADER_GET_standard_metadata___packet_length(_hdr_p) (((_hdr_p)->packet_length)) /* standard_metadata.packet_length [14;0] */

#define PIF_HEADER_SET_standard_metadata___packet_length(_hdr_p, _val) \
    do { \
        (_hdr_p)->packet_length = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.packet_length[14;0] */

#define PIF_HEADER_GET_standard_metadata___checksum_error(_hdr_p) (((_hdr_p)->checksum_error)) /* standard_metadata.checksum_error [1;0] */

#define PIF_HEADER_SET_standard_metadata___checksum_error(_hdr_p, _val) \
    do { \
        (_hdr_p)->checksum_error = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.checksum_error[1;0] */

#define PIF_HEADER_GET_standard_metadata____padding_0(_hdr_p) (((_hdr_p)->_padding_0)) /* standard_metadata._padding_0 [1;0] */

#define PIF_HEADER_SET_standard_metadata____padding_0(_hdr_p, _val) \
    do { \
        (_hdr_p)->_padding_0 = (unsigned)(((_val))); \
    } while (0) /* standard_metadata._padding_0[1;0] */

#define PIF_HEADER_GET_standard_metadata___egress_instance(_hdr_p) (((_hdr_p)->egress_instance)) /* standard_metadata.egress_instance [10;0] */

#define PIF_HEADER_SET_standard_metadata___egress_instance(_hdr_p, _val) \
    do { \
        (_hdr_p)->egress_instance = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.egress_instance[10;0] */

#define PIF_HEADER_GET_standard_metadata___parser_error_location(_hdr_p) (((_hdr_p)->parser_error_location)) /* standard_metadata.parser_error_location [8;0] */

#define PIF_HEADER_SET_standard_metadata___parser_error_location(_hdr_p, _val) \
    do { \
        (_hdr_p)->parser_error_location = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.parser_error_location[8;0] */

#define PIF_HEADER_GET_standard_metadata___instance_type(_hdr_p) (((_hdr_p)->instance_type)) /* standard_metadata.instance_type [4;0] */

#define PIF_HEADER_SET_standard_metadata___instance_type(_hdr_p, _val) \
    do { \
        (_hdr_p)->instance_type = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.instance_type[4;0] */

#define PIF_HEADER_GET_standard_metadata___parser_status(_hdr_p) (((_hdr_p)->parser_status)) /* standard_metadata.parser_status [3;0] */

#define PIF_HEADER_SET_standard_metadata___parser_status(_hdr_p, _val) \
    do { \
        (_hdr_p)->parser_status = (unsigned)(((_val))); \
    } while (0) /* standard_metadata.parser_status[3;0] */

#define PIF_HEADER_GET_standard_metadata____padding_1(_hdr_p) (((_hdr_p)->_padding_1)) /* standard_metadata._padding_1 [7;0] */

#define PIF_HEADER_SET_standard_metadata____padding_1(_hdr_p, _val) \
    do { \
        (_hdr_p)->_padding_1 = (unsigned)(((_val))); \
    } while (0) /* standard_metadata._padding_1[7;0] */



/*
 * Registers
 */

#endif /* __PIF_HEADERS_H__ */
