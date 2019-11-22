/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_HOPINT_H__
#define __PIF_PLUGIN_HOPINT_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* hopINT (8B) */
struct pif_plugin_hopINT {
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



#define PIF_PLUGIN_hopINT_T __lmem struct pif_plugin_hopINT

/*
 * Access function prototypes
 */

int pif_plugin_hdr_hopINT_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_hopINT_T *pif_plugin_hdr_get_hopINT(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_hopINT_T *pif_plugin_hdr_readonly_get_hopINT(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_hopINT_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_hopINT_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_hopINT_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_hopINT_VALID(_ctl);
}

__forceinline PIF_PLUGIN_hopINT_T *pif_plugin_hdr_get_hopINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_hopINT_DIRTY(_ctl);
    return (PIF_PLUGIN_hopINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_hopINT_OFF_LW);
}

__forceinline PIF_PLUGIN_hopINT_T *pif_plugin_hdr_readonly_get_hopINT(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_hopINT_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_hopINT_OFF_LW);
}

__forceinline int pif_plugin_hdr_hopINT_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    if (PIF_PARREP_T5_VALID(_ctl))
        return -1; /* either already present or incompatible header combination */
    PIF_PARREP_SET_hopINT_VALID(_ctl);
    return 0;
}

__forceinline int pif_plugin_hdr_hopINT_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_HOPINT_H__ */
