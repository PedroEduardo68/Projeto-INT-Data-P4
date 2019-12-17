/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PLUGIN_REPORT_H__
#define __PIF_PLUGIN_REPORT_H__

/* This file is generated, edit at your peril */

/*
 * Header type definition
 */

/* report (12B) */
struct pif_plugin_report {
    unsigned int f_version:8;
    unsigned int f_next_proto:8;
    unsigned int f_drop:1;
    unsigned int f_queue:1;
    unsigned int f_flow:1;
    unsigned int f_rsvd:5;
    unsigned int f_hw_id:8;
    unsigned int f_seq_num:32;
    unsigned int f_ingress_ts:32;
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

#define PIF_HEADER_GET_report___f_ingress_ts(_hdr_p) (((_hdr_p)->f_ingress_ts)) /* report.f_ingress_ts [32;0] */

#define PIF_HEADER_SET_report___f_ingress_ts(_hdr_p, _val) \
    do { \
        (_hdr_p)->f_ingress_ts = (unsigned)(((_val))); \
    } while (0) /* report.f_ingress_ts[32;0] */



#define PIF_PLUGIN_report_T __lmem struct pif_plugin_report

/*
 * Access function prototypes
 */

int pif_plugin_hdr_report_present(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_T *pif_plugin_hdr_get_report(EXTRACTED_HEADERS_T *extracted_headers);

PIF_PLUGIN_report_T *pif_plugin_hdr_readonly_get_report(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_add(EXTRACTED_HEADERS_T *extracted_headers);

int pif_plugin_hdr_report_remove(EXTRACTED_HEADERS_T *extracted_headers);






/*
 * Access function implementations
 */

#include "pif_parrep.h"

__forceinline int pif_plugin_hdr_report_present(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return PIF_PARREP_report_VALID(_ctl);
}

__forceinline PIF_PLUGIN_report_T *pif_plugin_hdr_get_report(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    PIF_PARREP_SET_report_DIRTY(_ctl);
    return (PIF_PLUGIN_report_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
}

__forceinline PIF_PLUGIN_report_T *pif_plugin_hdr_readonly_get_report(EXTRACTED_HEADERS_T *extracted_headers)
{
    __lmem struct pif_parrep_ctldata *_ctl = (__lmem struct pif_parrep_ctldata *)extracted_headers;
    return (PIF_PLUGIN_report_T *)(((__lmem uint32_t *)extracted_headers) + PIF_PARREP_report_OFF_LW);
}

__forceinline int pif_plugin_hdr_report_add(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not addable in the P4 design */
}

__forceinline int pif_plugin_hdr_report_remove(EXTRACTED_HEADERS_T *extracted_headers)
{
    return -1; /* this header is not removable in the P4 design */
}

#endif /* __PIF_PLUGIN_REPORT_H__ */
