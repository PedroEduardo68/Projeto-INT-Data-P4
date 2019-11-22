/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_PARREP_H__
#define __PIF_PARREP_H__

/* Generated C source defining layout of parsed representation */
/* Warning: your edits to this file may be lost */

/*
 * Parsed representation control data
 */
struct pif_parrep_ctldata {
    unsigned int valid:1;
    unsigned int t0_valid:1;
    unsigned int t0_dirty:1;
    unsigned int t0_orig_len:1;
    unsigned int t1_valid:1;
    unsigned int t1_dirty:1;
    unsigned int t1_orig_len:1;
    unsigned int t2_valid:1;
    unsigned int t2_dirty:1;
    unsigned int t2_orig_len:1;
    unsigned int t3_valid:1;
    unsigned int t3_dirty:1;
    unsigned int t3_orig_len:1;
    unsigned int t4_valid:1;
    unsigned int t4_dirty:1;
    unsigned int t4_orig_len:1;
    unsigned int t5_valid:1;
    unsigned int t5_dirty:1;
    unsigned int t5_orig_len:1;
    unsigned int t6_valid:1;
    unsigned int t6_dirty:1;
    unsigned int t6_orig_len:1;
    unsigned int t7_valid:1;
    unsigned int t7_type:1;
    unsigned int t7_dirty:1;
    unsigned int t7_orig_len:5;
    unsigned int _padding_0:2;
    unsigned int t8_valid:1;
    unsigned int t8_dirty:1;
    unsigned int t8_orig_len:1;
    unsigned int t9_valid:1;
    unsigned int t9_dirty:1;
    unsigned int t9_orig_len:1;
    unsigned int t10_valid:1;
    unsigned int t10_dirty:1;
    unsigned int t10_orig_len:1;
    unsigned int t11_valid:1;
    unsigned int t11_dirty:1;
    unsigned int t11_orig_len:1;
    unsigned int t12_valid:1;
    unsigned int t12_dirty:1;
    unsigned int t12_orig_len:1;
    unsigned int t13_valid:1;
    unsigned int t13_dirty:1;
    unsigned int t13_orig_len:1;
    unsigned int t14_valid:1;
    unsigned int t14_dirty:1;
    unsigned int t14_orig_len:1;
    unsigned int t15_valid:1;
    unsigned int t15_dirty:1;
    unsigned int t15_orig_len:1;
};

#define PIF_PARREP_CTLDATA_OFF_LW 0
#define PIF_PARREP_CTLDATA_LEN_LW 2

/*
 * Parsed representation layout
 */

/* Parsed represention tier types */
/* tier 7 */
#define PIF_PARREP_TYPE_udp 0
#define PIF_PARREP_TYPE_tcp 1

/* Parse state values */
#define PIF_PARREP_STATE_exit -1
#define PIF_PARREP_STATE_parse_tcp 3
#define PIF_PARREP_STATE_parse_udp 4
#define PIF_PARREP_STATE_parse_arp 1
#define PIF_PARREP_STATE_start 0
#define PIF_PARREP_STATE_parse_shimINT 5
#define PIF_PARREP_STATE_parse_ipv4 2
#define PIF_PARREP_MAX_STATE 5

/* Tier 0 */
#define PIF_PARREP_T0_OFF_LW 2
#define PIF_PARREP_T0_LEN_LW 4
#define PIF_PARREP_report_ethernet_OFF_LW (PIF_PARREP_T0_OFF_LW)
#define PIF_PARREP_report_ethernet_LEN_LW 4
#define PIF_PARREP_report_ethernet_LEN_B 14

/* Tier 1 */
#define PIF_PARREP_T1_OFF_LW 6
#define PIF_PARREP_T1_LEN_LW 5
#define PIF_PARREP_report_ipv4_OFF_LW (PIF_PARREP_T1_OFF_LW)
#define PIF_PARREP_report_ipv4_LEN_LW 5
#define PIF_PARREP_report_ipv4_LEN_B 20

/* Tier 2 */
#define PIF_PARREP_T2_OFF_LW 11
#define PIF_PARREP_T2_LEN_LW 2
#define PIF_PARREP_report_udp_OFF_LW (PIF_PARREP_T2_OFF_LW)
#define PIF_PARREP_report_udp_LEN_LW 2
#define PIF_PARREP_report_udp_LEN_B 8

/* Tier 3 */
#define PIF_PARREP_T3_OFF_LW 13
#define PIF_PARREP_T3_LEN_LW 4
#define PIF_PARREP_report_OFF_LW (PIF_PARREP_T3_OFF_LW)
#define PIF_PARREP_report_LEN_LW 4
#define PIF_PARREP_report_LEN_B 16

/* Tier 4 */
#define PIF_PARREP_T4_OFF_LW 17
#define PIF_PARREP_T4_LEN_LW 4
#define PIF_PARREP_ethernet_OFF_LW (PIF_PARREP_T4_OFF_LW)
#define PIF_PARREP_ethernet_LEN_LW 4
#define PIF_PARREP_ethernet_LEN_B 14

/* Tier 5 */
#define PIF_PARREP_T5_OFF_LW 21
#define PIF_PARREP_T5_LEN_LW 7
#define PIF_PARREP_arp_OFF_LW (PIF_PARREP_T5_OFF_LW)
#define PIF_PARREP_arp_LEN_LW 7
#define PIF_PARREP_arp_LEN_B 28

/* Tier 6 */
#define PIF_PARREP_T6_OFF_LW 28
#define PIF_PARREP_T6_LEN_LW 5
#define PIF_PARREP_ipv4_OFF_LW (PIF_PARREP_T6_OFF_LW)
#define PIF_PARREP_ipv4_LEN_LW 5
#define PIF_PARREP_ipv4_LEN_B 20

/* Tier 7 */
#define PIF_PARREP_T7_OFF_LW 33
#define PIF_PARREP_T7_LEN_LW 5
#define PIF_PARREP_udp_OFF_LW (PIF_PARREP_T7_OFF_LW)
#define PIF_PARREP_udp_LEN_LW 2
#define PIF_PARREP_udp_LEN_B 8
#define PIF_PARREP_tcp_OFF_LW (PIF_PARREP_T7_OFF_LW)
#define PIF_PARREP_tcp_LEN_LW 5
#define PIF_PARREP_tcp_LEN_B 20

/* Tier 8 */
#define PIF_PARREP_T8_OFF_LW 38
#define PIF_PARREP_T8_LEN_LW 1
#define PIF_PARREP_shimINT_OFF_LW (PIF_PARREP_T8_OFF_LW)
#define PIF_PARREP_shimINT_LEN_LW 1
#define PIF_PARREP_shimINT_LEN_B 4

/* Tier 9 */
#define PIF_PARREP_T9_OFF_LW 39
#define PIF_PARREP_T9_LEN_LW 2
#define PIF_PARREP_hopINT_OFF_LW (PIF_PARREP_T9_OFF_LW)
#define PIF_PARREP_hopINT_LEN_LW 2
#define PIF_PARREP_hopINT_LEN_B 8

/* Tier 10 */
#define PIF_PARREP_T10_OFF_LW 41
#define PIF_PARREP_T10_LEN_LW 1
#define PIF_PARREP_switch_id_OFF_LW (PIF_PARREP_T10_OFF_LW)
#define PIF_PARREP_switch_id_LEN_LW 1
#define PIF_PARREP_switch_id_LEN_B 4

/* Tier 11 */
#define PIF_PARREP_T11_OFF_LW 42
#define PIF_PARREP_T11_LEN_LW 1
#define PIF_PARREP_int_ingress_egress_ports_OFF_LW (PIF_PARREP_T11_OFF_LW)
#define PIF_PARREP_int_ingress_egress_ports_LEN_LW 1
#define PIF_PARREP_int_ingress_egress_ports_LEN_B 4

/* Tier 12 */
#define PIF_PARREP_T12_OFF_LW 43
#define PIF_PARREP_T12_LEN_LW 2
#define PIF_PARREP_hop_latency_OFF_LW (PIF_PARREP_T12_OFF_LW)
#define PIF_PARREP_hop_latency_LEN_LW 2
#define PIF_PARREP_hop_latency_LEN_B 8

/* Tier 13 */
#define PIF_PARREP_T13_OFF_LW 45
#define PIF_PARREP_T13_LEN_LW 2
#define PIF_PARREP_ingressTimestamp_OFF_LW (PIF_PARREP_T13_OFF_LW)
#define PIF_PARREP_ingressTimestamp_LEN_LW 2
#define PIF_PARREP_ingressTimestamp_LEN_B 8

/* Tier 14 */
#define PIF_PARREP_T14_OFF_LW 47
#define PIF_PARREP_T14_LEN_LW 2
#define PIF_PARREP_egressTimestamp_OFF_LW (PIF_PARREP_T14_OFF_LW)
#define PIF_PARREP_egressTimestamp_LEN_LW 2
#define PIF_PARREP_egressTimestamp_LEN_B 8

/* Tier 15 */
#define PIF_PARREP_T15_OFF_LW 49
#define PIF_PARREP_T15_LEN_LW 2
#define PIF_PARREP_tailINT_OFF_LW (PIF_PARREP_T15_OFF_LW)
#define PIF_PARREP_tailINT_LEN_LW 2
#define PIF_PARREP_tailINT_LEN_B 7

/*
 * Metadata
 */

#define PIF_PARREP_intrinsic_metadata_OFF_LW 51
#define PIF_PARREP_intrinsic_metadata_LEN_LW 4

#define PIF_PARREP_switch_local_OFF_LW 55
#define PIF_PARREP_switch_local_LEN_LW 7

#define PIF_PARREP_standard_metadata_OFF_LW 62
#define PIF_PARREP_standard_metadata_LEN_LW 4

#define PIF_PARREP_LEN_LW 66

/* Parsing branches to a constant control entry point */
#define PIF_PARREP_NO_VARIABLE_EXIT

/* Control data macros */
#define PIF_PARREP_VALID(_ctl) (_ctl->valid)
#define PIF_PARREP_SET_VALID(_ctl) \
    do { _ctl->valid = 1; } while (0)

/* Tier 0 */
#define PIF_PARREP_T0_TYPE(ctl) ( ((ctl)->t0_type))
#define PIF_PARREP_T0_VALID(ctl) ( ((ctl)->t0_valid))
#define PIF_PARREP_report_ethernet_VALID(ctl) ( ((ctl)->t0_valid) )
#define PIF_PARREP_SET_report_ethernet_VALID(ctl) \
    do { \
        (ctl)->t0_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_report_ethernet_VALID(ctl) \
    do { \
        (ctl)->t0_valid = 0; \
    } while(0);

#define PIF_PARREP_report_ethernet_DIRTY(_ctl) ((_ctl)->t0_dirty)
#define PIF_PARREP_T0_DIRTY(_ctl) ((_ctl)->t0_dirty)
#define PIF_PARREP_CLEAR_T0_DIRTY(_ctl)     do { \
        (_ctl)->t0_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T0_DIRTY(_ctl)     do { \
        (_ctl)->t0_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_report_ethernet_DIRTY(_ctl) \
    do { \
        (_ctl)->t0_dirty = 1; \
    } while(0);

#define PIF_PARREP_T0_ORIG_LEN(ctl) (((ctl)->t0_orig_len) ? PIF_PARREP_report_ethernet_LEN_B : 0)
#define PIF_PARREP_SET_T0_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t0_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_report_ethernet_ORIG_LEN(ctl) (((ctl)->t0_orig_len) ? PIF_PARREP_report_ethernet_LEN_B : 0)
#define PIF_PARREP_CLEAR_report_ethernet_ORIG_LEN(ctl) \
    do { \
        (ctl)->t0_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_report_ethernet_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t0_orig_len = 1; \
    } while(0);

/* Tier 1 */
#define PIF_PARREP_T1_TYPE(ctl) ( ((ctl)->t1_type))
#define PIF_PARREP_T1_VALID(ctl) ( ((ctl)->t1_valid))
#define PIF_PARREP_report_ipv4_VALID(ctl) ( ((ctl)->t1_valid) )
#define PIF_PARREP_SET_report_ipv4_VALID(ctl) \
    do { \
        (ctl)->t1_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_report_ipv4_VALID(ctl) \
    do { \
        (ctl)->t1_valid = 0; \
    } while(0);

#define PIF_PARREP_report_ipv4_DIRTY(_ctl) ((_ctl)->t1_dirty)
#define PIF_PARREP_T1_DIRTY(_ctl) ((_ctl)->t1_dirty)
#define PIF_PARREP_CLEAR_T1_DIRTY(_ctl)     do { \
        (_ctl)->t1_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T1_DIRTY(_ctl)     do { \
        (_ctl)->t1_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_report_ipv4_DIRTY(_ctl) \
    do { \
        (_ctl)->t1_dirty = 1; \
    } while(0);

#define PIF_PARREP_T1_ORIG_LEN(ctl) (((ctl)->t1_orig_len) ? PIF_PARREP_report_ipv4_LEN_B : 0)
#define PIF_PARREP_SET_T1_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t1_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_report_ipv4_ORIG_LEN(ctl) (((ctl)->t1_orig_len) ? PIF_PARREP_report_ipv4_LEN_B : 0)
#define PIF_PARREP_CLEAR_report_ipv4_ORIG_LEN(ctl) \
    do { \
        (ctl)->t1_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_report_ipv4_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t1_orig_len = 1; \
    } while(0);

/* Tier 2 */
#define PIF_PARREP_T2_TYPE(ctl) ( ((ctl)->t2_type))
#define PIF_PARREP_T2_VALID(ctl) ( ((ctl)->t2_valid))
#define PIF_PARREP_report_udp_VALID(ctl) ( ((ctl)->t2_valid) )
#define PIF_PARREP_SET_report_udp_VALID(ctl) \
    do { \
        (ctl)->t2_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_report_udp_VALID(ctl) \
    do { \
        (ctl)->t2_valid = 0; \
    } while(0);

#define PIF_PARREP_report_udp_DIRTY(_ctl) ((_ctl)->t2_dirty)
#define PIF_PARREP_T2_DIRTY(_ctl) ((_ctl)->t2_dirty)
#define PIF_PARREP_CLEAR_T2_DIRTY(_ctl)     do { \
        (_ctl)->t2_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T2_DIRTY(_ctl)     do { \
        (_ctl)->t2_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_report_udp_DIRTY(_ctl) \
    do { \
        (_ctl)->t2_dirty = 1; \
    } while(0);

#define PIF_PARREP_T2_ORIG_LEN(ctl) (((ctl)->t2_orig_len) ? PIF_PARREP_report_udp_LEN_B : 0)
#define PIF_PARREP_SET_T2_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t2_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_report_udp_ORIG_LEN(ctl) (((ctl)->t2_orig_len) ? PIF_PARREP_report_udp_LEN_B : 0)
#define PIF_PARREP_CLEAR_report_udp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t2_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_report_udp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t2_orig_len = 1; \
    } while(0);

/* Tier 3 */
#define PIF_PARREP_T3_TYPE(ctl) ( ((ctl)->t3_type))
#define PIF_PARREP_T3_VALID(ctl) ( ((ctl)->t3_valid))
#define PIF_PARREP_report_VALID(ctl) ( ((ctl)->t3_valid) )
#define PIF_PARREP_SET_report_VALID(ctl) \
    do { \
        (ctl)->t3_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_report_VALID(ctl) \
    do { \
        (ctl)->t3_valid = 0; \
    } while(0);

#define PIF_PARREP_report_DIRTY(_ctl) ((_ctl)->t3_dirty)
#define PIF_PARREP_T3_DIRTY(_ctl) ((_ctl)->t3_dirty)
#define PIF_PARREP_CLEAR_T3_DIRTY(_ctl)     do { \
        (_ctl)->t3_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T3_DIRTY(_ctl)     do { \
        (_ctl)->t3_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_report_DIRTY(_ctl) \
    do { \
        (_ctl)->t3_dirty = 1; \
    } while(0);

#define PIF_PARREP_T3_ORIG_LEN(ctl) (((ctl)->t3_orig_len) ? PIF_PARREP_report_LEN_B : 0)
#define PIF_PARREP_SET_T3_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t3_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_report_ORIG_LEN(ctl) (((ctl)->t3_orig_len) ? PIF_PARREP_report_LEN_B : 0)
#define PIF_PARREP_CLEAR_report_ORIG_LEN(ctl) \
    do { \
        (ctl)->t3_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_report_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t3_orig_len = 1; \
    } while(0);

/* Tier 4 */
#define PIF_PARREP_T4_TYPE(ctl) ( ((ctl)->t4_type))
#define PIF_PARREP_T4_VALID(ctl) ( ((ctl)->t4_valid))
#define PIF_PARREP_ethernet_VALID(ctl) ( ((ctl)->t4_valid) )
#define PIF_PARREP_SET_ethernet_VALID(ctl) \
    do { \
        (ctl)->t4_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_ethernet_VALID(ctl) \
    do { \
        (ctl)->t4_valid = 0; \
    } while(0);

#define PIF_PARREP_ethernet_DIRTY(_ctl) ((_ctl)->t4_dirty)
#define PIF_PARREP_T4_DIRTY(_ctl) ((_ctl)->t4_dirty)
#define PIF_PARREP_CLEAR_T4_DIRTY(_ctl)     do { \
        (_ctl)->t4_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T4_DIRTY(_ctl)     do { \
        (_ctl)->t4_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_ethernet_DIRTY(_ctl) \
    do { \
        (_ctl)->t4_dirty = 1; \
    } while(0);

#define PIF_PARREP_T4_ORIG_LEN(ctl) (((ctl)->t4_orig_len) ? PIF_PARREP_ethernet_LEN_B : 0)
#define PIF_PARREP_SET_T4_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t4_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_ethernet_ORIG_LEN(ctl) (((ctl)->t4_orig_len) ? PIF_PARREP_ethernet_LEN_B : 0)
#define PIF_PARREP_CLEAR_ethernet_ORIG_LEN(ctl) \
    do { \
        (ctl)->t4_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_ethernet_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t4_orig_len = 1; \
    } while(0);

/* Tier 5 */
#define PIF_PARREP_T5_TYPE(ctl) ( ((ctl)->t5_type))
#define PIF_PARREP_T5_VALID(ctl) ( ((ctl)->t5_valid))
#define PIF_PARREP_arp_VALID(ctl) ( ((ctl)->t5_valid) )
#define PIF_PARREP_SET_arp_VALID(ctl) \
    do { \
        (ctl)->t5_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_arp_VALID(ctl) \
    do { \
        (ctl)->t5_valid = 0; \
    } while(0);

#define PIF_PARREP_arp_DIRTY(_ctl) ((_ctl)->t5_dirty)
#define PIF_PARREP_T5_DIRTY(_ctl) ((_ctl)->t5_dirty)
#define PIF_PARREP_CLEAR_T5_DIRTY(_ctl)     do { \
        (_ctl)->t5_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T5_DIRTY(_ctl)     do { \
        (_ctl)->t5_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_arp_DIRTY(_ctl) \
    do { \
        (_ctl)->t5_dirty = 1; \
    } while(0);

#define PIF_PARREP_T5_ORIG_LEN(ctl) (((ctl)->t5_orig_len) ? PIF_PARREP_arp_LEN_B : 0)
#define PIF_PARREP_SET_T5_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t5_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_arp_ORIG_LEN(ctl) (((ctl)->t5_orig_len) ? PIF_PARREP_arp_LEN_B : 0)
#define PIF_PARREP_CLEAR_arp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t5_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_arp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t5_orig_len = 1; \
    } while(0);

/* Tier 6 */
#define PIF_PARREP_T6_TYPE(ctl) ( ((ctl)->t6_type))
#define PIF_PARREP_T6_VALID(ctl) ( ((ctl)->t6_valid))
#define PIF_PARREP_ipv4_VALID(ctl) ( ((ctl)->t6_valid) )
#define PIF_PARREP_SET_ipv4_VALID(ctl) \
    do { \
        (ctl)->t6_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_ipv4_VALID(ctl) \
    do { \
        (ctl)->t6_valid = 0; \
    } while(0);

#define PIF_PARREP_ipv4_DIRTY(_ctl) ((_ctl)->t6_dirty)
#define PIF_PARREP_T6_DIRTY(_ctl) ((_ctl)->t6_dirty)
#define PIF_PARREP_CLEAR_T6_DIRTY(_ctl)     do { \
        (_ctl)->t6_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T6_DIRTY(_ctl)     do { \
        (_ctl)->t6_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_ipv4_DIRTY(_ctl) \
    do { \
        (_ctl)->t6_dirty = 1; \
    } while(0);

#define PIF_PARREP_T6_ORIG_LEN(ctl) (((ctl)->t6_orig_len) ? PIF_PARREP_ipv4_LEN_B : 0)
#define PIF_PARREP_SET_T6_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t6_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_ipv4_ORIG_LEN(ctl) (((ctl)->t6_orig_len) ? PIF_PARREP_ipv4_LEN_B : 0)
#define PIF_PARREP_CLEAR_ipv4_ORIG_LEN(ctl) \
    do { \
        (ctl)->t6_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_ipv4_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t6_orig_len = 1; \
    } while(0);

/* Tier 7 */
#define PIF_PARREP_T7_TYPE(ctl) ( ((ctl)->t7_type))
#define PIF_PARREP_T7_VALID(ctl) ( ((ctl)->t7_valid & 0x1) )
#define PIF_PARREP_udp_VALID(ctl) ( ((ctl)->t7_valid & 0x1) && ((ctl)->t7_type == PIF_PARREP_TYPE_udp) )
#define PIF_PARREP_SET_udp_VALID(ctl) \
    do { \
        (ctl)->t7_valid = 1; \
        (ctl)->t7_type = PIF_PARREP_TYPE_udp; \
    } while(0);
#define PIF_PARREP_CLEAR_udp_VALID(ctl) \
    do { \
        (ctl)->t7_valid = 0; \
    } while(0);
#define PIF_PARREP_tcp_VALID(ctl) ( ((ctl)->t7_valid & 0x1) && ((ctl)->t7_type == PIF_PARREP_TYPE_tcp) )
#define PIF_PARREP_SET_tcp_VALID(ctl) \
    do { \
        (ctl)->t7_valid = 1; \
        (ctl)->t7_type = PIF_PARREP_TYPE_tcp; \
    } while(0);
#define PIF_PARREP_CLEAR_tcp_VALID(ctl) \
    do { \
        (ctl)->t7_valid = 0; \
    } while(0);

#define PIF_PARREP_udp_DIRTY(_ctl) ((_ctl)->t7_dirty)
#define PIF_PARREP_tcp_DIRTY(_ctl) ((_ctl)->t7_dirty)
#define PIF_PARREP_T7_DIRTY(_ctl) ((_ctl)->t7_dirty)
#define PIF_PARREP_CLEAR_T7_DIRTY(_ctl)     do { \
        (_ctl)->t7_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T7_DIRTY(_ctl)     do { \
        (_ctl)->t7_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_udp_DIRTY(_ctl) \
    do { \
        (_ctl)->t7_dirty = 1; \
    } while(0);
#define PIF_PARREP_SET_tcp_DIRTY(_ctl) \
    do { \
        (_ctl)->t7_dirty = 1; \
    } while(0);

#define PIF_PARREP_T7_ORIG_LEN(ctl) ((ctl)->t7_orig_len)
#define PIF_PARREP_SET_T7_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len = len; \
    } while(0);
#define PIF_PARREP_INC_T7_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len += len; \
    } while(0);
#define PIF_PARREP_udp_ORIG_LEN(ctl) ((ctl)->t7_orig_len)
#define PIF_PARREP_CLEAR_udp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t7_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_udp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len = len; \
    } while(0);
#define PIF_PARREP_INC_udp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len += len; \
    } while(0);
#define PIF_PARREP_tcp_ORIG_LEN(ctl) ((ctl)->t7_orig_len)
#define PIF_PARREP_CLEAR_tcp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t7_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_tcp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len = len; \
    } while(0);
#define PIF_PARREP_INC_tcp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t7_orig_len += len; \
    } while(0);

/* Tier 8 */
#define PIF_PARREP_T8_TYPE(ctl) ( ((ctl)->t8_type))
#define PIF_PARREP_T8_VALID(ctl) ( ((ctl)->t8_valid))
#define PIF_PARREP_shimINT_VALID(ctl) ( ((ctl)->t8_valid) )
#define PIF_PARREP_SET_shimINT_VALID(ctl) \
    do { \
        (ctl)->t8_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_shimINT_VALID(ctl) \
    do { \
        (ctl)->t8_valid = 0; \
    } while(0);

#define PIF_PARREP_shimINT_DIRTY(_ctl) ((_ctl)->t8_dirty)
#define PIF_PARREP_T8_DIRTY(_ctl) ((_ctl)->t8_dirty)
#define PIF_PARREP_CLEAR_T8_DIRTY(_ctl)     do { \
        (_ctl)->t8_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T8_DIRTY(_ctl)     do { \
        (_ctl)->t8_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_shimINT_DIRTY(_ctl) \
    do { \
        (_ctl)->t8_dirty = 1; \
    } while(0);

#define PIF_PARREP_T8_ORIG_LEN(ctl) (((ctl)->t8_orig_len) ? PIF_PARREP_shimINT_LEN_B : 0)
#define PIF_PARREP_SET_T8_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t8_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_shimINT_ORIG_LEN(ctl) (((ctl)->t8_orig_len) ? PIF_PARREP_shimINT_LEN_B : 0)
#define PIF_PARREP_CLEAR_shimINT_ORIG_LEN(ctl) \
    do { \
        (ctl)->t8_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_shimINT_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t8_orig_len = 1; \
    } while(0);

/* Tier 9 */
#define PIF_PARREP_T9_TYPE(ctl) ( ((ctl)->t9_type))
#define PIF_PARREP_T9_VALID(ctl) ( ((ctl)->t9_valid))
#define PIF_PARREP_hopINT_VALID(ctl) ( ((ctl)->t9_valid) )
#define PIF_PARREP_SET_hopINT_VALID(ctl) \
    do { \
        (ctl)->t9_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_hopINT_VALID(ctl) \
    do { \
        (ctl)->t9_valid = 0; \
    } while(0);

#define PIF_PARREP_hopINT_DIRTY(_ctl) ((_ctl)->t9_dirty)
#define PIF_PARREP_T9_DIRTY(_ctl) ((_ctl)->t9_dirty)
#define PIF_PARREP_CLEAR_T9_DIRTY(_ctl)     do { \
        (_ctl)->t9_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T9_DIRTY(_ctl)     do { \
        (_ctl)->t9_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_hopINT_DIRTY(_ctl) \
    do { \
        (_ctl)->t9_dirty = 1; \
    } while(0);

#define PIF_PARREP_T9_ORIG_LEN(ctl) (((ctl)->t9_orig_len) ? PIF_PARREP_hopINT_LEN_B : 0)
#define PIF_PARREP_SET_T9_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t9_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_hopINT_ORIG_LEN(ctl) (((ctl)->t9_orig_len) ? PIF_PARREP_hopINT_LEN_B : 0)
#define PIF_PARREP_CLEAR_hopINT_ORIG_LEN(ctl) \
    do { \
        (ctl)->t9_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_hopINT_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t9_orig_len = 1; \
    } while(0);

/* Tier 10 */
#define PIF_PARREP_T10_TYPE(ctl) ( ((ctl)->t10_type))
#define PIF_PARREP_T10_VALID(ctl) ( ((ctl)->t10_valid))
#define PIF_PARREP_switch_id_VALID(ctl) ( ((ctl)->t10_valid) )
#define PIF_PARREP_SET_switch_id_VALID(ctl) \
    do { \
        (ctl)->t10_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_switch_id_VALID(ctl) \
    do { \
        (ctl)->t10_valid = 0; \
    } while(0);

#define PIF_PARREP_switch_id_DIRTY(_ctl) ((_ctl)->t10_dirty)
#define PIF_PARREP_T10_DIRTY(_ctl) ((_ctl)->t10_dirty)
#define PIF_PARREP_CLEAR_T10_DIRTY(_ctl)     do { \
        (_ctl)->t10_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T10_DIRTY(_ctl)     do { \
        (_ctl)->t10_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_switch_id_DIRTY(_ctl) \
    do { \
        (_ctl)->t10_dirty = 1; \
    } while(0);

#define PIF_PARREP_T10_ORIG_LEN(ctl) (((ctl)->t10_orig_len) ? PIF_PARREP_switch_id_LEN_B : 0)
#define PIF_PARREP_SET_T10_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t10_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_switch_id_ORIG_LEN(ctl) (((ctl)->t10_orig_len) ? PIF_PARREP_switch_id_LEN_B : 0)
#define PIF_PARREP_CLEAR_switch_id_ORIG_LEN(ctl) \
    do { \
        (ctl)->t10_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_switch_id_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t10_orig_len = 1; \
    } while(0);

/* Tier 11 */
#define PIF_PARREP_T11_TYPE(ctl) ( ((ctl)->t11_type))
#define PIF_PARREP_T11_VALID(ctl) ( ((ctl)->t11_valid))
#define PIF_PARREP_int_ingress_egress_ports_VALID(ctl) ( ((ctl)->t11_valid) )
#define PIF_PARREP_SET_int_ingress_egress_ports_VALID(ctl) \
    do { \
        (ctl)->t11_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_int_ingress_egress_ports_VALID(ctl) \
    do { \
        (ctl)->t11_valid = 0; \
    } while(0);

#define PIF_PARREP_int_ingress_egress_ports_DIRTY(_ctl) ((_ctl)->t11_dirty)
#define PIF_PARREP_T11_DIRTY(_ctl) ((_ctl)->t11_dirty)
#define PIF_PARREP_CLEAR_T11_DIRTY(_ctl)     do { \
        (_ctl)->t11_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T11_DIRTY(_ctl)     do { \
        (_ctl)->t11_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_ctl) \
    do { \
        (_ctl)->t11_dirty = 1; \
    } while(0);

#define PIF_PARREP_T11_ORIG_LEN(ctl) (((ctl)->t11_orig_len) ? PIF_PARREP_int_ingress_egress_ports_LEN_B : 0)
#define PIF_PARREP_SET_T11_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t11_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_int_ingress_egress_ports_ORIG_LEN(ctl) (((ctl)->t11_orig_len) ? PIF_PARREP_int_ingress_egress_ports_LEN_B : 0)
#define PIF_PARREP_CLEAR_int_ingress_egress_ports_ORIG_LEN(ctl) \
    do { \
        (ctl)->t11_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_int_ingress_egress_ports_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t11_orig_len = 1; \
    } while(0);

/* Tier 12 */
#define PIF_PARREP_T12_TYPE(ctl) ( ((ctl)->t12_type))
#define PIF_PARREP_T12_VALID(ctl) ( ((ctl)->t12_valid))
#define PIF_PARREP_hop_latency_VALID(ctl) ( ((ctl)->t12_valid) )
#define PIF_PARREP_SET_hop_latency_VALID(ctl) \
    do { \
        (ctl)->t12_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_hop_latency_VALID(ctl) \
    do { \
        (ctl)->t12_valid = 0; \
    } while(0);

#define PIF_PARREP_hop_latency_DIRTY(_ctl) ((_ctl)->t12_dirty)
#define PIF_PARREP_T12_DIRTY(_ctl) ((_ctl)->t12_dirty)
#define PIF_PARREP_CLEAR_T12_DIRTY(_ctl)     do { \
        (_ctl)->t12_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T12_DIRTY(_ctl)     do { \
        (_ctl)->t12_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_hop_latency_DIRTY(_ctl) \
    do { \
        (_ctl)->t12_dirty = 1; \
    } while(0);

#define PIF_PARREP_T12_ORIG_LEN(ctl) (((ctl)->t12_orig_len) ? PIF_PARREP_hop_latency_LEN_B : 0)
#define PIF_PARREP_SET_T12_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t12_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_hop_latency_ORIG_LEN(ctl) (((ctl)->t12_orig_len) ? PIF_PARREP_hop_latency_LEN_B : 0)
#define PIF_PARREP_CLEAR_hop_latency_ORIG_LEN(ctl) \
    do { \
        (ctl)->t12_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_hop_latency_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t12_orig_len = 1; \
    } while(0);

/* Tier 13 */
#define PIF_PARREP_T13_TYPE(ctl) ( ((ctl)->t13_type))
#define PIF_PARREP_T13_VALID(ctl) ( ((ctl)->t13_valid))
#define PIF_PARREP_ingressTimestamp_VALID(ctl) ( ((ctl)->t13_valid) )
#define PIF_PARREP_SET_ingressTimestamp_VALID(ctl) \
    do { \
        (ctl)->t13_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_ingressTimestamp_VALID(ctl) \
    do { \
        (ctl)->t13_valid = 0; \
    } while(0);

#define PIF_PARREP_ingressTimestamp_DIRTY(_ctl) ((_ctl)->t13_dirty)
#define PIF_PARREP_T13_DIRTY(_ctl) ((_ctl)->t13_dirty)
#define PIF_PARREP_CLEAR_T13_DIRTY(_ctl)     do { \
        (_ctl)->t13_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T13_DIRTY(_ctl)     do { \
        (_ctl)->t13_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_ingressTimestamp_DIRTY(_ctl) \
    do { \
        (_ctl)->t13_dirty = 1; \
    } while(0);

#define PIF_PARREP_T13_ORIG_LEN(ctl) (((ctl)->t13_orig_len) ? PIF_PARREP_ingressTimestamp_LEN_B : 0)
#define PIF_PARREP_SET_T13_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t13_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_ingressTimestamp_ORIG_LEN(ctl) (((ctl)->t13_orig_len) ? PIF_PARREP_ingressTimestamp_LEN_B : 0)
#define PIF_PARREP_CLEAR_ingressTimestamp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t13_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_ingressTimestamp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t13_orig_len = 1; \
    } while(0);

/* Tier 14 */
#define PIF_PARREP_T14_TYPE(ctl) ( ((ctl)->t14_type))
#define PIF_PARREP_T14_VALID(ctl) ( ((ctl)->t14_valid))
#define PIF_PARREP_egressTimestamp_VALID(ctl) ( ((ctl)->t14_valid) )
#define PIF_PARREP_SET_egressTimestamp_VALID(ctl) \
    do { \
        (ctl)->t14_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_egressTimestamp_VALID(ctl) \
    do { \
        (ctl)->t14_valid = 0; \
    } while(0);

#define PIF_PARREP_egressTimestamp_DIRTY(_ctl) ((_ctl)->t14_dirty)
#define PIF_PARREP_T14_DIRTY(_ctl) ((_ctl)->t14_dirty)
#define PIF_PARREP_CLEAR_T14_DIRTY(_ctl)     do { \
        (_ctl)->t14_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T14_DIRTY(_ctl)     do { \
        (_ctl)->t14_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_egressTimestamp_DIRTY(_ctl) \
    do { \
        (_ctl)->t14_dirty = 1; \
    } while(0);

#define PIF_PARREP_T14_ORIG_LEN(ctl) (((ctl)->t14_orig_len) ? PIF_PARREP_egressTimestamp_LEN_B : 0)
#define PIF_PARREP_SET_T14_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t14_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_egressTimestamp_ORIG_LEN(ctl) (((ctl)->t14_orig_len) ? PIF_PARREP_egressTimestamp_LEN_B : 0)
#define PIF_PARREP_CLEAR_egressTimestamp_ORIG_LEN(ctl) \
    do { \
        (ctl)->t14_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_egressTimestamp_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t14_orig_len = 1; \
    } while(0);

/* Tier 15 */
#define PIF_PARREP_T15_TYPE(ctl) ( ((ctl)->t15_type))
#define PIF_PARREP_T15_VALID(ctl) ( ((ctl)->t15_valid))
#define PIF_PARREP_tailINT_VALID(ctl) ( ((ctl)->t15_valid) )
#define PIF_PARREP_SET_tailINT_VALID(ctl) \
    do { \
        (ctl)->t15_valid = 1; \
    } while(0);
#define PIF_PARREP_CLEAR_tailINT_VALID(ctl) \
    do { \
        (ctl)->t15_valid = 0; \
    } while(0);

#define PIF_PARREP_tailINT_DIRTY(_ctl) ((_ctl)->t15_dirty)
#define PIF_PARREP_T15_DIRTY(_ctl) ((_ctl)->t15_dirty)
#define PIF_PARREP_CLEAR_T15_DIRTY(_ctl)     do { \
        (_ctl)->t15_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_T15_DIRTY(_ctl)     do { \
        (_ctl)->t15_dirty = 0; \
    } while(0);
#define PIF_PARREP_SET_tailINT_DIRTY(_ctl) \
    do { \
        (_ctl)->t15_dirty = 1; \
    } while(0);

#define PIF_PARREP_T15_ORIG_LEN(ctl) (((ctl)->t15_orig_len) ? PIF_PARREP_tailINT_LEN_B : 0)
#define PIF_PARREP_SET_T15_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t15_orig_len = (len == 0 ? 0 : 1); \
    } while(0);
#define PIF_PARREP_tailINT_ORIG_LEN(ctl) (((ctl)->t15_orig_len) ? PIF_PARREP_tailINT_LEN_B : 0)
#define PIF_PARREP_CLEAR_tailINT_ORIG_LEN(ctl) \
    do { \
        (ctl)->t15_orig_len = 0; \
    } while(0);
#define PIF_PARREP_SET_tailINT_ORIG_LEN(ctl, len) \
    do { \
        (ctl)->t15_orig_len = 1; \
    } while(0);



void pif_value_set_scan_configs();

#endif /* __PIF_PARREP_H__ */
