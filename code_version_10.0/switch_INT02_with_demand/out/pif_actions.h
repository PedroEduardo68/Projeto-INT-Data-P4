/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_ACTIONS_H__
#define __PIF_ACTIONS_H__

/* Warning: generated file - your edits to this file may be lost */

/* Action operation IDs */

#define PIF_ACTION_ID_ingress__act 0
#define PIF_ACTION_ID_egress__action_eq192 1
#define PIF_ACTION_ID_ingress__send_telemetry_report 2
#define PIF_ACTION_ID_ingress__act_0 3
#define PIF_ACTION_ID_ingress__act_1 4
#define PIF_ACTION_ID_ingress__arp_forward 5
#define PIF_ACTION_ID_egress__action_eq128 6
#define PIF_ACTION_ID_ingress__drop 7
#define PIF_ACTION_ID_egress__action_eq184 8
#define PIF_ACTION_ID_egress__action_eq240 9
#define PIF_ACTION_ID_egress__action_eq88 10
#define PIF_ACTION_ID_ingress__ipv4_forward 11
#define PIF_ACTION_ID_egress__action_eq254 12
#define PIF_ACTION_ID_egress__action_eq248 13
#define PIF_ACTION_ID_egress__action_eq160 14
#define PIF_ACTION_ID_egress__action_eq224 15
#define PIF_ACTION_ID_egress__action_eq252 16
#define PIF_ACTION_ID_MAX 16

/* Match action data structure */

__packed struct pif_action_actiondata_ingress__act {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq192 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_ingress__send_telemetry_report {
    uint32_t monitor_mac_1; /* monitor_mac[48:16] */
    uint32_t monitor_ip;
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
    uint16_t monitor_port;
    uint16_t monitor_mac_0; /* monitor_mac[16:0] */
};

__packed struct pif_action_actiondata_ingress__act_0 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_ingress__act_1 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_ingress__arp_forward {
    uint32_t dstmac_1; /* dstmac[48:16] */
    uint32_t srcmac_1; /* srcmac[48:16] */
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
    uint16_t srcmac_0; /* srcmac[16:0] */
    uint16_t dstmac_0; /* dstmac[16:0] */
    uint8_t __pif_padding[2]; /* padding */
    uint16_t espec;
};

__packed struct pif_action_actiondata_egress__action_eq128 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_ingress__drop {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq184 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq240 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq88 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_ingress__ipv4_forward {
    uint32_t dstmac_1; /* dstmac[48:16] */
    uint32_t srcmac_1; /* srcmac[48:16] */
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
    uint16_t srcmac_0; /* srcmac[16:0] */
    uint16_t dstmac_0; /* dstmac[16:0] */
    uint8_t __pif_padding[2]; /* padding */
    uint16_t espec;
};

__packed struct pif_action_actiondata_egress__action_eq254 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq248 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq160 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq224 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

__packed struct pif_action_actiondata_egress__action_eq252 {
    uint32_t __pif_rule_no;
    uint32_t __pif_table_no;
};

#endif /* __PIF_ACTIONS_H__ */
