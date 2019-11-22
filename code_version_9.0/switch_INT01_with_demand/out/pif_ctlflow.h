/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_CTLFLOW_H__
#define __PIF_CTLFLOW_H__

/* Defines for checking flow presence */
#define PIF_CTLFLOW_HAS_ingress_flow
#define PIF_CTLFLOW_HAS_egress_flow

#define PIF_CTLFLOW_STATE_ingress 0
#define PIF_CTLFLOW_STATE_accept 0
/* Control state nodes for ingress_flow */
#define PIF_CTLFLOW_STATE_ingress_flow_DONE -1
#define PIF_CTLFLOW_STATE_ingress_flow_exit_control_flow -1
#define PIF_CTLFLOW_STATE_ingress_flow 0

#define PIF_CTLFLOW_STATE_ingress_flow_ingress__ipv4_lpm 0
#define PIF_CTLFLOW_STATE_ingress_flow__condition_2 1
#define PIF_CTLFLOW_STATE_ingress_flow_ingress__int_source 2
#define PIF_CTLFLOW_STATE_ingress_flow__condition_0 3
#define PIF_CTLFLOW_STATE_ingress_flow__condition_1 4
#define PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act 5
#define PIF_CTLFLOW_STATE_ingress_flow_ingress__arp_lpm 6

/* Control state nodes for egress_flow */
#define PIF_CTLFLOW_STATE_egress_flow_DONE -1
#define PIF_CTLFLOW_STATE_egress_flow_exit_control_flow -1
#define PIF_CTLFLOW_STATE_egress_flow 0

#define PIF_CTLFLOW_STATE_egress_flow__condition_3 0
#define PIF_CTLFLOW_STATE_egress_flow_egress__add_metadata 1

/* Unified control state numbers */
#define PIF_CTLFLOW_STATE_ingress__ipv4_lpm 0
#define PIF_CTLFLOW_STATE__condition_2 1
#define PIF_CTLFLOW_STATE_ingress__int_source 2
#define PIF_CTLFLOW_STATE__condition_0 3
#define PIF_CTLFLOW_STATE__condition_1 4
#define PIF_CTLFLOW_STATE_ingress__tbl_act 5
#define PIF_CTLFLOW_STATE_ingress__arp_lpm 6
#define PIF_CTLFLOW_STATE__condition_3 7
#define PIF_CTLFLOW_STATE_egress__add_metadata 8

/* Control flow entry points  */
int pif_ctlflow_ingress_flow(int *start_state, __lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off);
int pif_ctlflow_egress_flow(int *start_state, __lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off);

#endif /* __PIF_CTLFLOW_H__ */
