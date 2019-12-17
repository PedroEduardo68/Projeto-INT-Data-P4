/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#include <nfp/me.h>
#include "pif_common.h"

/****************************************
 * ingress_flow                         *
 ****************************************/

/* State transition functions */

static int handle_ingress_flow__condition_4(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_4_register_0;
    __lmem struct pif_header_ipv4 *ipv4;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow__condition_4");
#endif

    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);

    //expression _condition_4: ((ipv4.typeServiceDiffServ) == (23))
    {
    unsigned int pif_expression__condition_4_register_1;
    unsigned int pif_expression__condition_4_register_2;
    unsigned int pif_expression__condition_4_register_3;
    //subexpression 2: 23
    // constant : 0x17

    //subexpression 0: (ipv4.typeServiceDiffServ)==(23)
    pif_expression__condition_4_register_1 = ipv4->typeServiceDiffServ;
    pif_expression__condition_4_register_2 = 0x17;
    /* implicit cast 5 -> 8 */
    pif_expression__condition_4_register_3 = pif_expression__condition_4_register_2 & 0x1f;
    pif_expression__condition_4_register_0 = (pif_expression__condition_4_register_1 == pif_expression__condition_4_register_3);
    }

    if (pif_expression__condition_4_register_0)
        return PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act_1;
    else
        return PIF_CTLFLOW_STATE_ingress_flow_exit_control_flow;
}

static int handle_ingress_flow_ingress__arp_lpm(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__arp_lpm");
#endif

    {
        struct pif_lookup_result result;
        result = pif_lookup(PIF_TABLE_ID_ingress__arp_lpm, _pif_parrep, actbuf, actbuf_off);
        action_id = result.action_id;
        *actlen = result.action_len;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow__condition_3; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

static int handle_ingress_flow__condition_3(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_3_register_0;
    __lmem struct pif_parrep_ctldata *prdata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow__condition_3");
#endif

    //expression _condition_3: (valid(ethernet))
    {
    //subexpression 0: valid(ethernet)
    pif_expression__condition_3_register_0 = PIF_PARREP_ethernet_VALID(prdata);
    }

    if (pif_expression__condition_3_register_0)
        return PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act_0;
    else
        return PIF_CTLFLOW_STATE_ingress_flow__condition_4;
}

static int handle_ingress_flow_ingress__tbl_act_0(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__tbl_act_0");
#endif

    {
        struct pif_action_actiondata_ingress__act_0 actdata;
        __xwrite struct {
            union pif_action_opdata opdata;
            struct pif_action_actiondata_ingress__act_0 actdata;
            } wr_buf;

        wr_buf.opdata.val32 = (PIF_ACTION_ID_ingress__act_0 << PIF_ACTION_OPDATA_ACTION_ID_off) | ((sizeof(actdata) / 4) << PIF_ACTION_OPDATA_ACTDATA_CNT_off);
        actdata.__pif_table_no = 0xffffffff;
        actdata.__pif_rule_no = 0x0;
        wr_buf.actdata = actdata;

        mem_write32(&wr_buf,
                    actbuf + actbuf_off,
                    sizeof(wr_buf));
        *actlen = sizeof(wr_buf)/4;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow__condition_4; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

static int handle_ingress_flow__condition_2(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_2_register_0;
    __lmem struct pif_header_ipv4 *ipv4;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow__condition_2");
#endif

    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);

    //expression _condition_2: ((ipv4.typeServiceDiffServ) == (23))
    {
    unsigned int pif_expression__condition_2_register_1;
    unsigned int pif_expression__condition_2_register_2;
    unsigned int pif_expression__condition_2_register_3;
    //subexpression 2: 23
    // constant : 0x17

    //subexpression 0: (ipv4.typeServiceDiffServ)==(23)
    pif_expression__condition_2_register_1 = ipv4->typeServiceDiffServ;
    pif_expression__condition_2_register_2 = 0x17;
    /* implicit cast 5 -> 8 */
    pif_expression__condition_2_register_3 = pif_expression__condition_2_register_2 & 0x1f;
    pif_expression__condition_2_register_0 = (pif_expression__condition_2_register_1 == pif_expression__condition_2_register_3);
    }

    if (pif_expression__condition_2_register_0)
        return PIF_CTLFLOW_STATE_ingress_flow_ingress__process_int_report;
    else
        return PIF_CTLFLOW_STATE_ingress_flow__condition_3;
}

static int handle_ingress_flow_ingress__process_int_report(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__process_int_report");
#endif

    {
        struct pif_lookup_result result;
        result = pif_lookup(PIF_TABLE_ID_ingress__process_int_report, _pif_parrep, actbuf, actbuf_off);
        action_id = result.action_id;
        *actlen = result.action_len;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow__condition_3; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

static int handle_ingress_flow_ingress__ipv4_lpm(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__ipv4_lpm");
#endif

    {
        struct pif_lookup_result result;
        result = pif_lookup(PIF_TABLE_ID_ingress__ipv4_lpm, _pif_parrep, actbuf, actbuf_off);
        action_id = result.action_id;
        *actlen = result.action_len;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow__condition_2; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

static int handle_ingress_flow_ingress__tbl_act_1(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__tbl_act_1");
#endif

    {
        struct pif_action_actiondata_ingress__act_1 actdata;
        __xwrite struct {
            union pif_action_opdata opdata;
            struct pif_action_actiondata_ingress__act_1 actdata;
            } wr_buf;

        wr_buf.opdata.val32 = (PIF_ACTION_ID_ingress__act_1 << PIF_ACTION_OPDATA_ACTION_ID_off) | ((sizeof(actdata) / 4) << PIF_ACTION_OPDATA_ACTDATA_CNT_off);
        actdata.__pif_table_no = 0xffffffff;
        actdata.__pif_rule_no = 0x0;
        wr_buf.actdata = actdata;

        mem_write32(&wr_buf,
                    actbuf + actbuf_off,
                    sizeof(wr_buf));
        *actlen = sizeof(wr_buf)/4;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow_exit_control_flow; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

static int handle_ingress_flow__condition_0(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_0_register_0;
    __lmem struct pif_parrep_ctldata *prdata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow__condition_0");
#endif

    //expression _condition_0: (valid(arp))
    {
    //subexpression 0: valid(arp)
    pif_expression__condition_0_register_0 = PIF_PARREP_arp_VALID(prdata);
    }

    if (pif_expression__condition_0_register_0)
        return PIF_CTLFLOW_STATE_ingress_flow_ingress__arp_lpm;
    else
        return PIF_CTLFLOW_STATE_ingress_flow__condition_1;
}

static int handle_ingress_flow__condition_1(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_1_register_0;
    __lmem struct pif_parrep_ctldata *prdata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow__condition_1");
#endif

    //expression _condition_1: (valid(ipv4))
    {
    //subexpression 0: valid(ipv4)
    pif_expression__condition_1_register_0 = PIF_PARREP_ipv4_VALID(prdata);
    }

    if (pif_expression__condition_1_register_0)
        return PIF_CTLFLOW_STATE_ingress_flow_ingress__ipv4_lpm;
    else
        return PIF_CTLFLOW_STATE_ingress_flow__condition_3;
}

static int handle_ingress_flow_ingress__tbl_act(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_ingress_flow_ingress__tbl_act");
#endif

    {
        struct pif_action_actiondata_ingress__act actdata;
        __xwrite struct {
            union pif_action_opdata opdata;
            struct pif_action_actiondata_ingress__act actdata;
            } wr_buf;

        wr_buf.opdata.val32 = (PIF_ACTION_ID_ingress__act << PIF_ACTION_OPDATA_ACTION_ID_off) | ((sizeof(actdata) / 4) << PIF_ACTION_OPDATA_ACTDATA_CNT_off);
        actdata.__pif_table_no = 0xffffffff;
        actdata.__pif_rule_no = 0x0;
        wr_buf.actdata = actdata;

        mem_write32(&wr_buf,
                    actbuf + actbuf_off,
                    sizeof(wr_buf));
        *actlen = sizeof(wr_buf)/4;
    }

    next_state = PIF_CTLFLOW_STATE_ingress_flow__condition_0; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_ingress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

/* Control flow entry point */

int pif_ctlflow_ingress_flow(int *start_state, __lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off)
{
    __gpr int actlen, totlen = 0;
    __gpr int ret;
    int pif_ctlflow_state_ingress_flow = PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act;

    while (pif_ctlflow_state_ingress_flow != PIF_CTLFLOW_STATE_ingress_flow_DONE) {
        PIF_DEBUG_SET_STATE(PIF_DEBUG_STATE_CONTROL, ((0 << 16) + pif_ctlflow_state_ingress_flow));
#ifdef PIF_DEBUG
        __debug_label("pif_ctlflow_state_ingress_flow");
#endif
        switch (pif_ctlflow_state_ingress_flow) {
        case PIF_CTLFLOW_STATE_ingress_flow__condition_4:
            pif_ctlflow_state_ingress_flow = handle_ingress_flow__condition_4(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__arp_lpm:
            ret = handle_ingress_flow_ingress__arp_lpm(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        case PIF_CTLFLOW_STATE_ingress_flow__condition_3:
            pif_ctlflow_state_ingress_flow = handle_ingress_flow__condition_3(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act_0:
            ret = handle_ingress_flow_ingress__tbl_act_0(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        case PIF_CTLFLOW_STATE_ingress_flow__condition_2:
            pif_ctlflow_state_ingress_flow = handle_ingress_flow__condition_2(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__process_int_report:
            ret = handle_ingress_flow_ingress__process_int_report(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__ipv4_lpm:
            ret = handle_ingress_flow_ingress__ipv4_lpm(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act_1:
            ret = handle_ingress_flow_ingress__tbl_act_1(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        case PIF_CTLFLOW_STATE_ingress_flow__condition_0:
            pif_ctlflow_state_ingress_flow = handle_ingress_flow__condition_0(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_ingress_flow__condition_1:
            pif_ctlflow_state_ingress_flow = handle_ingress_flow__condition_1(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_ingress_flow_ingress__tbl_act:
            ret = handle_ingress_flow_ingress__tbl_act(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_ingress_flow);
            break;
        }
        if (actlen < 0) /* error! */
            return actlen & ((~(1 << PIF_LOOKUP_ERROR_BIT)));
        __critical_path();
        totlen += actlen;
        if (ret < 0)
            return -totlen;
    }

    return totlen;
}

/****************************************
 * egress_flow                          *
 ****************************************/

/* State transition functions */

static int handle_egress_flow__condition_5(__lmem uint32_t *_pif_parrep)
{
    unsigned int pif_expression__condition_5_register_0;
    __lmem struct pif_header_report_ipv4 *report_ipv4;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_egress_flow__condition_5");
#endif

    report_ipv4 = (__lmem struct pif_header_report_ipv4 *) (_pif_parrep + PIF_PARREP_report_ipv4_OFF_LW);

    //expression _condition_5: ((report_ipv4.typeServiceDiffServ) == (23))
    {
    unsigned int pif_expression__condition_5_register_1;
    unsigned int pif_expression__condition_5_register_2;
    unsigned int pif_expression__condition_5_register_3;
    //subexpression 2: 23
    // constant : 0x17

    //subexpression 0: (report_ipv4.typeServiceDiffServ)==(23)
    pif_expression__condition_5_register_1 = report_ipv4->typeServiceDiffServ;
    pif_expression__condition_5_register_2 = 0x17;
    /* implicit cast 5 -> 8 */
    pif_expression__condition_5_register_3 = pif_expression__condition_5_register_2 & 0x1f;
    pif_expression__condition_5_register_0 = (pif_expression__condition_5_register_1 == pif_expression__condition_5_register_3);
    }

    if (pif_expression__condition_5_register_0)
        return PIF_CTLFLOW_STATE_egress_flow_egress__add_metadata;
    else
        return PIF_CTLFLOW_STATE_egress_flow_exit_control_flow;
}

static int handle_egress_flow_egress__add_metadata(__lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off, int *actlen, int *state)
{
    __gpr int action_id, ret;
    int next_state = PIF_CTLFLOW_STATE_egress_flow_DONE;

#ifdef PIF_DEBUG
    __debug_label("pif_ctlflow_state_egress_flow_egress__add_metadata");
#endif

    {
        struct pif_lookup_result result;
        result = pif_lookup(PIF_TABLE_ID_egress__add_metadata, _pif_parrep, actbuf, actbuf_off);
        action_id = result.action_id;
        *actlen = result.action_len;
    }

    next_state = PIF_CTLFLOW_STATE_egress_flow_exit_control_flow; /* always */

    if (*actlen > 0) {
        __critical_path();
        ret = pif_action_execute(_pif_parrep, actbuf, actbuf_off, *actlen);
        if (ret < 0)
            return ret;
        __critical_path();
        if (ret > 0)
            next_state = PIF_CTLFLOW_STATE_egress_flow_DONE;
        __critical_path();
    }

    *state = next_state;
    return 0;
}

/* Control flow entry point */

int pif_ctlflow_egress_flow(int *start_state, __lmem uint32_t *_pif_parrep, __mem __addr40 uint32_t *actbuf, unsigned int actbuf_off)
{
    __gpr int actlen, totlen = 0;
    __gpr int ret;
    int pif_ctlflow_state_egress_flow = PIF_CTLFLOW_STATE_egress_flow__condition_5;

    while (pif_ctlflow_state_egress_flow != PIF_CTLFLOW_STATE_egress_flow_DONE) {
        PIF_DEBUG_SET_STATE(PIF_DEBUG_STATE_CONTROL, ((1 << 16) + pif_ctlflow_state_egress_flow));
#ifdef PIF_DEBUG
        __debug_label("pif_ctlflow_state_egress_flow");
#endif
        switch (pif_ctlflow_state_egress_flow) {
        case PIF_CTLFLOW_STATE_egress_flow__condition_5:
            pif_ctlflow_state_egress_flow = handle_egress_flow__condition_5(_pif_parrep);
            continue;
        case PIF_CTLFLOW_STATE_egress_flow_egress__add_metadata:
            ret = handle_egress_flow_egress__add_metadata(_pif_parrep, actbuf, actbuf_off + totlen, (int *)&actlen, (int *)&pif_ctlflow_state_egress_flow);
            break;
        }
        if (actlen < 0) /* error! */
            return actlen & ((~(1 << PIF_LOOKUP_ERROR_BIT)));
        __critical_path();
        totlen += actlen;
        if (ret < 0)
            return -totlen;
    }

    return totlen;
}
