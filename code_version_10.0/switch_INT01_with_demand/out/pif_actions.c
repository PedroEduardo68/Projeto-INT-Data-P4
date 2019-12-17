/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#include <nfp/mem_atomic.h>
#include <nfp/mem_ring.h>
#include <nfp/me.h>
#include <nfp/cls.h>
#include "mac_time.h"
#include "pif_common.h"
#include "pkt_clone.h"

#ifdef PIF_DEBUG
    __export __emem_n(0) uint64_t pif_act_stats[PIF_ACTION_ID_MAX + 1];
#endif

extern __nnr uint32_t calc_fld_bmsk;

#define BITRANGE(var, width, offset) \
    (((var) >> (offset)) & ((1 << (width)) - 1))

extern __lmem __shared struct mac_time_state mac_time_state;

static int pif_action_exec_ingress__act(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__act *_pif_act_data = (__xread struct pif_action_actiondata_ingress__act *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_standard_metadata *standard_metadata;
    __lmem struct pif_header_ingress__scalars *ingress__scalars;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__act");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__act");
#endif

    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    standard_metadata = (__lmem struct pif_header_standard_metadata *) (_pif_parrep + PIF_PARREP_standard_metadata_OFF_LW);
    ingress__scalars = (__lmem struct pif_header_ingress__scalars *) (_pif_parrep + PIF_PARREP_ingress__scalars_OFF_LW);

    {
        /* modify_field(ingress::scalars.tmp,_expression_act_0) */
        unsigned int pif_expression__expression_act_0_register_0;

        /* primitive body */
        //expression _expression_act_0: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_0_register_1;
        unsigned int pif_expression__expression_act_0_register_2;
        unsigned int pif_expression__expression_act_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_0_register_1 = switch_local->port_in;
        pif_expression__expression_act_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_0_register_3 = pif_expression__expression_act_0_register_1 & 0xffff;
        pif_expression__expression_act_0_register_0 = pif_expression__expression_act_0_register_3 & pif_expression__expression_act_0_register_2;
        }

        ingress__scalars->tmp = pif_expression__expression_act_0_register_0;

    }
    {
        /* register_read(switch_local.ingresspackage,ingresscount.value,ingress::scalars.tmp) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp;

            if (_pif_index < 8) {
                __xread uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_ingresscount *_pif_hdrptr = (__mem __addr40 struct pif_header_ingresscount *) &pif_register_ingresscount[_pif_index];

                mem_read_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

                switch_local->ingresspackage = ((_pif_xreg[0] >> 8) & 0xffffff);
                switch_local->__ingresspackage_1 = _pif_xreg[0];

            }
        }
    }
    {
        /* modify_field(switch_local.ingresspackage,_expression_act_1) */
        unsigned int pif_expression__expression_act_1_register_2;

        /* primitive body */
        //expression _expression_act_1: ((((switch_local.ingresspackage) + (0x00000001))) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_1_register_0;
        unsigned int pif_expression__expression_act_1_register_1;
        //subexpression 4: 0x00000001
        // constant : 0x1

        //subexpression 1: (switch_local.ingresspackage)+(0x00000001)
        pif_expression__expression_act_1_register_1 = (switch_local->ingresspackage << 8) | switch_local->__ingresspackage_1;
        pif_expression__expression_act_1_register_2 = 0x1;
        pif_expression__expression_act_1_register_0 = pif_expression__expression_act_1_register_1 + pif_expression__expression_act_1_register_2;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (((switch_local.ingresspackage)+(0x00000001)))&(0xffffffff)
        pif_expression__expression_act_1_register_1 = 0xffffffff;
        pif_expression__expression_act_1_register_2 = pif_expression__expression_act_1_register_0 & pif_expression__expression_act_1_register_1;
        }

        switch_local->ingresspackage = ((pif_expression__expression_act_1_register_2 >> 8) & 0xffffff);
        switch_local->__ingresspackage_1 = pif_expression__expression_act_1_register_2;

    }
    {
        /* modify_field(ingress::scalars.tmp_0,_expression_act_2) */
        unsigned int pif_expression__expression_act_2_register_0;

        /* primitive body */
        //expression _expression_act_2: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_2_register_1;
        unsigned int pif_expression__expression_act_2_register_2;
        unsigned int pif_expression__expression_act_2_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_2_register_1 = switch_local->port_in;
        pif_expression__expression_act_2_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_2_register_3 = pif_expression__expression_act_2_register_1 & 0xffff;
        pif_expression__expression_act_2_register_0 = pif_expression__expression_act_2_register_3 & pif_expression__expression_act_2_register_2;
        }

        ingress__scalars->tmp_0 = pif_expression__expression_act_2_register_0;

    }
    {
        /* register_write(ingresscount.value,ingress::scalars.tmp_0,switch_local.ingresspackage) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp_0;

            if (_pif_index < 8) {
                __xwrite uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_ingresscount *_pif_hdrptr = (__mem __addr40 struct pif_header_ingresscount *) &pif_register_ingresscount[_pif_index];

                _pif_xreg[0] = (switch_local->ingresspackage << 8) | switch_local->__ingresspackage_1;

                mem_write_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);
            }
        }
    }
    {
        /* modify_field(ingress::scalars.tmp_1,_expression_act_3) */
        unsigned int pif_expression__expression_act_3_register_0;

        /* primitive body */
        //expression _expression_act_3: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_3_register_1;
        unsigned int pif_expression__expression_act_3_register_2;
        unsigned int pif_expression__expression_act_3_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_3_register_1 = switch_local->port_in;
        pif_expression__expression_act_3_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_3_register_3 = pif_expression__expression_act_3_register_1 & 0xffff;
        pif_expression__expression_act_3_register_0 = pif_expression__expression_act_3_register_3 & pif_expression__expression_act_3_register_2;
        }

        ingress__scalars->tmp_1 = pif_expression__expression_act_3_register_0;

    }
    {
        /* register_read(switch_local.ingressbyte,bytecountingress.value,ingress::scalars.tmp_1) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp_1;

            if (_pif_index < 8) {
                __xread uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_bytecountingress *_pif_hdrptr = (__mem __addr40 struct pif_header_bytecountingress *) &pif_register_bytecountingress[_pif_index];

                mem_read_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);

                switch_local->ingressbyte = ((_pif_xreg[0] >> 8) & 0xffffff);
                switch_local->__ingressbyte_1 = _pif_xreg[0];

            }
        }
    }
    {
        /* modify_field(switch_local.ingressbyte,_expression_act_4) */
        unsigned int pif_expression__expression_act_4_register_0;

        /* primitive body */
        //expression _expression_act_4: ((((switch_local.ingressbyte) + (((standard_metadata.packet_length) & (0xffffffff))))) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_4_register_1;
        unsigned int pif_expression__expression_act_4_register_2;
        unsigned int pif_expression__expression_act_4_register_3;
        //subexpression 6: 0xffffffff
        // constant : 0xffffffff

        //subexpression 4: (standard_metadata.packet_length)&(0xffffffff)
        pif_expression__expression_act_4_register_1 = standard_metadata->packet_length;
        pif_expression__expression_act_4_register_2 = 0xffffffff;
        /* implicit cast 14 -> 32 */
        pif_expression__expression_act_4_register_3 = pif_expression__expression_act_4_register_1 & 0x3fff;
        pif_expression__expression_act_4_register_0 = pif_expression__expression_act_4_register_3 & pif_expression__expression_act_4_register_2;
        //subexpression 1: (switch_local.ingressbyte)+(((standard_metadata.packet_length)&(0xffffffff)))
        pif_expression__expression_act_4_register_3 = (switch_local->ingressbyte << 8) | switch_local->__ingressbyte_1;
        pif_expression__expression_act_4_register_2 = pif_expression__expression_act_4_register_3 + pif_expression__expression_act_4_register_0;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (((switch_local.ingressbyte)+(((standard_metadata.packet_length)&(0xffffffff)))))&(0xffffffff)
        pif_expression__expression_act_4_register_3 = 0xffffffff;
        pif_expression__expression_act_4_register_0 = pif_expression__expression_act_4_register_2 & pif_expression__expression_act_4_register_3;
        }

        switch_local->ingressbyte = ((pif_expression__expression_act_4_register_0 >> 8) & 0xffffff);
        switch_local->__ingressbyte_1 = pif_expression__expression_act_4_register_0;

    }
    {
        /* modify_field(ingress::scalars.tmp_2,_expression_act_5) */
        unsigned int pif_expression__expression_act_5_register_0;

        /* primitive body */
        //expression _expression_act_5: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_5_register_1;
        unsigned int pif_expression__expression_act_5_register_2;
        unsigned int pif_expression__expression_act_5_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_5_register_1 = switch_local->port_in;
        pif_expression__expression_act_5_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_5_register_3 = pif_expression__expression_act_5_register_1 & 0xffff;
        pif_expression__expression_act_5_register_0 = pif_expression__expression_act_5_register_3 & pif_expression__expression_act_5_register_2;
        }

        ingress__scalars->tmp_2 = pif_expression__expression_act_5_register_0;

    }
    {
        /* register_write(bytecountingress.value,ingress::scalars.tmp_2,switch_local.ingressbyte) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp_2;

            if (_pif_index < 8) {
                __xwrite uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_bytecountingress *_pif_hdrptr = (__mem __addr40 struct pif_header_bytecountingress *) &pif_register_bytecountingress[_pif_index];

                _pif_xreg[0] = (switch_local->ingressbyte << 8) | switch_local->__ingressbyte_1;

                mem_write_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);
            }
        }
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq192(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq192 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq192 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq192");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq192");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq192_0) */
        unsigned int pif_expression__expression_action_eq192_0_register_0;

        /* primitive body */
        //expression _expression_action_eq192_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq192_0_register_1;
        unsigned int pif_expression__expression_action_eq192_0_register_2;
        unsigned int pif_expression__expression_action_eq192_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq192_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq192_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq192_0_register_3 = pif_expression__expression_action_eq192_0_register_1 & 0xffff;
        pif_expression__expression_action_eq192_0_register_0 = pif_expression__expression_action_eq192_0_register_3 & pif_expression__expression_action_eq192_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq192_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq192_1) */
        unsigned int pif_expression__expression_action_eq192_1_register_2;

        /* primitive body */
        //expression _expression_action_eq192_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq192_1_register_0;
        unsigned int pif_expression__expression_action_eq192_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq192_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq192_1_register_2 = 0x4;
        pif_expression__expression_action_eq192_1_register_0 = pif_expression__expression_action_eq192_1_register_1 + pif_expression__expression_action_eq192_1_register_2;
        pif_expression__expression_action_eq192_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq192_1_register_1 = 0xff;
        pif_expression__expression_action_eq192_1_register_2 = pif_expression__expression_action_eq192_1_register_0 & pif_expression__expression_action_eq192_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq192_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq192_2) */
        unsigned int pif_expression__expression_action_eq192_2_register_2;

        /* primitive body */
        //expression _expression_action_eq192_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq192_2_register_0;
        unsigned int pif_expression__expression_action_eq192_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq192_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq192_2_register_2 = 0x4;
        pif_expression__expression_action_eq192_2_register_0 = pif_expression__expression_action_eq192_2_register_1 + pif_expression__expression_action_eq192_2_register_2;
        pif_expression__expression_action_eq192_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq192_2_register_1 = 0xff;
        pif_expression__expression_action_eq192_2_register_2 = pif_expression__expression_action_eq192_2_register_0 & pif_expression__expression_action_eq192_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq192_2_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq192_3) */
        unsigned int pif_expression__expression_action_eq192_3_register_2;

        /* primitive body */
        //expression _expression_action_eq192_3: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq192_3_register_0;
        unsigned int pif_expression__expression_action_eq192_3_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq192_3_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq192_3_register_2 = 0x1;
        pif_expression__expression_action_eq192_3_register_0 = pif_expression__expression_action_eq192_3_register_1 + pif_expression__expression_action_eq192_3_register_2;
        pif_expression__expression_action_eq192_3_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq192_3_register_1 = 0xff;
        pif_expression__expression_action_eq192_3_register_2 = pif_expression__expression_action_eq192_3_register_0 & pif_expression__expression_action_eq192_3_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq192_3_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq192_4) */
        unsigned int pif_expression__expression_action_eq192_4_register_0;

        /* primitive body */
        //expression _expression_action_eq192_4: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq192_4_register_1;
        unsigned int pif_expression__expression_action_eq192_4_register_2;
        unsigned int pif_expression__expression_action_eq192_4_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq192_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq192_4_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq192_4_register_3 = pif_expression__expression_action_eq192_4_register_1 & 0xff;
        pif_expression__expression_action_eq192_4_register_0 = pif_expression__expression_action_eq192_4_register_3 & pif_expression__expression_action_eq192_4_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq192_4_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq192_4_register_2 = pif_expression__expression_action_eq192_4_register_3 + pif_expression__expression_action_eq192_4_register_0;
        pif_expression__expression_action_eq192_4_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq192_4_register_3 = 0xffff;
        pif_expression__expression_action_eq192_4_register_0 = pif_expression__expression_action_eq192_4_register_2 & pif_expression__expression_action_eq192_4_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq192_4_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_ingress__add_int_source(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__add_int_source *_pif_act_data = (__xread struct pif_action_actiondata_ingress__add_int_source *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_standard_metadata *standard_metadata;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_shimINT *shimINT;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__add_int_source");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__add_int_source");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    standard_metadata = (__lmem struct pif_header_standard_metadata *) (_pif_parrep + PIF_PARREP_standard_metadata_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_udp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* modify_field(switch_local.port_out,standard_metadata.egress_spec) */

        /* primitive body */
        switch_local->port_out = standard_metadata->egress_spec;

    }
    {
        /* modify_field(switch_local.port_in,standard_metadata.ingress_port) */

        /* primitive body */
        switch_local->port_in = standard_metadata->ingress_port;

    }
    {
        /* modify_field(switch_local.switch_id,0x0001) */

        /* primitive body */
        switch_local->switch_id = 0x1;

    }
    {
        /* add_header(shimINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_shimINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_shimINT_LEN_LW; i++)
                    ((__lmem uint32_t *)shimINT)[i] = 0;
            }
            PIF_PARREP_SET_shimINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(shimINT.shim_type,0x01) */

        /* primitive body */
        shimINT->shim_type = 0x1;

    }
    {
        /* modify_field(shimINT.shim_reserved1,0x00) */

        /* primitive body */
        shimINT->shim_reserved1 = 0x0;

    }
    {
        /* modify_field(shimINT.shim_length,0x00) */

        /* primitive body */
        shimINT->shim_length = 0x0;

    }
    {
        /* modify_field(shimINT.shim_rsvd2,0x00) */

        /* primitive body */
        shimINT->shim_rsvd2 = 0x0;

    }
    {
        /* add_header(hopINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hopINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hopINT_LEN_LW; i++)
                    ((__lmem uint32_t *)hopINT)[i] = 0;
            }
            PIF_PARREP_SET_hopINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hopINT.int_version,0x08) */

        /* primitive body */
        hopINT->int_version = 0x8;

    }
    {
        /* modify_field(hopINT.int_replication,0x01) */

        /* primitive body */
        hopINT->int_replication = 0x1;

    }
    {
        /* modify_field(hopINT.int_copy,0x00) */

        /* primitive body */
        hopINT->int_copy = 0x0;

    }
    {
        /* modify_field(hopINT.int_exceeded,0x00) */

        /* primitive body */
        hopINT->int_exceeded = 0x0;

    }
    {
        /* modify_field(hopINT.int_rsvd_1,0x00) */

        /* primitive body */
        hopINT->int_rsvd_1 = 0x0;

    }
    {
        /* modify_field(hopINT.int_ins_cnt,0x08) */

        /* primitive body */
        hopINT->int_ins_cnt = 0x2;
        hopINT->__int_ins_cnt_1 = 0x0;

    }
    {
        /* modify_field(hopINT.int_max_hops,0x02) */

        /* primitive body */
        hopINT->int_max_hops = 0x2;

    }
    {
        /* modify_field(hopINT.int_total_hops,0x00) */

        /* primitive body */
        hopINT->int_total_hops = 0x0;

    }
    {
        /* modify_field(hopINT.int_instruction_bit,instruction) */

        /* primitive body */
        hopINT->int_instruction_bit = _pif_act_data->instruction;

    }
    {
        /* modify_field(hopINT.int_rsvd_instructions,0x00) */

        /* primitive body */
        hopINT->int_rsvd_instructions = 0x0;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_add_int_source_0) */
        unsigned int pif_expression__expression_add_int_source_0_register_0;

        /* primitive body */
        //expression _expression_add_int_source_0: ((((((((ipv4.totalLength) + (0x0008))) & (0xffff))) + (0x0004))) & (0xffff))
        {
        unsigned int pif_expression__expression_add_int_source_0_register_1;
        unsigned int pif_expression__expression_add_int_source_0_register_2;
        //subexpression 8: 0x0008
        // constant : 0x8

        //subexpression 5: (ipv4.totalLength)+(0x0008)
        pif_expression__expression_add_int_source_0_register_1 = ipv4->totalLength;
        pif_expression__expression_add_int_source_0_register_2 = 0x8;
        pif_expression__expression_add_int_source_0_register_0 = pif_expression__expression_add_int_source_0_register_1 + pif_expression__expression_add_int_source_0_register_2;
        pif_expression__expression_add_int_source_0_register_0 &= 0xffff;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 3: (((ipv4.totalLength)+(0x0008)))&(0xffff)
        pif_expression__expression_add_int_source_0_register_1 = 0xffff;
        pif_expression__expression_add_int_source_0_register_2 = pif_expression__expression_add_int_source_0_register_0 & pif_expression__expression_add_int_source_0_register_1;
        //subexpression 4: 0x0004
        // constant : 0x4

        //subexpression 1: (((((ipv4.totalLength)+(0x0008)))&(0xffff)))+(0x0004)
        pif_expression__expression_add_int_source_0_register_0 = 0x4;
        pif_expression__expression_add_int_source_0_register_1 = pif_expression__expression_add_int_source_0_register_2 + pif_expression__expression_add_int_source_0_register_0;
        pif_expression__expression_add_int_source_0_register_1 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((((((ipv4.totalLength)+(0x0008)))&(0xffff)))+(0x0004)))&(0xffff)
        pif_expression__expression_add_int_source_0_register_2 = 0xffff;
        pif_expression__expression_add_int_source_0_register_0 = pif_expression__expression_add_int_source_0_register_1 & pif_expression__expression_add_int_source_0_register_2;
        }

        ipv4->totalLength = pif_expression__expression_add_int_source_0_register_0;

    }
    {
        /* modify_field(udp.lengthUDP,_expression_add_int_source_1) */
        unsigned int pif_expression__expression_add_int_source_1_register_0;

        /* primitive body */
        //expression _expression_add_int_source_1: ((((((((udp.lengthUDP) + (0x0008))) & (0xffff))) + (0x0004))) & (0xffff))
        {
        unsigned int pif_expression__expression_add_int_source_1_register_1;
        unsigned int pif_expression__expression_add_int_source_1_register_2;
        //subexpression 8: 0x0008
        // constant : 0x8

        //subexpression 5: (udp.lengthUDP)+(0x0008)
        pif_expression__expression_add_int_source_1_register_1 = udp->lengthUDP;
        pif_expression__expression_add_int_source_1_register_2 = 0x8;
        pif_expression__expression_add_int_source_1_register_0 = pif_expression__expression_add_int_source_1_register_1 + pif_expression__expression_add_int_source_1_register_2;
        pif_expression__expression_add_int_source_1_register_0 &= 0xffff;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 3: (((udp.lengthUDP)+(0x0008)))&(0xffff)
        pif_expression__expression_add_int_source_1_register_1 = 0xffff;
        pif_expression__expression_add_int_source_1_register_2 = pif_expression__expression_add_int_source_1_register_0 & pif_expression__expression_add_int_source_1_register_1;
        //subexpression 4: 0x0004
        // constant : 0x4

        //subexpression 1: (((((udp.lengthUDP)+(0x0008)))&(0xffff)))+(0x0004)
        pif_expression__expression_add_int_source_1_register_0 = 0x4;
        pif_expression__expression_add_int_source_1_register_1 = pif_expression__expression_add_int_source_1_register_2 + pif_expression__expression_add_int_source_1_register_0;
        pif_expression__expression_add_int_source_1_register_1 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((((((udp.lengthUDP)+(0x0008)))&(0xffff)))+(0x0004)))&(0xffff)
        pif_expression__expression_add_int_source_1_register_2 = 0xffff;
        pif_expression__expression_add_int_source_1_register_0 = pif_expression__expression_add_int_source_1_register_1 & pif_expression__expression_add_int_source_1_register_2;
        }

        udp->lengthUDP = pif_expression__expression_add_int_source_1_register_0;

    }
    {
        /* modify_field(ipv4.typeServiceDiffServ,0x17) */

        /* primitive body */
        ipv4->typeServiceDiffServ = 0x17;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_ingress__act_0(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__act_0 *_pif_act_data = (__xread struct pif_action_actiondata_ingress__act_0 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__act_0");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__act_0");
#endif

    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);

    {
        /* modify_field(switch_local.ingresststamp,intrinsic_metadata.ingress_global_tstamp) */

        /* primitive body */
        switch_local->ingresststamp = ((intrinsic_metadata->ingress_global_tstamp >> 8) & 0xffffff);
        switch_local->__ingresststamp_1 = ((intrinsic_metadata->ingress_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__ingress_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__ingresststamp_2 = intrinsic_metadata->__ingress_global_tstamp_1;

    }
    return _pif_return;
}

static int pif_action_exec_ingress__act_1(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__act_1 *_pif_act_data = (__xread struct pif_action_actiondata_ingress__act_1 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_ingress__scalars *ingress__scalars;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__act_1");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__act_1");
#endif

    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    ingress__scalars = (__lmem struct pif_header_ingress__scalars *) (_pif_parrep + PIF_PARREP_ingress__scalars_OFF_LW);

    {
        /* modify_field(ingress::scalars.tmp_3,_expression_act_1_0) */
        unsigned int pif_expression__expression_act_1_0_register_0;

        /* primitive body */
        //expression _expression_act_1_0: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_1_0_register_1;
        unsigned int pif_expression__expression_act_1_0_register_2;
        unsigned int pif_expression__expression_act_1_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_1_0_register_1 = switch_local->port_in;
        pif_expression__expression_act_1_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_1_0_register_3 = pif_expression__expression_act_1_0_register_1 & 0xffff;
        pif_expression__expression_act_1_0_register_0 = pif_expression__expression_act_1_0_register_3 & pif_expression__expression_act_1_0_register_2;
        }

        ingress__scalars->tmp_3 = pif_expression__expression_act_1_0_register_0;

    }
    {
        /* register_write(ingresscount.value,ingress::scalars.tmp_3,0x00000000) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp_3;

            if (_pif_index < 8) {
                __xwrite uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_ingresscount *_pif_hdrptr = (__mem __addr40 struct pif_header_ingresscount *) &pif_register_ingresscount[_pif_index];

                _pif_xreg[0] = 0x0;

                mem_write_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);
            }
        }
    }
    {
        /* modify_field(ingress::scalars.tmp_4,_expression_act_1_1) */
        unsigned int pif_expression__expression_act_1_1_register_0;

        /* primitive body */
        //expression _expression_act_1_1: ((switch_local.port_in) & (0xffffffff))
        {
        unsigned int pif_expression__expression_act_1_1_register_1;
        unsigned int pif_expression__expression_act_1_1_register_2;
        unsigned int pif_expression__expression_act_1_1_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.port_in)&(0xffffffff)
        pif_expression__expression_act_1_1_register_1 = switch_local->port_in;
        pif_expression__expression_act_1_1_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_act_1_1_register_3 = pif_expression__expression_act_1_1_register_1 & 0xffff;
        pif_expression__expression_act_1_1_register_0 = pif_expression__expression_act_1_1_register_3 & pif_expression__expression_act_1_1_register_2;
        }

        ingress__scalars->tmp_4 = pif_expression__expression_act_1_1_register_0;

    }
    {
        /* register_write(bytecountingress.value,ingress::scalars.tmp_4,0x00000000) */

        /* primitive body */
        {
            unsigned int _pif_index;
            _pif_index = ingress__scalars->tmp_4;

            if (_pif_index < 8) {
                __xwrite uint32_t _pif_xreg[1];
                __mem __addr40 struct pif_header_bytecountingress *_pif_hdrptr = (__mem __addr40 struct pif_header_bytecountingress *) &pif_register_bytecountingress[_pif_index];

                _pif_xreg[0] = 0x0;

                mem_write_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)_pif_hdrptr) + 0, 4);
            }
        }
    }
    return _pif_return;
}

static int pif_action_exec_ingress__arp_forward(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__arp_forward *_pif_act_data = (__xread struct pif_action_actiondata_ingress__arp_forward *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_standard_metadata *standard_metadata;
    __lmem struct pif_header_ethernet *ethernet;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__arp_forward");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__arp_forward");
#endif

    standard_metadata = (__lmem struct pif_header_standard_metadata *) (_pif_parrep + PIF_PARREP_standard_metadata_OFF_LW);
    ethernet = (__lmem struct pif_header_ethernet *) (_pif_parrep + PIF_PARREP_ethernet_OFF_LW);
    PIF_PARREP_SET_ethernet_DIRTY(_pif_ctldata);

    {
        /* modify_field(standard_metadata.egress_spec,espec) */

        /* primitive body */
        standard_metadata->egress_spec = _pif_act_data->espec;

    }
    {
        /* modify_field(ethernet.sourceAddress,srcmac) */

        /* primitive body */
        ethernet->sourceAddress = ((_pif_act_data->srcmac_1 >> 16) & 0xffff);
        ethernet->__sourceAddress_1 = ((_pif_act_data->srcmac_1 & 0xffff) << 16) | _pif_act_data->srcmac_0;

    }
    {
        /* modify_field(ethernet.destinationAddress,dstmac) */

        /* primitive body */
        ethernet->destinationAddress = _pif_act_data->dstmac_1;
        ethernet->__destinationAddress_1 = _pif_act_data->dstmac_0;

    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq128(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq128 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq128 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq128");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq128");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq128_0) */
        unsigned int pif_expression__expression_action_eq128_0_register_0;

        /* primitive body */
        //expression _expression_action_eq128_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq128_0_register_1;
        unsigned int pif_expression__expression_action_eq128_0_register_2;
        unsigned int pif_expression__expression_action_eq128_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq128_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq128_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq128_0_register_3 = pif_expression__expression_action_eq128_0_register_1 & 0xffff;
        pif_expression__expression_action_eq128_0_register_0 = pif_expression__expression_action_eq128_0_register_3 & pif_expression__expression_action_eq128_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq128_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq128_1) */
        unsigned int pif_expression__expression_action_eq128_1_register_2;

        /* primitive body */
        //expression _expression_action_eq128_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq128_1_register_0;
        unsigned int pif_expression__expression_action_eq128_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq128_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq128_1_register_2 = 0x4;
        pif_expression__expression_action_eq128_1_register_0 = pif_expression__expression_action_eq128_1_register_1 + pif_expression__expression_action_eq128_1_register_2;
        pif_expression__expression_action_eq128_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq128_1_register_1 = 0xff;
        pif_expression__expression_action_eq128_1_register_2 = pif_expression__expression_action_eq128_1_register_0 & pif_expression__expression_action_eq128_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq128_1_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq128_2) */
        unsigned int pif_expression__expression_action_eq128_2_register_2;

        /* primitive body */
        //expression _expression_action_eq128_2: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq128_2_register_0;
        unsigned int pif_expression__expression_action_eq128_2_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq128_2_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq128_2_register_2 = 0x1;
        pif_expression__expression_action_eq128_2_register_0 = pif_expression__expression_action_eq128_2_register_1 + pif_expression__expression_action_eq128_2_register_2;
        pif_expression__expression_action_eq128_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq128_2_register_1 = 0xff;
        pif_expression__expression_action_eq128_2_register_2 = pif_expression__expression_action_eq128_2_register_0 & pif_expression__expression_action_eq128_2_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq128_2_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq128_3) */
        unsigned int pif_expression__expression_action_eq128_3_register_0;

        /* primitive body */
        //expression _expression_action_eq128_3: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq128_3_register_1;
        unsigned int pif_expression__expression_action_eq128_3_register_2;
        unsigned int pif_expression__expression_action_eq128_3_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq128_3_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq128_3_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq128_3_register_3 = pif_expression__expression_action_eq128_3_register_1 & 0xff;
        pif_expression__expression_action_eq128_3_register_0 = pif_expression__expression_action_eq128_3_register_3 & pif_expression__expression_action_eq128_3_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq128_3_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq128_3_register_2 = pif_expression__expression_action_eq128_3_register_3 + pif_expression__expression_action_eq128_3_register_0;
        pif_expression__expression_action_eq128_3_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq128_3_register_3 = 0xffff;
        pif_expression__expression_action_eq128_3_register_0 = pif_expression__expression_action_eq128_3_register_2 & pif_expression__expression_action_eq128_3_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq128_3_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_ingress__drop(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__drop *_pif_act_data = (__xread struct pif_action_actiondata_ingress__drop *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__drop");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__drop");
#endif


    {
        /* drop() */

        /* primitive body */
        _pif_return = PIF_RETURN_DROP;
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq184(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq184 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq184 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_egressTimestamp *egressTimestamp;
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq184");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq184");
#endif

    egressTimestamp = (__lmem struct pif_header_egressTimestamp *) (_pif_parrep + PIF_PARREP_egressTimestamp_OFF_LW);
    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_egressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq184_0) */
        unsigned int pif_expression__expression_action_eq184_0_register_0;

        /* primitive body */
        //expression _expression_action_eq184_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq184_0_register_1;
        unsigned int pif_expression__expression_action_eq184_0_register_2;
        unsigned int pif_expression__expression_action_eq184_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq184_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq184_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq184_0_register_3 = pif_expression__expression_action_eq184_0_register_1 & 0xffff;
        pif_expression__expression_action_eq184_0_register_0 = pif_expression__expression_action_eq184_0_register_3 & pif_expression__expression_action_eq184_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq184_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq184_1) */
        unsigned int pif_expression__expression_action_eq184_1_register_2;

        /* primitive body */
        //expression _expression_action_eq184_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq184_1_register_0;
        unsigned int pif_expression__expression_action_eq184_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq184_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq184_1_register_2 = 0x4;
        pif_expression__expression_action_eq184_1_register_0 = pif_expression__expression_action_eq184_1_register_1 + pif_expression__expression_action_eq184_1_register_2;
        pif_expression__expression_action_eq184_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq184_1_register_1 = 0xff;
        pif_expression__expression_action_eq184_1_register_2 = pif_expression__expression_action_eq184_1_register_0 & pif_expression__expression_action_eq184_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq184_1_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq184_2) */
        unsigned int pif_expression__expression_action_eq184_2_register_4;
        unsigned int pif_expression__expression_action_eq184_2_register_5;

        /* primitive body */
        //expression _expression_action_eq184_2: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq184_2_register_0;
        unsigned int pif_expression__expression_action_eq184_2_register_1;
        unsigned int pif_expression__expression_action_eq184_2_register_2;
        unsigned int pif_expression__expression_action_eq184_2_register_3;
        unsigned int pif_expression__expression_action_eq184_2_register_6;
        unsigned int pif_expression__expression_action_eq184_2_register_7;
        unsigned int pif_expression__expression_action_eq184_2_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq184_2_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq184_2_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq184_2_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq184_2_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq184_2_register_6 = ~pif_expression__expression_action_eq184_2_register_4;
        pif_expression__expression_action_eq184_2_register_7 = ~pif_expression__expression_action_eq184_2_register_5;
        pif_expression__expression_action_eq184_2_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq184_2_register_5 = pif_expression__expression_action_eq184_2_register_6 + pif_expression__expression_action_eq184_2_register_8;
        if (pif_expression__expression_action_eq184_2_register_5 < pif_expression__expression_action_eq184_2_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq184_2_register_4 = pif_expression__expression_action_eq184_2_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq184_2_register_0 = pif_expression__expression_action_eq184_2_register_2 + pif_expression__expression_action_eq184_2_register_5;
        if (pif_expression__expression_action_eq184_2_register_0 < pif_expression__expression_action_eq184_2_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq184_2_register_1 = pif_expression__expression_action_eq184_2_register_3 + pif_expression__expression_action_eq184_2_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq184_2_register_3 = 0xffffffff;
        pif_expression__expression_action_eq184_2_register_2 = 0xffffffff;
        pif_expression__expression_action_eq184_2_register_4 = pif_expression__expression_action_eq184_2_register_0 & pif_expression__expression_action_eq184_2_register_3;
        pif_expression__expression_action_eq184_2_register_5 = pif_expression__expression_action_eq184_2_register_1 & pif_expression__expression_action_eq184_2_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq184_2_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq184_2_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq184_3) */
        unsigned int pif_expression__expression_action_eq184_3_register_2;

        /* primitive body */
        //expression _expression_action_eq184_3: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq184_3_register_0;
        unsigned int pif_expression__expression_action_eq184_3_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq184_3_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq184_3_register_2 = 0x8;
        pif_expression__expression_action_eq184_3_register_0 = pif_expression__expression_action_eq184_3_register_1 + pif_expression__expression_action_eq184_3_register_2;
        pif_expression__expression_action_eq184_3_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq184_3_register_1 = 0xff;
        pif_expression__expression_action_eq184_3_register_2 = pif_expression__expression_action_eq184_3_register_0 & pif_expression__expression_action_eq184_3_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq184_3_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq184_4) */
        unsigned int pif_expression__expression_action_eq184_4_register_2;

        /* primitive body */
        //expression _expression_action_eq184_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq184_4_register_0;
        unsigned int pif_expression__expression_action_eq184_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq184_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq184_4_register_2 = 0x8;
        pif_expression__expression_action_eq184_4_register_0 = pif_expression__expression_action_eq184_4_register_1 + pif_expression__expression_action_eq184_4_register_2;
        pif_expression__expression_action_eq184_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq184_4_register_1 = 0xff;
        pif_expression__expression_action_eq184_4_register_2 = pif_expression__expression_action_eq184_4_register_0 & pif_expression__expression_action_eq184_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq184_4_register_2;

    }
    {
        /* add_header(egressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_egressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_egressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)egressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_egressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(egressTimestamp.int_egressTimestamp,switch_local.egresststamp) */

        /* primitive body */
        egressTimestamp->int_egressTimestamp = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        egressTimestamp->__int_egressTimestamp_1 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq184_5) */
        unsigned int pif_expression__expression_action_eq184_5_register_2;

        /* primitive body */
        //expression _expression_action_eq184_5: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq184_5_register_0;
        unsigned int pif_expression__expression_action_eq184_5_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq184_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq184_5_register_2 = 0x8;
        pif_expression__expression_action_eq184_5_register_0 = pif_expression__expression_action_eq184_5_register_1 + pif_expression__expression_action_eq184_5_register_2;
        pif_expression__expression_action_eq184_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq184_5_register_1 = 0xff;
        pif_expression__expression_action_eq184_5_register_2 = pif_expression__expression_action_eq184_5_register_0 & pif_expression__expression_action_eq184_5_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq184_5_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq184_6) */
        unsigned int pif_expression__expression_action_eq184_6_register_2;

        /* primitive body */
        //expression _expression_action_eq184_6: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq184_6_register_0;
        unsigned int pif_expression__expression_action_eq184_6_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq184_6_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq184_6_register_2 = 0x1;
        pif_expression__expression_action_eq184_6_register_0 = pif_expression__expression_action_eq184_6_register_1 + pif_expression__expression_action_eq184_6_register_2;
        pif_expression__expression_action_eq184_6_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq184_6_register_1 = 0xff;
        pif_expression__expression_action_eq184_6_register_2 = pif_expression__expression_action_eq184_6_register_0 & pif_expression__expression_action_eq184_6_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq184_6_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq184_7) */
        unsigned int pif_expression__expression_action_eq184_7_register_0;

        /* primitive body */
        //expression _expression_action_eq184_7: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq184_7_register_1;
        unsigned int pif_expression__expression_action_eq184_7_register_2;
        unsigned int pif_expression__expression_action_eq184_7_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq184_7_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq184_7_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq184_7_register_3 = pif_expression__expression_action_eq184_7_register_1 & 0xff;
        pif_expression__expression_action_eq184_7_register_0 = pif_expression__expression_action_eq184_7_register_3 & pif_expression__expression_action_eq184_7_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq184_7_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq184_7_register_2 = pif_expression__expression_action_eq184_7_register_3 + pif_expression__expression_action_eq184_7_register_0;
        pif_expression__expression_action_eq184_7_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq184_7_register_3 = 0xffff;
        pif_expression__expression_action_eq184_7_register_0 = pif_expression__expression_action_eq184_7_register_2 & pif_expression__expression_action_eq184_7_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq184_7_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq240(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq240 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq240 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq240");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq240");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq240_0) */
        unsigned int pif_expression__expression_action_eq240_0_register_0;

        /* primitive body */
        //expression _expression_action_eq240_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq240_0_register_1;
        unsigned int pif_expression__expression_action_eq240_0_register_2;
        unsigned int pif_expression__expression_action_eq240_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq240_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq240_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq240_0_register_3 = pif_expression__expression_action_eq240_0_register_1 & 0xffff;
        pif_expression__expression_action_eq240_0_register_0 = pif_expression__expression_action_eq240_0_register_3 & pif_expression__expression_action_eq240_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq240_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq240_1) */
        unsigned int pif_expression__expression_action_eq240_1_register_2;

        /* primitive body */
        //expression _expression_action_eq240_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq240_1_register_0;
        unsigned int pif_expression__expression_action_eq240_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq240_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq240_1_register_2 = 0x4;
        pif_expression__expression_action_eq240_1_register_0 = pif_expression__expression_action_eq240_1_register_1 + pif_expression__expression_action_eq240_1_register_2;
        pif_expression__expression_action_eq240_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq240_1_register_1 = 0xff;
        pif_expression__expression_action_eq240_1_register_2 = pif_expression__expression_action_eq240_1_register_0 & pif_expression__expression_action_eq240_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq240_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq240_2) */
        unsigned int pif_expression__expression_action_eq240_2_register_2;

        /* primitive body */
        //expression _expression_action_eq240_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq240_2_register_0;
        unsigned int pif_expression__expression_action_eq240_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq240_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq240_2_register_2 = 0x4;
        pif_expression__expression_action_eq240_2_register_0 = pif_expression__expression_action_eq240_2_register_1 + pif_expression__expression_action_eq240_2_register_2;
        pif_expression__expression_action_eq240_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq240_2_register_1 = 0xff;
        pif_expression__expression_action_eq240_2_register_2 = pif_expression__expression_action_eq240_2_register_0 & pif_expression__expression_action_eq240_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq240_2_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq240_3) */
        unsigned int pif_expression__expression_action_eq240_3_register_4;
        unsigned int pif_expression__expression_action_eq240_3_register_5;

        /* primitive body */
        //expression _expression_action_eq240_3: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq240_3_register_0;
        unsigned int pif_expression__expression_action_eq240_3_register_1;
        unsigned int pif_expression__expression_action_eq240_3_register_2;
        unsigned int pif_expression__expression_action_eq240_3_register_3;
        unsigned int pif_expression__expression_action_eq240_3_register_6;
        unsigned int pif_expression__expression_action_eq240_3_register_7;
        unsigned int pif_expression__expression_action_eq240_3_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq240_3_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq240_3_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq240_3_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq240_3_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq240_3_register_6 = ~pif_expression__expression_action_eq240_3_register_4;
        pif_expression__expression_action_eq240_3_register_7 = ~pif_expression__expression_action_eq240_3_register_5;
        pif_expression__expression_action_eq240_3_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq240_3_register_5 = pif_expression__expression_action_eq240_3_register_6 + pif_expression__expression_action_eq240_3_register_8;
        if (pif_expression__expression_action_eq240_3_register_5 < pif_expression__expression_action_eq240_3_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq240_3_register_4 = pif_expression__expression_action_eq240_3_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq240_3_register_0 = pif_expression__expression_action_eq240_3_register_2 + pif_expression__expression_action_eq240_3_register_5;
        if (pif_expression__expression_action_eq240_3_register_0 < pif_expression__expression_action_eq240_3_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq240_3_register_1 = pif_expression__expression_action_eq240_3_register_3 + pif_expression__expression_action_eq240_3_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq240_3_register_3 = 0xffffffff;
        pif_expression__expression_action_eq240_3_register_2 = 0xffffffff;
        pif_expression__expression_action_eq240_3_register_4 = pif_expression__expression_action_eq240_3_register_0 & pif_expression__expression_action_eq240_3_register_3;
        pif_expression__expression_action_eq240_3_register_5 = pif_expression__expression_action_eq240_3_register_1 & pif_expression__expression_action_eq240_3_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq240_3_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq240_3_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq240_4) */
        unsigned int pif_expression__expression_action_eq240_4_register_2;

        /* primitive body */
        //expression _expression_action_eq240_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq240_4_register_0;
        unsigned int pif_expression__expression_action_eq240_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq240_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq240_4_register_2 = 0x8;
        pif_expression__expression_action_eq240_4_register_0 = pif_expression__expression_action_eq240_4_register_1 + pif_expression__expression_action_eq240_4_register_2;
        pif_expression__expression_action_eq240_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq240_4_register_1 = 0xff;
        pif_expression__expression_action_eq240_4_register_2 = pif_expression__expression_action_eq240_4_register_0 & pif_expression__expression_action_eq240_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq240_4_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq240_5) */
        unsigned int pif_expression__expression_action_eq240_5_register_2;

        /* primitive body */
        //expression _expression_action_eq240_5: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq240_5_register_0;
        unsigned int pif_expression__expression_action_eq240_5_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq240_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq240_5_register_2 = 0x8;
        pif_expression__expression_action_eq240_5_register_0 = pif_expression__expression_action_eq240_5_register_1 + pif_expression__expression_action_eq240_5_register_2;
        pif_expression__expression_action_eq240_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq240_5_register_1 = 0xff;
        pif_expression__expression_action_eq240_5_register_2 = pif_expression__expression_action_eq240_5_register_0 & pif_expression__expression_action_eq240_5_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq240_5_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq240_6) */
        unsigned int pif_expression__expression_action_eq240_6_register_2;

        /* primitive body */
        //expression _expression_action_eq240_6: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq240_6_register_0;
        unsigned int pif_expression__expression_action_eq240_6_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq240_6_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq240_6_register_2 = 0x1;
        pif_expression__expression_action_eq240_6_register_0 = pif_expression__expression_action_eq240_6_register_1 + pif_expression__expression_action_eq240_6_register_2;
        pif_expression__expression_action_eq240_6_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq240_6_register_1 = 0xff;
        pif_expression__expression_action_eq240_6_register_2 = pif_expression__expression_action_eq240_6_register_0 & pif_expression__expression_action_eq240_6_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq240_6_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq240_7) */
        unsigned int pif_expression__expression_action_eq240_7_register_0;

        /* primitive body */
        //expression _expression_action_eq240_7: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq240_7_register_1;
        unsigned int pif_expression__expression_action_eq240_7_register_2;
        unsigned int pif_expression__expression_action_eq240_7_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq240_7_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq240_7_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq240_7_register_3 = pif_expression__expression_action_eq240_7_register_1 & 0xff;
        pif_expression__expression_action_eq240_7_register_0 = pif_expression__expression_action_eq240_7_register_3 & pif_expression__expression_action_eq240_7_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq240_7_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq240_7_register_2 = pif_expression__expression_action_eq240_7_register_3 + pif_expression__expression_action_eq240_7_register_0;
        pif_expression__expression_action_eq240_7_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq240_7_register_3 = 0xffff;
        pif_expression__expression_action_eq240_7_register_0 = pif_expression__expression_action_eq240_7_register_2 & pif_expression__expression_action_eq240_7_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq240_7_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq88(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq88 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq88 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_egressTimestamp *egressTimestamp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_shimINT *shimINT;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq88");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq88");
#endif

    egressTimestamp = (__lmem struct pif_header_egressTimestamp *) (_pif_parrep + PIF_PARREP_egressTimestamp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    PIF_PARREP_SET_egressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq88_0) */
        unsigned int pif_expression__expression_action_eq88_0_register_2;

        /* primitive body */
        //expression _expression_action_eq88_0: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq88_0_register_0;
        unsigned int pif_expression__expression_action_eq88_0_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq88_0_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq88_0_register_2 = 0x4;
        pif_expression__expression_action_eq88_0_register_0 = pif_expression__expression_action_eq88_0_register_1 + pif_expression__expression_action_eq88_0_register_2;
        pif_expression__expression_action_eq88_0_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq88_0_register_1 = 0xff;
        pif_expression__expression_action_eq88_0_register_2 = pif_expression__expression_action_eq88_0_register_0 & pif_expression__expression_action_eq88_0_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq88_0_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq88_1) */
        unsigned int pif_expression__expression_action_eq88_1_register_2;

        /* primitive body */
        //expression _expression_action_eq88_1: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq88_1_register_0;
        unsigned int pif_expression__expression_action_eq88_1_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq88_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq88_1_register_2 = 0x8;
        pif_expression__expression_action_eq88_1_register_0 = pif_expression__expression_action_eq88_1_register_1 + pif_expression__expression_action_eq88_1_register_2;
        pif_expression__expression_action_eq88_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq88_1_register_1 = 0xff;
        pif_expression__expression_action_eq88_1_register_2 = pif_expression__expression_action_eq88_1_register_0 & pif_expression__expression_action_eq88_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq88_1_register_2;

    }
    {
        /* add_header(egressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_egressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_egressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)egressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_egressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(egressTimestamp.int_egressTimestamp,switch_local.egresststamp) */

        /* primitive body */
        egressTimestamp->int_egressTimestamp = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        egressTimestamp->__int_egressTimestamp_1 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq88_2) */
        unsigned int pif_expression__expression_action_eq88_2_register_2;

        /* primitive body */
        //expression _expression_action_eq88_2: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq88_2_register_0;
        unsigned int pif_expression__expression_action_eq88_2_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq88_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq88_2_register_2 = 0x8;
        pif_expression__expression_action_eq88_2_register_0 = pif_expression__expression_action_eq88_2_register_1 + pif_expression__expression_action_eq88_2_register_2;
        pif_expression__expression_action_eq88_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq88_2_register_1 = 0xff;
        pif_expression__expression_action_eq88_2_register_2 = pif_expression__expression_action_eq88_2_register_0 & pif_expression__expression_action_eq88_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq88_2_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq88_3) */
        unsigned int pif_expression__expression_action_eq88_3_register_2;

        /* primitive body */
        //expression _expression_action_eq88_3: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq88_3_register_0;
        unsigned int pif_expression__expression_action_eq88_3_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq88_3_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq88_3_register_2 = 0x1;
        pif_expression__expression_action_eq88_3_register_0 = pif_expression__expression_action_eq88_3_register_1 + pif_expression__expression_action_eq88_3_register_2;
        pif_expression__expression_action_eq88_3_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq88_3_register_1 = 0xff;
        pif_expression__expression_action_eq88_3_register_2 = pif_expression__expression_action_eq88_3_register_0 & pif_expression__expression_action_eq88_3_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq88_3_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq88_4) */
        unsigned int pif_expression__expression_action_eq88_4_register_0;

        /* primitive body */
        //expression _expression_action_eq88_4: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq88_4_register_1;
        unsigned int pif_expression__expression_action_eq88_4_register_2;
        unsigned int pif_expression__expression_action_eq88_4_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq88_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq88_4_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq88_4_register_3 = pif_expression__expression_action_eq88_4_register_1 & 0xff;
        pif_expression__expression_action_eq88_4_register_0 = pif_expression__expression_action_eq88_4_register_3 & pif_expression__expression_action_eq88_4_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq88_4_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq88_4_register_2 = pif_expression__expression_action_eq88_4_register_3 + pif_expression__expression_action_eq88_4_register_0;
        pif_expression__expression_action_eq88_4_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq88_4_register_3 = 0xffff;
        pif_expression__expression_action_eq88_4_register_0 = pif_expression__expression_action_eq88_4_register_2 & pif_expression__expression_action_eq88_4_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq88_4_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_ingress__ipv4_forward(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_ingress__ipv4_forward *_pif_act_data = (__xread struct pif_action_actiondata_ingress__ipv4_forward *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_standard_metadata *standard_metadata;
    __lmem struct pif_header_ethernet *ethernet;
    __lmem struct pif_header_ipv4 *ipv4;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_ingress__ipv4_forward");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_ingress__ipv4_forward");
#endif

    standard_metadata = (__lmem struct pif_header_standard_metadata *) (_pif_parrep + PIF_PARREP_standard_metadata_OFF_LW);
    ethernet = (__lmem struct pif_header_ethernet *) (_pif_parrep + PIF_PARREP_ethernet_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ethernet_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((ipv4->timeToLive) << 24);
        _pif_flc_update_val |= ((ipv4->protocol) << 16);
        _pif_flc_update_val |= ((ipv4->sourceAddress) >> 16);
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xff000000, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* modify_field(standard_metadata.egress_spec,espec) */

        /* primitive body */
        standard_metadata->egress_spec = _pif_act_data->espec;

    }
    {
        /* modify_field(ethernet.sourceAddress,srcmac) */

        /* primitive body */
        ethernet->sourceAddress = ((_pif_act_data->srcmac_1 >> 16) & 0xffff);
        ethernet->__sourceAddress_1 = ((_pif_act_data->srcmac_1 & 0xffff) << 16) | _pif_act_data->srcmac_0;

    }
    {
        /* modify_field(ethernet.destinationAddress,dstmac) */

        /* primitive body */
        ethernet->destinationAddress = _pif_act_data->dstmac_1;
        ethernet->__destinationAddress_1 = _pif_act_data->dstmac_0;

    }
    {
        /* modify_field(ipv4.timeToLive,_expression_ipv4_forward_0) */
        unsigned int pif_expression__expression_ipv4_forward_0_register_2;

        /* primitive body */
        //expression _expression_ipv4_forward_0: ((((ipv4.timeToLive) + (0xff))) & (0xff))
        {
        unsigned int pif_expression__expression_ipv4_forward_0_register_0;
        unsigned int pif_expression__expression_ipv4_forward_0_register_1;
        //subexpression 4: 0xff
        // constant : 0xff

        //subexpression 1: (ipv4.timeToLive)+(0xff)
        pif_expression__expression_ipv4_forward_0_register_1 = ipv4->timeToLive;
        pif_expression__expression_ipv4_forward_0_register_2 = 0xff;
        pif_expression__expression_ipv4_forward_0_register_0 = pif_expression__expression_ipv4_forward_0_register_1 + pif_expression__expression_ipv4_forward_0_register_2;
        pif_expression__expression_ipv4_forward_0_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((ipv4.timeToLive)+(0xff)))&(0xff)
        pif_expression__expression_ipv4_forward_0_register_1 = 0xff;
        pif_expression__expression_ipv4_forward_0_register_2 = pif_expression__expression_ipv4_forward_0_register_0 & pif_expression__expression_ipv4_forward_0_register_1;
        }

        ipv4->timeToLive = pif_expression__expression_ipv4_forward_0_register_2;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((ipv4->timeToLive) << 24);
        _pif_flc_update_val |= ((ipv4->protocol) << 16);
        _pif_flc_update_val |= ((ipv4->sourceAddress) >> 16);
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xff000000, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq254(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq254 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq254 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_egressTimestamp *egressTimestamp;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_countpackage *countpackage;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_bytepackage *bytepackage;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq254");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq254");
#endif

    egressTimestamp = (__lmem struct pif_header_egressTimestamp *) (_pif_parrep + PIF_PARREP_egressTimestamp_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    countpackage = (__lmem struct pif_header_countpackage *) (_pif_parrep + PIF_PARREP_countpackage_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    bytepackage = (__lmem struct pif_header_bytepackage *) (_pif_parrep + PIF_PARREP_bytepackage_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_egressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_bytepackage_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_countpackage_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq254_0) */
        unsigned int pif_expression__expression_action_eq254_0_register_0;

        /* primitive body */
        //expression _expression_action_eq254_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq254_0_register_1;
        unsigned int pif_expression__expression_action_eq254_0_register_2;
        unsigned int pif_expression__expression_action_eq254_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq254_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq254_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq254_0_register_3 = pif_expression__expression_action_eq254_0_register_1 & 0xffff;
        pif_expression__expression_action_eq254_0_register_0 = pif_expression__expression_action_eq254_0_register_3 & pif_expression__expression_action_eq254_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq254_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_1) */
        unsigned int pif_expression__expression_action_eq254_1_register_2;

        /* primitive body */
        //expression _expression_action_eq254_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_1_register_0;
        unsigned int pif_expression__expression_action_eq254_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq254_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_1_register_2 = 0x4;
        pif_expression__expression_action_eq254_1_register_0 = pif_expression__expression_action_eq254_1_register_1 + pif_expression__expression_action_eq254_1_register_2;
        pif_expression__expression_action_eq254_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq254_1_register_1 = 0xff;
        pif_expression__expression_action_eq254_1_register_2 = pif_expression__expression_action_eq254_1_register_0 & pif_expression__expression_action_eq254_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_2) */
        unsigned int pif_expression__expression_action_eq254_2_register_2;

        /* primitive body */
        //expression _expression_action_eq254_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_2_register_0;
        unsigned int pif_expression__expression_action_eq254_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq254_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_2_register_2 = 0x4;
        pif_expression__expression_action_eq254_2_register_0 = pif_expression__expression_action_eq254_2_register_1 + pif_expression__expression_action_eq254_2_register_2;
        pif_expression__expression_action_eq254_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq254_2_register_1 = 0xff;
        pif_expression__expression_action_eq254_2_register_2 = pif_expression__expression_action_eq254_2_register_0 & pif_expression__expression_action_eq254_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_2_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq254_3) */
        unsigned int pif_expression__expression_action_eq254_3_register_4;
        unsigned int pif_expression__expression_action_eq254_3_register_5;

        /* primitive body */
        //expression _expression_action_eq254_3: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq254_3_register_0;
        unsigned int pif_expression__expression_action_eq254_3_register_1;
        unsigned int pif_expression__expression_action_eq254_3_register_2;
        unsigned int pif_expression__expression_action_eq254_3_register_3;
        unsigned int pif_expression__expression_action_eq254_3_register_6;
        unsigned int pif_expression__expression_action_eq254_3_register_7;
        unsigned int pif_expression__expression_action_eq254_3_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq254_3_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq254_3_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq254_3_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq254_3_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq254_3_register_6 = ~pif_expression__expression_action_eq254_3_register_4;
        pif_expression__expression_action_eq254_3_register_7 = ~pif_expression__expression_action_eq254_3_register_5;
        pif_expression__expression_action_eq254_3_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq254_3_register_5 = pif_expression__expression_action_eq254_3_register_6 + pif_expression__expression_action_eq254_3_register_8;
        if (pif_expression__expression_action_eq254_3_register_5 < pif_expression__expression_action_eq254_3_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq254_3_register_4 = pif_expression__expression_action_eq254_3_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq254_3_register_0 = pif_expression__expression_action_eq254_3_register_2 + pif_expression__expression_action_eq254_3_register_5;
        if (pif_expression__expression_action_eq254_3_register_0 < pif_expression__expression_action_eq254_3_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq254_3_register_1 = pif_expression__expression_action_eq254_3_register_3 + pif_expression__expression_action_eq254_3_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq254_3_register_3 = 0xffffffff;
        pif_expression__expression_action_eq254_3_register_2 = 0xffffffff;
        pif_expression__expression_action_eq254_3_register_4 = pif_expression__expression_action_eq254_3_register_0 & pif_expression__expression_action_eq254_3_register_3;
        pif_expression__expression_action_eq254_3_register_5 = pif_expression__expression_action_eq254_3_register_1 & pif_expression__expression_action_eq254_3_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq254_3_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq254_3_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_4) */
        unsigned int pif_expression__expression_action_eq254_4_register_2;

        /* primitive body */
        //expression _expression_action_eq254_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_4_register_0;
        unsigned int pif_expression__expression_action_eq254_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq254_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_4_register_2 = 0x8;
        pif_expression__expression_action_eq254_4_register_0 = pif_expression__expression_action_eq254_4_register_1 + pif_expression__expression_action_eq254_4_register_2;
        pif_expression__expression_action_eq254_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq254_4_register_1 = 0xff;
        pif_expression__expression_action_eq254_4_register_2 = pif_expression__expression_action_eq254_4_register_0 & pif_expression__expression_action_eq254_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_4_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_5) */
        unsigned int pif_expression__expression_action_eq254_5_register_2;

        /* primitive body */
        //expression _expression_action_eq254_5: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_5_register_0;
        unsigned int pif_expression__expression_action_eq254_5_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq254_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_5_register_2 = 0x8;
        pif_expression__expression_action_eq254_5_register_0 = pif_expression__expression_action_eq254_5_register_1 + pif_expression__expression_action_eq254_5_register_2;
        pif_expression__expression_action_eq254_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq254_5_register_1 = 0xff;
        pif_expression__expression_action_eq254_5_register_2 = pif_expression__expression_action_eq254_5_register_0 & pif_expression__expression_action_eq254_5_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_5_register_2;

    }
    {
        /* add_header(egressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_egressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_egressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)egressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_egressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(egressTimestamp.int_egressTimestamp,switch_local.egresststamp) */

        /* primitive body */
        egressTimestamp->int_egressTimestamp = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        egressTimestamp->__int_egressTimestamp_1 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_6) */
        unsigned int pif_expression__expression_action_eq254_6_register_2;

        /* primitive body */
        //expression _expression_action_eq254_6: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_6_register_0;
        unsigned int pif_expression__expression_action_eq254_6_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq254_6_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_6_register_2 = 0x8;
        pif_expression__expression_action_eq254_6_register_0 = pif_expression__expression_action_eq254_6_register_1 + pif_expression__expression_action_eq254_6_register_2;
        pif_expression__expression_action_eq254_6_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq254_6_register_1 = 0xff;
        pif_expression__expression_action_eq254_6_register_2 = pif_expression__expression_action_eq254_6_register_0 & pif_expression__expression_action_eq254_6_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_6_register_2;

    }
    {
        /* add_header(countpackage) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_countpackage_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_countpackage_LEN_LW; i++)
                    ((__lmem uint32_t *)countpackage)[i] = 0;
            }
            PIF_PARREP_SET_countpackage_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(countpackage.int_ingresscountpackage,switch_local.ingresspackage) */

        /* primitive body */
        countpackage->int_ingresscountpackage = (switch_local->ingresspackage << 8) | switch_local->__ingresspackage_1;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_7) */
        unsigned int pif_expression__expression_action_eq254_7_register_2;

        /* primitive body */
        //expression _expression_action_eq254_7: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_7_register_0;
        unsigned int pif_expression__expression_action_eq254_7_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq254_7_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_7_register_2 = 0x4;
        pif_expression__expression_action_eq254_7_register_0 = pif_expression__expression_action_eq254_7_register_1 + pif_expression__expression_action_eq254_7_register_2;
        pif_expression__expression_action_eq254_7_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq254_7_register_1 = 0xff;
        pif_expression__expression_action_eq254_7_register_2 = pif_expression__expression_action_eq254_7_register_0 & pif_expression__expression_action_eq254_7_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_7_register_2;

    }
    {
        /* add_header(bytepackage) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_bytepackage_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_bytepackage_LEN_LW; i++)
                    ((__lmem uint32_t *)bytepackage)[i] = 0;
            }
            PIF_PARREP_SET_bytepackage_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(bytepackage.int_bytepackageingress,switch_local.ingressbyte) */

        /* primitive body */
        bytepackage->int_bytepackageingress = (switch_local->ingressbyte << 8) | switch_local->__ingressbyte_1;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq254_8) */
        unsigned int pif_expression__expression_action_eq254_8_register_2;

        /* primitive body */
        //expression _expression_action_eq254_8: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_8_register_0;
        unsigned int pif_expression__expression_action_eq254_8_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq254_8_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_8_register_2 = 0x4;
        pif_expression__expression_action_eq254_8_register_0 = pif_expression__expression_action_eq254_8_register_1 + pif_expression__expression_action_eq254_8_register_2;
        pif_expression__expression_action_eq254_8_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq254_8_register_1 = 0xff;
        pif_expression__expression_action_eq254_8_register_2 = pif_expression__expression_action_eq254_8_register_0 & pif_expression__expression_action_eq254_8_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq254_8_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq254_9) */
        unsigned int pif_expression__expression_action_eq254_9_register_2;

        /* primitive body */
        //expression _expression_action_eq254_9: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq254_9_register_0;
        unsigned int pif_expression__expression_action_eq254_9_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq254_9_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq254_9_register_2 = 0x1;
        pif_expression__expression_action_eq254_9_register_0 = pif_expression__expression_action_eq254_9_register_1 + pif_expression__expression_action_eq254_9_register_2;
        pif_expression__expression_action_eq254_9_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq254_9_register_1 = 0xff;
        pif_expression__expression_action_eq254_9_register_2 = pif_expression__expression_action_eq254_9_register_0 & pif_expression__expression_action_eq254_9_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq254_9_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq254_10) */
        unsigned int pif_expression__expression_action_eq254_10_register_0;

        /* primitive body */
        //expression _expression_action_eq254_10: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq254_10_register_1;
        unsigned int pif_expression__expression_action_eq254_10_register_2;
        unsigned int pif_expression__expression_action_eq254_10_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq254_10_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq254_10_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq254_10_register_3 = pif_expression__expression_action_eq254_10_register_1 & 0xff;
        pif_expression__expression_action_eq254_10_register_0 = pif_expression__expression_action_eq254_10_register_3 & pif_expression__expression_action_eq254_10_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq254_10_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq254_10_register_2 = pif_expression__expression_action_eq254_10_register_3 + pif_expression__expression_action_eq254_10_register_0;
        pif_expression__expression_action_eq254_10_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq254_10_register_3 = 0xffff;
        pif_expression__expression_action_eq254_10_register_0 = pif_expression__expression_action_eq254_10_register_2 & pif_expression__expression_action_eq254_10_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq254_10_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq248(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq248 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq248 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_egressTimestamp *egressTimestamp;
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq248");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq248");
#endif

    egressTimestamp = (__lmem struct pif_header_egressTimestamp *) (_pif_parrep + PIF_PARREP_egressTimestamp_OFF_LW);
    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_egressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq248_0) */
        unsigned int pif_expression__expression_action_eq248_0_register_0;

        /* primitive body */
        //expression _expression_action_eq248_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq248_0_register_1;
        unsigned int pif_expression__expression_action_eq248_0_register_2;
        unsigned int pif_expression__expression_action_eq248_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq248_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq248_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq248_0_register_3 = pif_expression__expression_action_eq248_0_register_1 & 0xffff;
        pif_expression__expression_action_eq248_0_register_0 = pif_expression__expression_action_eq248_0_register_3 & pif_expression__expression_action_eq248_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq248_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq248_1) */
        unsigned int pif_expression__expression_action_eq248_1_register_2;

        /* primitive body */
        //expression _expression_action_eq248_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_1_register_0;
        unsigned int pif_expression__expression_action_eq248_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq248_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_1_register_2 = 0x4;
        pif_expression__expression_action_eq248_1_register_0 = pif_expression__expression_action_eq248_1_register_1 + pif_expression__expression_action_eq248_1_register_2;
        pif_expression__expression_action_eq248_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq248_1_register_1 = 0xff;
        pif_expression__expression_action_eq248_1_register_2 = pif_expression__expression_action_eq248_1_register_0 & pif_expression__expression_action_eq248_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq248_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq248_2) */
        unsigned int pif_expression__expression_action_eq248_2_register_2;

        /* primitive body */
        //expression _expression_action_eq248_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_2_register_0;
        unsigned int pif_expression__expression_action_eq248_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq248_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_2_register_2 = 0x4;
        pif_expression__expression_action_eq248_2_register_0 = pif_expression__expression_action_eq248_2_register_1 + pif_expression__expression_action_eq248_2_register_2;
        pif_expression__expression_action_eq248_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq248_2_register_1 = 0xff;
        pif_expression__expression_action_eq248_2_register_2 = pif_expression__expression_action_eq248_2_register_0 & pif_expression__expression_action_eq248_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq248_2_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq248_3) */
        unsigned int pif_expression__expression_action_eq248_3_register_4;
        unsigned int pif_expression__expression_action_eq248_3_register_5;

        /* primitive body */
        //expression _expression_action_eq248_3: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq248_3_register_0;
        unsigned int pif_expression__expression_action_eq248_3_register_1;
        unsigned int pif_expression__expression_action_eq248_3_register_2;
        unsigned int pif_expression__expression_action_eq248_3_register_3;
        unsigned int pif_expression__expression_action_eq248_3_register_6;
        unsigned int pif_expression__expression_action_eq248_3_register_7;
        unsigned int pif_expression__expression_action_eq248_3_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq248_3_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq248_3_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq248_3_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq248_3_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq248_3_register_6 = ~pif_expression__expression_action_eq248_3_register_4;
        pif_expression__expression_action_eq248_3_register_7 = ~pif_expression__expression_action_eq248_3_register_5;
        pif_expression__expression_action_eq248_3_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq248_3_register_5 = pif_expression__expression_action_eq248_3_register_6 + pif_expression__expression_action_eq248_3_register_8;
        if (pif_expression__expression_action_eq248_3_register_5 < pif_expression__expression_action_eq248_3_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq248_3_register_4 = pif_expression__expression_action_eq248_3_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq248_3_register_0 = pif_expression__expression_action_eq248_3_register_2 + pif_expression__expression_action_eq248_3_register_5;
        if (pif_expression__expression_action_eq248_3_register_0 < pif_expression__expression_action_eq248_3_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq248_3_register_1 = pif_expression__expression_action_eq248_3_register_3 + pif_expression__expression_action_eq248_3_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq248_3_register_3 = 0xffffffff;
        pif_expression__expression_action_eq248_3_register_2 = 0xffffffff;
        pif_expression__expression_action_eq248_3_register_4 = pif_expression__expression_action_eq248_3_register_0 & pif_expression__expression_action_eq248_3_register_3;
        pif_expression__expression_action_eq248_3_register_5 = pif_expression__expression_action_eq248_3_register_1 & pif_expression__expression_action_eq248_3_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq248_3_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq248_3_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq248_4) */
        unsigned int pif_expression__expression_action_eq248_4_register_2;

        /* primitive body */
        //expression _expression_action_eq248_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_4_register_0;
        unsigned int pif_expression__expression_action_eq248_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq248_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_4_register_2 = 0x8;
        pif_expression__expression_action_eq248_4_register_0 = pif_expression__expression_action_eq248_4_register_1 + pif_expression__expression_action_eq248_4_register_2;
        pif_expression__expression_action_eq248_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq248_4_register_1 = 0xff;
        pif_expression__expression_action_eq248_4_register_2 = pif_expression__expression_action_eq248_4_register_0 & pif_expression__expression_action_eq248_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq248_4_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq248_5) */
        unsigned int pif_expression__expression_action_eq248_5_register_2;

        /* primitive body */
        //expression _expression_action_eq248_5: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_5_register_0;
        unsigned int pif_expression__expression_action_eq248_5_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq248_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_5_register_2 = 0x8;
        pif_expression__expression_action_eq248_5_register_0 = pif_expression__expression_action_eq248_5_register_1 + pif_expression__expression_action_eq248_5_register_2;
        pif_expression__expression_action_eq248_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq248_5_register_1 = 0xff;
        pif_expression__expression_action_eq248_5_register_2 = pif_expression__expression_action_eq248_5_register_0 & pif_expression__expression_action_eq248_5_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq248_5_register_2;

    }
    {
        /* add_header(egressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_egressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_egressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)egressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_egressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(egressTimestamp.int_egressTimestamp,switch_local.egresststamp) */

        /* primitive body */
        egressTimestamp->int_egressTimestamp = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        egressTimestamp->__int_egressTimestamp_1 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq248_6) */
        unsigned int pif_expression__expression_action_eq248_6_register_2;

        /* primitive body */
        //expression _expression_action_eq248_6: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_6_register_0;
        unsigned int pif_expression__expression_action_eq248_6_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq248_6_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_6_register_2 = 0x8;
        pif_expression__expression_action_eq248_6_register_0 = pif_expression__expression_action_eq248_6_register_1 + pif_expression__expression_action_eq248_6_register_2;
        pif_expression__expression_action_eq248_6_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq248_6_register_1 = 0xff;
        pif_expression__expression_action_eq248_6_register_2 = pif_expression__expression_action_eq248_6_register_0 & pif_expression__expression_action_eq248_6_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq248_6_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq248_7) */
        unsigned int pif_expression__expression_action_eq248_7_register_2;

        /* primitive body */
        //expression _expression_action_eq248_7: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq248_7_register_0;
        unsigned int pif_expression__expression_action_eq248_7_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq248_7_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq248_7_register_2 = 0x1;
        pif_expression__expression_action_eq248_7_register_0 = pif_expression__expression_action_eq248_7_register_1 + pif_expression__expression_action_eq248_7_register_2;
        pif_expression__expression_action_eq248_7_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq248_7_register_1 = 0xff;
        pif_expression__expression_action_eq248_7_register_2 = pif_expression__expression_action_eq248_7_register_0 & pif_expression__expression_action_eq248_7_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq248_7_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq248_8) */
        unsigned int pif_expression__expression_action_eq248_8_register_0;

        /* primitive body */
        //expression _expression_action_eq248_8: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq248_8_register_1;
        unsigned int pif_expression__expression_action_eq248_8_register_2;
        unsigned int pif_expression__expression_action_eq248_8_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq248_8_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq248_8_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq248_8_register_3 = pif_expression__expression_action_eq248_8_register_1 & 0xff;
        pif_expression__expression_action_eq248_8_register_0 = pif_expression__expression_action_eq248_8_register_3 & pif_expression__expression_action_eq248_8_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq248_8_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq248_8_register_2 = pif_expression__expression_action_eq248_8_register_3 + pif_expression__expression_action_eq248_8_register_0;
        pif_expression__expression_action_eq248_8_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq248_8_register_3 = 0xffff;
        pif_expression__expression_action_eq248_8_register_0 = pif_expression__expression_action_eq248_8_register_2 & pif_expression__expression_action_eq248_8_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq248_8_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq160(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq160 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq160 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq160");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq160");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq160_0) */
        unsigned int pif_expression__expression_action_eq160_0_register_0;

        /* primitive body */
        //expression _expression_action_eq160_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq160_0_register_1;
        unsigned int pif_expression__expression_action_eq160_0_register_2;
        unsigned int pif_expression__expression_action_eq160_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq160_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq160_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq160_0_register_3 = pif_expression__expression_action_eq160_0_register_1 & 0xffff;
        pif_expression__expression_action_eq160_0_register_0 = pif_expression__expression_action_eq160_0_register_3 & pif_expression__expression_action_eq160_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq160_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq160_1) */
        unsigned int pif_expression__expression_action_eq160_1_register_2;

        /* primitive body */
        //expression _expression_action_eq160_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq160_1_register_0;
        unsigned int pif_expression__expression_action_eq160_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq160_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq160_1_register_2 = 0x4;
        pif_expression__expression_action_eq160_1_register_0 = pif_expression__expression_action_eq160_1_register_1 + pif_expression__expression_action_eq160_1_register_2;
        pif_expression__expression_action_eq160_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq160_1_register_1 = 0xff;
        pif_expression__expression_action_eq160_1_register_2 = pif_expression__expression_action_eq160_1_register_0 & pif_expression__expression_action_eq160_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq160_1_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq160_2) */
        unsigned int pif_expression__expression_action_eq160_2_register_4;
        unsigned int pif_expression__expression_action_eq160_2_register_5;

        /* primitive body */
        //expression _expression_action_eq160_2: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq160_2_register_0;
        unsigned int pif_expression__expression_action_eq160_2_register_1;
        unsigned int pif_expression__expression_action_eq160_2_register_2;
        unsigned int pif_expression__expression_action_eq160_2_register_3;
        unsigned int pif_expression__expression_action_eq160_2_register_6;
        unsigned int pif_expression__expression_action_eq160_2_register_7;
        unsigned int pif_expression__expression_action_eq160_2_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq160_2_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq160_2_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq160_2_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq160_2_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq160_2_register_6 = ~pif_expression__expression_action_eq160_2_register_4;
        pif_expression__expression_action_eq160_2_register_7 = ~pif_expression__expression_action_eq160_2_register_5;
        pif_expression__expression_action_eq160_2_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq160_2_register_5 = pif_expression__expression_action_eq160_2_register_6 + pif_expression__expression_action_eq160_2_register_8;
        if (pif_expression__expression_action_eq160_2_register_5 < pif_expression__expression_action_eq160_2_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq160_2_register_4 = pif_expression__expression_action_eq160_2_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq160_2_register_0 = pif_expression__expression_action_eq160_2_register_2 + pif_expression__expression_action_eq160_2_register_5;
        if (pif_expression__expression_action_eq160_2_register_0 < pif_expression__expression_action_eq160_2_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq160_2_register_1 = pif_expression__expression_action_eq160_2_register_3 + pif_expression__expression_action_eq160_2_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq160_2_register_3 = 0xffffffff;
        pif_expression__expression_action_eq160_2_register_2 = 0xffffffff;
        pif_expression__expression_action_eq160_2_register_4 = pif_expression__expression_action_eq160_2_register_0 & pif_expression__expression_action_eq160_2_register_3;
        pif_expression__expression_action_eq160_2_register_5 = pif_expression__expression_action_eq160_2_register_1 & pif_expression__expression_action_eq160_2_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq160_2_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq160_2_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq160_3) */
        unsigned int pif_expression__expression_action_eq160_3_register_2;

        /* primitive body */
        //expression _expression_action_eq160_3: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq160_3_register_0;
        unsigned int pif_expression__expression_action_eq160_3_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq160_3_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq160_3_register_2 = 0x8;
        pif_expression__expression_action_eq160_3_register_0 = pif_expression__expression_action_eq160_3_register_1 + pif_expression__expression_action_eq160_3_register_2;
        pif_expression__expression_action_eq160_3_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq160_3_register_1 = 0xff;
        pif_expression__expression_action_eq160_3_register_2 = pif_expression__expression_action_eq160_3_register_0 & pif_expression__expression_action_eq160_3_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq160_3_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq160_4) */
        unsigned int pif_expression__expression_action_eq160_4_register_2;

        /* primitive body */
        //expression _expression_action_eq160_4: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq160_4_register_0;
        unsigned int pif_expression__expression_action_eq160_4_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq160_4_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq160_4_register_2 = 0x1;
        pif_expression__expression_action_eq160_4_register_0 = pif_expression__expression_action_eq160_4_register_1 + pif_expression__expression_action_eq160_4_register_2;
        pif_expression__expression_action_eq160_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq160_4_register_1 = 0xff;
        pif_expression__expression_action_eq160_4_register_2 = pif_expression__expression_action_eq160_4_register_0 & pif_expression__expression_action_eq160_4_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq160_4_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq160_5) */
        unsigned int pif_expression__expression_action_eq160_5_register_0;

        /* primitive body */
        //expression _expression_action_eq160_5: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq160_5_register_1;
        unsigned int pif_expression__expression_action_eq160_5_register_2;
        unsigned int pif_expression__expression_action_eq160_5_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq160_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq160_5_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq160_5_register_3 = pif_expression__expression_action_eq160_5_register_1 & 0xff;
        pif_expression__expression_action_eq160_5_register_0 = pif_expression__expression_action_eq160_5_register_3 & pif_expression__expression_action_eq160_5_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq160_5_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq160_5_register_2 = pif_expression__expression_action_eq160_5_register_3 + pif_expression__expression_action_eq160_5_register_0;
        pif_expression__expression_action_eq160_5_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq160_5_register_3 = 0xffff;
        pif_expression__expression_action_eq160_5_register_0 = pif_expression__expression_action_eq160_5_register_2 & pif_expression__expression_action_eq160_5_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq160_5_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq224(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq224 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq224 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq224");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq224");
#endif

    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq224_0) */
        unsigned int pif_expression__expression_action_eq224_0_register_0;

        /* primitive body */
        //expression _expression_action_eq224_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq224_0_register_1;
        unsigned int pif_expression__expression_action_eq224_0_register_2;
        unsigned int pif_expression__expression_action_eq224_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq224_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq224_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq224_0_register_3 = pif_expression__expression_action_eq224_0_register_1 & 0xffff;
        pif_expression__expression_action_eq224_0_register_0 = pif_expression__expression_action_eq224_0_register_3 & pif_expression__expression_action_eq224_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq224_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq224_1) */
        unsigned int pif_expression__expression_action_eq224_1_register_2;

        /* primitive body */
        //expression _expression_action_eq224_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq224_1_register_0;
        unsigned int pif_expression__expression_action_eq224_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq224_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq224_1_register_2 = 0x4;
        pif_expression__expression_action_eq224_1_register_0 = pif_expression__expression_action_eq224_1_register_1 + pif_expression__expression_action_eq224_1_register_2;
        pif_expression__expression_action_eq224_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq224_1_register_1 = 0xff;
        pif_expression__expression_action_eq224_1_register_2 = pif_expression__expression_action_eq224_1_register_0 & pif_expression__expression_action_eq224_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq224_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq224_2) */
        unsigned int pif_expression__expression_action_eq224_2_register_2;

        /* primitive body */
        //expression _expression_action_eq224_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq224_2_register_0;
        unsigned int pif_expression__expression_action_eq224_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq224_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq224_2_register_2 = 0x4;
        pif_expression__expression_action_eq224_2_register_0 = pif_expression__expression_action_eq224_2_register_1 + pif_expression__expression_action_eq224_2_register_2;
        pif_expression__expression_action_eq224_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq224_2_register_1 = 0xff;
        pif_expression__expression_action_eq224_2_register_2 = pif_expression__expression_action_eq224_2_register_0 & pif_expression__expression_action_eq224_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq224_2_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq224_3) */
        unsigned int pif_expression__expression_action_eq224_3_register_4;
        unsigned int pif_expression__expression_action_eq224_3_register_5;

        /* primitive body */
        //expression _expression_action_eq224_3: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq224_3_register_0;
        unsigned int pif_expression__expression_action_eq224_3_register_1;
        unsigned int pif_expression__expression_action_eq224_3_register_2;
        unsigned int pif_expression__expression_action_eq224_3_register_3;
        unsigned int pif_expression__expression_action_eq224_3_register_6;
        unsigned int pif_expression__expression_action_eq224_3_register_7;
        unsigned int pif_expression__expression_action_eq224_3_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq224_3_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq224_3_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq224_3_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq224_3_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq224_3_register_6 = ~pif_expression__expression_action_eq224_3_register_4;
        pif_expression__expression_action_eq224_3_register_7 = ~pif_expression__expression_action_eq224_3_register_5;
        pif_expression__expression_action_eq224_3_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq224_3_register_5 = pif_expression__expression_action_eq224_3_register_6 + pif_expression__expression_action_eq224_3_register_8;
        if (pif_expression__expression_action_eq224_3_register_5 < pif_expression__expression_action_eq224_3_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq224_3_register_4 = pif_expression__expression_action_eq224_3_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq224_3_register_0 = pif_expression__expression_action_eq224_3_register_2 + pif_expression__expression_action_eq224_3_register_5;
        if (pif_expression__expression_action_eq224_3_register_0 < pif_expression__expression_action_eq224_3_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq224_3_register_1 = pif_expression__expression_action_eq224_3_register_3 + pif_expression__expression_action_eq224_3_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq224_3_register_3 = 0xffffffff;
        pif_expression__expression_action_eq224_3_register_2 = 0xffffffff;
        pif_expression__expression_action_eq224_3_register_4 = pif_expression__expression_action_eq224_3_register_0 & pif_expression__expression_action_eq224_3_register_3;
        pif_expression__expression_action_eq224_3_register_5 = pif_expression__expression_action_eq224_3_register_1 & pif_expression__expression_action_eq224_3_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq224_3_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq224_3_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq224_4) */
        unsigned int pif_expression__expression_action_eq224_4_register_2;

        /* primitive body */
        //expression _expression_action_eq224_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq224_4_register_0;
        unsigned int pif_expression__expression_action_eq224_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq224_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq224_4_register_2 = 0x8;
        pif_expression__expression_action_eq224_4_register_0 = pif_expression__expression_action_eq224_4_register_1 + pif_expression__expression_action_eq224_4_register_2;
        pif_expression__expression_action_eq224_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq224_4_register_1 = 0xff;
        pif_expression__expression_action_eq224_4_register_2 = pif_expression__expression_action_eq224_4_register_0 & pif_expression__expression_action_eq224_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq224_4_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq224_5) */
        unsigned int pif_expression__expression_action_eq224_5_register_2;

        /* primitive body */
        //expression _expression_action_eq224_5: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq224_5_register_0;
        unsigned int pif_expression__expression_action_eq224_5_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq224_5_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq224_5_register_2 = 0x1;
        pif_expression__expression_action_eq224_5_register_0 = pif_expression__expression_action_eq224_5_register_1 + pif_expression__expression_action_eq224_5_register_2;
        pif_expression__expression_action_eq224_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq224_5_register_1 = 0xff;
        pif_expression__expression_action_eq224_5_register_2 = pif_expression__expression_action_eq224_5_register_0 & pif_expression__expression_action_eq224_5_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq224_5_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq224_6) */
        unsigned int pif_expression__expression_action_eq224_6_register_0;

        /* primitive body */
        //expression _expression_action_eq224_6: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq224_6_register_1;
        unsigned int pif_expression__expression_action_eq224_6_register_2;
        unsigned int pif_expression__expression_action_eq224_6_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq224_6_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq224_6_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq224_6_register_3 = pif_expression__expression_action_eq224_6_register_1 & 0xff;
        pif_expression__expression_action_eq224_6_register_0 = pif_expression__expression_action_eq224_6_register_3 & pif_expression__expression_action_eq224_6_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq224_6_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq224_6_register_2 = pif_expression__expression_action_eq224_6_register_3 + pif_expression__expression_action_eq224_6_register_0;
        pif_expression__expression_action_eq224_6_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq224_6_register_3 = 0xffff;
        pif_expression__expression_action_eq224_6_register_0 = pif_expression__expression_action_eq224_6_register_2 & pif_expression__expression_action_eq224_6_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq224_6_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

static int pif_action_exec_egress__action_eq252(__lmem uint32_t *_pif_parrep, __xread uint32_t *_pif_actdatabuf, unsigned _pif_debug)
{
    int _pif_return = PIF_RETURN_FORWARD;
    __xread struct pif_action_actiondata_egress__action_eq252 *_pif_act_data = (__xread struct pif_action_actiondata_egress__action_eq252 *)_pif_actdatabuf;
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    __lmem struct pif_header_egressTimestamp *egressTimestamp;
    __lmem struct pif_header_ingressTimestamp *ingressTimestamp;
    __lmem struct pif_header_udp *udp;
    __lmem struct pif_header_tailINT *tailINT;
    __lmem struct pif_header_hop_latency *hop_latency;
    __lmem struct pif_header_int_ingress_egress_ports *int_ingress_egress_ports;
    __lmem struct pif_header_ipv4 *ipv4;
    __lmem struct pif_header_countpackage *countpackage;
    __lmem struct pif_header_hopINT *hopINT;
    __lmem struct pif_header_shimINT *shimINT;
    __lmem struct pif_header_switch_local *switch_local;
    __lmem struct pif_header_switch_id *switch_id;
    __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
    unsigned int _pif_flc_val_calc;
#ifdef PIF_DEBUG
    if (_pif_debug & PIF_ACTION_OPDATA_DBGFLAG_BREAK) {
        /* copy the table number and rule number into mailboxes */
        unsigned int temp0, temp1;
        temp0 = local_csr_read(local_csr_mailbox_2);
        temp1 = local_csr_read(local_csr_mailbox_3);
        local_csr_write(local_csr_mailbox_2, _pif_act_data->__pif_rule_no);
        local_csr_write(local_csr_mailbox_3, _pif_act_data->__pif_table_no);
#if SIMULATION == 1
        __asm { /* add nops so mailboxes have time to propagate */
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        nop;
        }
#endif
        __debug_label("pif_table_hit_egress__action_eq252");
        local_csr_write(local_csr_mailbox_2, temp0);
        local_csr_write(local_csr_mailbox_3, temp1);
    }
#endif
#ifdef PIF_DEBUG
    __debug_label("pif_action_state_egress__action_eq252");
#endif

    egressTimestamp = (__lmem struct pif_header_egressTimestamp *) (_pif_parrep + PIF_PARREP_egressTimestamp_OFF_LW);
    ingressTimestamp = (__lmem struct pif_header_ingressTimestamp *) (_pif_parrep + PIF_PARREP_ingressTimestamp_OFF_LW);
    udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
    tailINT = (__lmem struct pif_header_tailINT *) (_pif_parrep + PIF_PARREP_tailINT_OFF_LW);
    hop_latency = (__lmem struct pif_header_hop_latency *) (_pif_parrep + PIF_PARREP_hop_latency_OFF_LW);
    int_ingress_egress_ports = (__lmem struct pif_header_int_ingress_egress_ports *) (_pif_parrep + PIF_PARREP_int_ingress_egress_ports_OFF_LW);
    ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
    countpackage = (__lmem struct pif_header_countpackage *) (_pif_parrep + PIF_PARREP_countpackage_OFF_LW);
    hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
    shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
    switch_local = (__lmem struct pif_header_switch_local *) (_pif_parrep + PIF_PARREP_switch_local_OFF_LW);
    switch_id = (__lmem struct pif_header_switch_id *) (_pif_parrep + PIF_PARREP_switch_id_OFF_LW);
    intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (_pif_parrep + PIF_PARREP_intrinsic_metadata_OFF_LW);
    PIF_PARREP_SET_egressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_switch_id_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_tailINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_int_ingress_egress_ports_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ipv4_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hopINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_shimINT_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_ingressTimestamp_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_countpackage_DIRTY(_pif_ctldata);
    PIF_PARREP_SET_hop_latency_DIRTY(_pif_ctldata);

    _pif_flc_val_calc = PIF_HEADER_GET_ipv4___headerChecksum(ipv4);

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 1);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    {
        /* add_header(switch_id) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_switch_id_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_switch_id_LEN_LW; i++)
                    ((__lmem uint32_t *)switch_id)[i] = 0;
            }
            PIF_PARREP_SET_switch_id_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(switch_id.int_switch_id,_expression_action_eq252_0) */
        unsigned int pif_expression__expression_action_eq252_0_register_0;

        /* primitive body */
        //expression _expression_action_eq252_0: ((switch_local.switch_id) & (0xffffffff))
        {
        unsigned int pif_expression__expression_action_eq252_0_register_1;
        unsigned int pif_expression__expression_action_eq252_0_register_2;
        unsigned int pif_expression__expression_action_eq252_0_register_3;
        //subexpression 2: 0xffffffff
        // constant : 0xffffffff

        //subexpression 0: (switch_local.switch_id)&(0xffffffff)
        pif_expression__expression_action_eq252_0_register_1 = switch_local->switch_id;
        pif_expression__expression_action_eq252_0_register_2 = 0xffffffff;
        /* implicit cast 16 -> 32 */
        pif_expression__expression_action_eq252_0_register_3 = pif_expression__expression_action_eq252_0_register_1 & 0xffff;
        pif_expression__expression_action_eq252_0_register_0 = pif_expression__expression_action_eq252_0_register_3 & pif_expression__expression_action_eq252_0_register_2;
        }

        switch_id->int_switch_id = pif_expression__expression_action_eq252_0_register_0;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_1) */
        unsigned int pif_expression__expression_action_eq252_1_register_2;

        /* primitive body */
        //expression _expression_action_eq252_1: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_1_register_0;
        unsigned int pif_expression__expression_action_eq252_1_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq252_1_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_1_register_2 = 0x4;
        pif_expression__expression_action_eq252_1_register_0 = pif_expression__expression_action_eq252_1_register_1 + pif_expression__expression_action_eq252_1_register_2;
        pif_expression__expression_action_eq252_1_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq252_1_register_1 = 0xff;
        pif_expression__expression_action_eq252_1_register_2 = pif_expression__expression_action_eq252_1_register_0 & pif_expression__expression_action_eq252_1_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_1_register_2;

    }
    {
        /* add_header(int_ingress_egress_ports) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_int_ingress_egress_ports_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_int_ingress_egress_ports_LEN_LW; i++)
                    ((__lmem uint32_t *)int_ingress_egress_ports)[i] = 0;
            }
            PIF_PARREP_SET_int_ingress_egress_ports_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(int_ingress_egress_ports.int_ingress_id,switch_local.port_in) */

        /* primitive body */
        int_ingress_egress_ports->int_ingress_id = switch_local->port_in;

    }
    {
        /* modify_field(int_ingress_egress_ports.int_egress_id,switch_local.port_out) */

        /* primitive body */
        int_ingress_egress_ports->int_egress_id = switch_local->port_out;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_2) */
        unsigned int pif_expression__expression_action_eq252_2_register_2;

        /* primitive body */
        //expression _expression_action_eq252_2: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_2_register_0;
        unsigned int pif_expression__expression_action_eq252_2_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq252_2_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_2_register_2 = 0x4;
        pif_expression__expression_action_eq252_2_register_0 = pif_expression__expression_action_eq252_2_register_1 + pif_expression__expression_action_eq252_2_register_2;
        pif_expression__expression_action_eq252_2_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq252_2_register_1 = 0xff;
        pif_expression__expression_action_eq252_2_register_2 = pif_expression__expression_action_eq252_2_register_0 & pif_expression__expression_action_eq252_2_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_2_register_2;

    }
    {
        /* modify_field(switch_local.egresststamp,intrinsic_metadata.current_global_tstamp) */

        /* primitive body */
        /* populate intrinsic_metadata.current_global_tstamp */
        {
            struct mac_time_data curr_mac_time = mac_time_calc(mac_time_state);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___0(intrinsic_metadata, curr_mac_time.nsec);
            PIF_HEADER_SET_intrinsic_metadata___current_global_tstamp___1(intrinsic_metadata, curr_mac_time.sec);
        }
        switch_local->egresststamp = ((intrinsic_metadata->current_global_tstamp >> 8) & 0xffffff);
        switch_local->__egresststamp_1 = ((intrinsic_metadata->current_global_tstamp & 0xff) << 24) | ((intrinsic_metadata->__current_global_tstamp_1 >> 8) & 0xffffff);
        switch_local->__egresststamp_2 = intrinsic_metadata->__current_global_tstamp_1;

    }
    {
        /* add_header(hop_latency) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_hop_latency_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_hop_latency_LEN_LW; i++)
                    ((__lmem uint32_t *)hop_latency)[i] = 0;
            }
            PIF_PARREP_SET_hop_latency_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(hop_latency.int_hop_latency,_expression_action_eq252_3) */
        unsigned int pif_expression__expression_action_eq252_3_register_4;
        unsigned int pif_expression__expression_action_eq252_3_register_5;

        /* primitive body */
        //expression _expression_action_eq252_3: ((((switch_local.egresststamp) - (switch_local.ingresststamp))) & (0xffffffffffffffff))
        {
        unsigned int pif_expression__expression_action_eq252_3_register_0;
        unsigned int pif_expression__expression_action_eq252_3_register_1;
        unsigned int pif_expression__expression_action_eq252_3_register_2;
        unsigned int pif_expression__expression_action_eq252_3_register_3;
        unsigned int pif_expression__expression_action_eq252_3_register_6;
        unsigned int pif_expression__expression_action_eq252_3_register_7;
        unsigned int pif_expression__expression_action_eq252_3_register_8;
        //subexpression 1: (switch_local.egresststamp)-(switch_local.ingresststamp)
        pif_expression__expression_action_eq252_3_register_2 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;
        pif_expression__expression_action_eq252_3_register_3 = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq252_3_register_4 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;
        pif_expression__expression_action_eq252_3_register_5 = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        pif_expression__expression_action_eq252_3_register_6 = ~pif_expression__expression_action_eq252_3_register_4;
        pif_expression__expression_action_eq252_3_register_7 = ~pif_expression__expression_action_eq252_3_register_5;
        pif_expression__expression_action_eq252_3_register_8 = 0x1;
        {
        unsigned int overflow;
        pif_expression__expression_action_eq252_3_register_5 = pif_expression__expression_action_eq252_3_register_6 + pif_expression__expression_action_eq252_3_register_8;
        if (pif_expression__expression_action_eq252_3_register_5 < pif_expression__expression_action_eq252_3_register_6)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq252_3_register_4 = pif_expression__expression_action_eq252_3_register_7 + 0 + overflow;
        }
        {
        unsigned int overflow;
        pif_expression__expression_action_eq252_3_register_0 = pif_expression__expression_action_eq252_3_register_2 + pif_expression__expression_action_eq252_3_register_5;
        if (pif_expression__expression_action_eq252_3_register_0 < pif_expression__expression_action_eq252_3_register_2)
            overflow = 1;
        else
            overflow = 0;
        pif_expression__expression_action_eq252_3_register_1 = pif_expression__expression_action_eq252_3_register_3 + pif_expression__expression_action_eq252_3_register_4 + overflow;
        }
        //subexpression 2: 0xffffffffffffffff
        // constant : 0xffffffffffffffff

        //subexpression 0: (((switch_local.egresststamp)-(switch_local.ingresststamp)))&(0xffffffffffffffff)
        pif_expression__expression_action_eq252_3_register_3 = 0xffffffff;
        pif_expression__expression_action_eq252_3_register_2 = 0xffffffff;
        pif_expression__expression_action_eq252_3_register_4 = pif_expression__expression_action_eq252_3_register_0 & pif_expression__expression_action_eq252_3_register_3;
        pif_expression__expression_action_eq252_3_register_5 = pif_expression__expression_action_eq252_3_register_1 & pif_expression__expression_action_eq252_3_register_2;
        }

        hop_latency->int_hop_latency = pif_expression__expression_action_eq252_3_register_5;
        hop_latency->__int_hop_latency_1 = pif_expression__expression_action_eq252_3_register_4;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_4) */
        unsigned int pif_expression__expression_action_eq252_4_register_2;

        /* primitive body */
        //expression _expression_action_eq252_4: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_4_register_0;
        unsigned int pif_expression__expression_action_eq252_4_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq252_4_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_4_register_2 = 0x8;
        pif_expression__expression_action_eq252_4_register_0 = pif_expression__expression_action_eq252_4_register_1 + pif_expression__expression_action_eq252_4_register_2;
        pif_expression__expression_action_eq252_4_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq252_4_register_1 = 0xff;
        pif_expression__expression_action_eq252_4_register_2 = pif_expression__expression_action_eq252_4_register_0 & pif_expression__expression_action_eq252_4_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_4_register_2;

    }
    {
        /* add_header(ingressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_ingressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_ingressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)ingressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_ingressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(ingressTimestamp.int_ingressTimestamp,switch_local.ingresststamp) */

        /* primitive body */
        ingressTimestamp->int_ingressTimestamp = (switch_local->ingresststamp << 8) | ((switch_local->__ingresststamp_1 >> 24) & 0xff);
        ingressTimestamp->__int_ingressTimestamp_1 = ((switch_local->__ingresststamp_1 & 0xffffff) << 8) | switch_local->__ingresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_5) */
        unsigned int pif_expression__expression_action_eq252_5_register_2;

        /* primitive body */
        //expression _expression_action_eq252_5: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_5_register_0;
        unsigned int pif_expression__expression_action_eq252_5_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq252_5_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_5_register_2 = 0x8;
        pif_expression__expression_action_eq252_5_register_0 = pif_expression__expression_action_eq252_5_register_1 + pif_expression__expression_action_eq252_5_register_2;
        pif_expression__expression_action_eq252_5_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq252_5_register_1 = 0xff;
        pif_expression__expression_action_eq252_5_register_2 = pif_expression__expression_action_eq252_5_register_0 & pif_expression__expression_action_eq252_5_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_5_register_2;

    }
    {
        /* add_header(egressTimestamp) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_egressTimestamp_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_egressTimestamp_LEN_LW; i++)
                    ((__lmem uint32_t *)egressTimestamp)[i] = 0;
            }
            PIF_PARREP_SET_egressTimestamp_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(egressTimestamp.int_egressTimestamp,switch_local.egresststamp) */

        /* primitive body */
        egressTimestamp->int_egressTimestamp = (switch_local->egresststamp << 8) | ((switch_local->__egresststamp_1 >> 24) & 0xff);
        egressTimestamp->__int_egressTimestamp_1 = ((switch_local->__egresststamp_1 & 0xffffff) << 8) | switch_local->__egresststamp_2;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_6) */
        unsigned int pif_expression__expression_action_eq252_6_register_2;

        /* primitive body */
        //expression _expression_action_eq252_6: ((((shimINT.shim_length) + (0x08))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_6_register_0;
        unsigned int pif_expression__expression_action_eq252_6_register_1;
        //subexpression 4: 0x08
        // constant : 0x8

        //subexpression 1: (shimINT.shim_length)+(0x08)
        pif_expression__expression_action_eq252_6_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_6_register_2 = 0x8;
        pif_expression__expression_action_eq252_6_register_0 = pif_expression__expression_action_eq252_6_register_1 + pif_expression__expression_action_eq252_6_register_2;
        pif_expression__expression_action_eq252_6_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x08)))&(0xff)
        pif_expression__expression_action_eq252_6_register_1 = 0xff;
        pif_expression__expression_action_eq252_6_register_2 = pif_expression__expression_action_eq252_6_register_0 & pif_expression__expression_action_eq252_6_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_6_register_2;

    }
    {
        /* add_header(countpackage) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_countpackage_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_countpackage_LEN_LW; i++)
                    ((__lmem uint32_t *)countpackage)[i] = 0;
            }
            PIF_PARREP_SET_countpackage_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(countpackage.int_ingresscountpackage,switch_local.ingresspackage) */

        /* primitive body */
        countpackage->int_ingresscountpackage = (switch_local->ingresspackage << 8) | switch_local->__ingresspackage_1;

    }
    {
        /* modify_field(shimINT.shim_length,_expression_action_eq252_7) */
        unsigned int pif_expression__expression_action_eq252_7_register_2;

        /* primitive body */
        //expression _expression_action_eq252_7: ((((shimINT.shim_length) + (0x04))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_7_register_0;
        unsigned int pif_expression__expression_action_eq252_7_register_1;
        //subexpression 4: 0x04
        // constant : 0x4

        //subexpression 1: (shimINT.shim_length)+(0x04)
        pif_expression__expression_action_eq252_7_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_7_register_2 = 0x4;
        pif_expression__expression_action_eq252_7_register_0 = pif_expression__expression_action_eq252_7_register_1 + pif_expression__expression_action_eq252_7_register_2;
        pif_expression__expression_action_eq252_7_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((shimINT.shim_length)+(0x04)))&(0xff)
        pif_expression__expression_action_eq252_7_register_1 = 0xff;
        pif_expression__expression_action_eq252_7_register_2 = pif_expression__expression_action_eq252_7_register_0 & pif_expression__expression_action_eq252_7_register_1;
        }

        shimINT->shim_length = pif_expression__expression_action_eq252_7_register_2;

    }
    {
        /* add_header(tailINT) */

        /* primitive body */
        {
            /* zero headers for P4-14 spec compliance */
            if (!PIF_PARREP_tailINT_VALID(_pif_ctldata)) {
                int i;
                for (i = 0; i < PIF_PARREP_tailINT_LEN_LW; i++)
                    ((__lmem uint32_t *)tailINT)[i] = 0;
            }
            PIF_PARREP_SET_tailINT_VALID(_pif_ctldata);
        }
    }
    {
        /* modify_field(tailINT.tail_header,0x000000ff) */

        /* primitive body */
        tailINT->tail_header = 0xff;

    }
    {
        /* modify_field(tailINT.tail_proto,ipv4.protocol) */

        /* primitive body */
        tailINT->tail_proto = ipv4->protocol;

    }
    {
        /* modify_field(tailINT.tail_port,udp.destinationPort) */

        /* primitive body */
        tailINT->tail_port = udp->destinationPort;

    }
    {
        /* modify_field(tailINT.tail_dscp,ipv4.typeServiceDiffServ) */

        /* primitive body */
        tailINT->tail_dscp = ipv4->typeServiceDiffServ;

    }
    {
        /* modify_field(hopINT.int_total_hops,_expression_action_eq252_8) */
        unsigned int pif_expression__expression_action_eq252_8_register_2;

        /* primitive body */
        //expression _expression_action_eq252_8: ((((hopINT.int_total_hops) + (0x01))) & (0xff))
        {
        unsigned int pif_expression__expression_action_eq252_8_register_0;
        unsigned int pif_expression__expression_action_eq252_8_register_1;
        //subexpression 4: 0x01
        // constant : 0x1

        //subexpression 1: (hopINT.int_total_hops)+(0x01)
        pif_expression__expression_action_eq252_8_register_1 = hopINT->int_total_hops;
        pif_expression__expression_action_eq252_8_register_2 = 0x1;
        pif_expression__expression_action_eq252_8_register_0 = pif_expression__expression_action_eq252_8_register_1 + pif_expression__expression_action_eq252_8_register_2;
        pif_expression__expression_action_eq252_8_register_0 &= 0xff;
        //subexpression 2: 0xff
        // constant : 0xff

        //subexpression 0: (((hopINT.int_total_hops)+(0x01)))&(0xff)
        pif_expression__expression_action_eq252_8_register_1 = 0xff;
        pif_expression__expression_action_eq252_8_register_2 = pif_expression__expression_action_eq252_8_register_0 & pif_expression__expression_action_eq252_8_register_1;
        }

        hopINT->int_total_hops = pif_expression__expression_action_eq252_8_register_2;

    }
    {
        /* modify_field(ipv4.totalLength,_expression_action_eq252_9) */
        unsigned int pif_expression__expression_action_eq252_9_register_0;

        /* primitive body */
        //expression _expression_action_eq252_9: ((((ipv4.totalLength) + (((shimINT.shim_length) & (0xffff))))) & (0xffff))
        {
        unsigned int pif_expression__expression_action_eq252_9_register_1;
        unsigned int pif_expression__expression_action_eq252_9_register_2;
        unsigned int pif_expression__expression_action_eq252_9_register_3;
        //subexpression 6: 0xffff
        // constant : 0xffff

        //subexpression 4: (shimINT.shim_length)&(0xffff)
        pif_expression__expression_action_eq252_9_register_1 = shimINT->shim_length;
        pif_expression__expression_action_eq252_9_register_2 = 0xffff;
        /* implicit cast 8 -> 16 */
        pif_expression__expression_action_eq252_9_register_3 = pif_expression__expression_action_eq252_9_register_1 & 0xff;
        pif_expression__expression_action_eq252_9_register_0 = pif_expression__expression_action_eq252_9_register_3 & pif_expression__expression_action_eq252_9_register_2;
        //subexpression 1: (ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))
        pif_expression__expression_action_eq252_9_register_3 = ipv4->totalLength;
        pif_expression__expression_action_eq252_9_register_2 = pif_expression__expression_action_eq252_9_register_3 + pif_expression__expression_action_eq252_9_register_0;
        pif_expression__expression_action_eq252_9_register_2 &= 0xffff;
        //subexpression 2: 0xffff
        // constant : 0xffff

        //subexpression 0: (((ipv4.totalLength)+(((shimINT.shim_length)&(0xffff)))))&(0xffff)
        pif_expression__expression_action_eq252_9_register_3 = 0xffff;
        pif_expression__expression_action_eq252_9_register_0 = pif_expression__expression_action_eq252_9_register_2 & pif_expression__expression_action_eq252_9_register_3;
        }

        ipv4->totalLength = pif_expression__expression_action_eq252_9_register_0;

    }

    if (PIF_FLCALC_UPD_INCR(PIF_FLCALC_CALC) != 0 && PIF_PARREP_ipv4_VALID(_pif_ctldata)) {
        unsigned int _pif_flc_update_val;

        _pif_flc_update_val = ((__lmem uint32_t *)ipv4)[0];
        _pif_flc_val_calc = pif_flcalc_csum16_update_lw(_pif_flc_val_calc, _pif_flc_update_val, 0xffff, 0);

        PIF_HEADER_SET_ipv4___headerChecksum(ipv4, _pif_flc_val_calc);
    }
    return _pif_return;
}

extern __forceinline int pif_action_exec_op(__lmem uint32_t *parrep, __xread uint32_t *_actdata)
{
    __xread union pif_action_opdata *opdata = (__xread union pif_action_opdata *) _actdata;
    int ret = -1;

    if (opdata->action_id > PIF_ACTION_ID_MAX) {
        /* FIXME: TODO: account for bad action id */
        return -1;
    }

    PIF_DEBUG_SET_STATE(PIF_DEBUG_STATE_ACTION, opdata->action_id);
    switch (opdata->action_id) {
    case PIF_ACTION_ID_ingress__act:
        ret = pif_action_exec_ingress__act(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq192:
        ret = pif_action_exec_egress__action_eq192(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__add_int_source:
        ret = pif_action_exec_ingress__add_int_source(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__act_0:
        ret = pif_action_exec_ingress__act_0(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__act_1:
        ret = pif_action_exec_ingress__act_1(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__arp_forward:
        ret = pif_action_exec_ingress__arp_forward(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq128:
        ret = pif_action_exec_egress__action_eq128(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__drop:
        ret = pif_action_exec_ingress__drop(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq184:
        ret = pif_action_exec_egress__action_eq184(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq240:
        ret = pif_action_exec_egress__action_eq240(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq88:
        ret = pif_action_exec_egress__action_eq88(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_ingress__ipv4_forward:
        ret = pif_action_exec_ingress__ipv4_forward(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq254:
        ret = pif_action_exec_egress__action_eq254(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq248:
        ret = pif_action_exec_egress__action_eq248(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq160:
        ret = pif_action_exec_egress__action_eq160(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq224:
        ret = pif_action_exec_egress__action_eq224(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    case PIF_ACTION_ID_egress__action_eq252:
        ret = pif_action_exec_egress__action_eq252(parrep, _actdata + PIF_ACTION_OPDATA_LW, opdata->dbg_flags);
        break;
    }
#ifdef PIF_DEBUG
        mem_incr64((__mem __addr40 uint64_t *)(pif_act_stats + opdata->action_id));
#endif

    return ret;
}
