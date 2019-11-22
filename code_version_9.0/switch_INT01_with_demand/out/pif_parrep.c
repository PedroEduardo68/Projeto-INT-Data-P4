/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#include <nfp/me.h>
#include <hashmap.h>
#include "pif_common.h"

extern __forceinline
pif_parrep_extract(__lmem uint32_t *_pif_parrep, __mem __addr40 uint8_t *_pif_parrep_pktdata, unsigned int _pif_parrep_pktlen, __lmem uint32_t *_pif_parrep_fk_ptr, __gpr uint32_t *_pif_parrep_fk_len)
{
    __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
    PIF_PKT_INFO_TYPE struct pif_pkt_info *pkt_info = &pif_pkt_info_global;
    __xread uint32_t _pif_read_xbuf[24];
    unsigned int _pif_read_xbuf_off = 2;
    __gpr unsigned int _pif_parrep_pktoff = -2;
    unsigned int _pif_t_index;
    __gpr int _pif_parrep_state = 0;
    __gpr int _pif_parrep_error = 0;
    int i;

    /* First zero the parsed representation control data fields */
    for (i = 0; i < PIF_PARREP_CTLDATA_LEN_LW; i++)
        _pif_parrep[PIF_PARREP_CTLDATA_OFF_LW + i] = 0;

    _pif_parrep_pktdata -= _pif_read_xbuf_off;
    mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
    _pif_t_index = ((__ctx() << 5) | __xfer_reg_number(_pif_read_xbuf)) << 2;
__label_start:
    { /* implementation of parse node start */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_ethernet *ethernet;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_start");
#endif

        ethernet = (__lmem struct pif_header_ethernet *) (_pif_parrep + PIF_PARREP_ethernet_OFF_LW);
        {
            /* extract(ethernet) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_ethernet_LEN_LW;
                    sizeB = PIF_PARREP_ethernet_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_ethernet_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 4 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 4 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 2 of 4 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 3 of 4 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_ethernet_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_start;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_ethernet_VALID(_pif_ctldata);
                PIF_PARREP_SET_ethernet_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
        if (((ethernet->etherType) == (0x806))) {
            __critical_path(); /* prioritize the fall through */
        } else if (((ethernet->etherType) == (0x800))) {
            goto __label_parse_ipv4;
        } else {
            goto _pif_parrep_label_exit;
        }
    } /* end of implementation of parse node start */
__label_parse_arp:
    { /* implementation of parse node parse_arp */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_arp *arp;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_parse_arp");
#endif

        arp = (__lmem struct pif_header_arp *) (_pif_parrep + PIF_PARREP_arp_OFF_LW);
        {
            /* extract(arp) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_arp_LEN_LW;
                    sizeB = PIF_PARREP_arp_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_arp_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 2 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 3 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 4 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 5 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 6 of 7 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_arp_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_arp;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_arp_VALID(_pif_ctldata);
                PIF_PARREP_SET_arp_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
#ifndef PIF_GLOBAL_FLOWCACHE_DISABLED
        {
            __lmem struct pif_global_flowkey_arp *_pif_fk = (__lmem struct pif_global_flowkey_arp *)(_pif_parrep_fk_ptr + (*_pif_parrep_fk_len));
            _pif_fk->arp__targetProtocolAddress = arp->targetProtocolAddress;
            (*_pif_parrep_fk_len) += 1;
        }
#endif
        if (((arp->hardwareType) == (0x800))) {
            __critical_path(); /* prioritize the fall through */
        } else {
            goto _pif_parrep_label_exit;
        }
    } /* end of implementation of parse node parse_arp */
__label_parse_ipv4:
    { /* implementation of parse node parse_ipv4 */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_ipv4 *ipv4;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_parse_ipv4");
#endif

        ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
        {
            /* extract(ipv4) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_ipv4_LEN_LW;
                    sizeB = PIF_PARREP_ipv4_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_ipv4_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 2 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 3 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 4 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_ipv4_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_ipv4;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_ipv4_VALID(_pif_ctldata);
                PIF_PARREP_SET_ipv4_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
#ifndef PIF_GLOBAL_FLOWCACHE_DISABLED
        {
            __lmem struct pif_global_flowkey_ipv4 *_pif_fk = (__lmem struct pif_global_flowkey_ipv4 *)(_pif_parrep_fk_ptr + (*_pif_parrep_fk_len));
            _pif_fk->ipv4__destinationAddress = ipv4->destinationAddress;
            _pif_fk->ipv4__typeServiceDiffServ = ipv4->typeServiceDiffServ;
            _pif_fk->__padding = 0;
            (*_pif_parrep_fk_len) += 2;
        }
#endif
        if (((ipv4->protocol) == (0x6))) {
            __critical_path(); /* prioritize the fall through */
        } else if (((ipv4->protocol) == (0x11))) {
            goto __label_parse_udp;
        } else {
            goto _pif_parrep_label_exit;
        }
    } /* end of implementation of parse node parse_ipv4 */
__label_parse_tcp:
    { /* implementation of parse node parse_tcp */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_tcp *tcp;
        __lmem struct pif_header_ipv4 *ipv4;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_parse_tcp");
#endif

        tcp = (__lmem struct pif_header_tcp *) (_pif_parrep + PIF_PARREP_tcp_OFF_LW);
        ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
        {
            /* extract(tcp) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_tcp_LEN_LW;
                    sizeB = PIF_PARREP_tcp_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_tcp_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 2 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 3 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 4 of 5 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_tcp_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_tcp;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_tcp_VALID(_pif_ctldata);
                PIF_PARREP_SET_tcp_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
        if (((ipv4->typeServiceDiffServ) == (0x17))) {
            __critical_path(); /* prioritize the fall through */
        } else {
            goto _pif_parrep_label_exit;
        }
    } /* end of implementation of parse node parse_tcp */
__label_parse_shimINT:
    { /* implementation of parse node parse_shimINT */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_shimINT *shimINT;
        __lmem struct pif_header_hopINT *hopINT;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_parse_shimINT");
#endif

        shimINT = (__lmem struct pif_header_shimINT *) (_pif_parrep + PIF_PARREP_shimINT_OFF_LW);
        hopINT = (__lmem struct pif_header_hopINT *) (_pif_parrep + PIF_PARREP_hopINT_OFF_LW);
        {
            /* extract(shimINT) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_shimINT_LEN_LW;
                    sizeB = PIF_PARREP_shimINT_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_shimINT_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 1 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_shimINT_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_shimINT;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_shimINT_VALID(_pif_ctldata);
                PIF_PARREP_SET_shimINT_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
        {
            /* extract(hopINT) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_hopINT_LEN_LW;
                    sizeB = PIF_PARREP_hopINT_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_hopINT_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 2 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 2 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_hopINT_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_shimINT;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_hopINT_VALID(_pif_ctldata);
                PIF_PARREP_SET_hopINT_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
#ifndef PIF_GLOBAL_FLOWCACHE_DISABLED
        {
            __lmem struct pif_global_flowkey_hopINT *_pif_fk = (__lmem struct pif_global_flowkey_hopINT *)(_pif_parrep_fk_ptr + (*_pif_parrep_fk_len));
            _pif_fk->hopINT__int_instruction_bit = hopINT->int_instruction_bit;
            _pif_fk->__padding = 0;
            (*_pif_parrep_fk_len) += 1;
        }
#endif
        goto _pif_parrep_label_exit;
    } /* end of implementation of parse node parse_shimINT */
__label_parse_udp:
    { /* implementation of parse node parse_udp */
        __lmem struct pif_parrep_ctldata *_pif_ctldata = (__lmem struct pif_parrep_ctldata *)(_pif_parrep + PIF_PARREP_CTLDATA_OFF_LW);
        __lmem struct pif_header_udp *udp;
        __lmem struct pif_header_ipv4 *ipv4;
#ifdef PIF_DEBUG
        __debug_label("pif_parrep_state_parse_udp");
#endif

        udp = (__lmem struct pif_header_udp *) (_pif_parrep + PIF_PARREP_udp_OFF_LW);
        ipv4 = (__lmem struct pif_header_ipv4 *) (_pif_parrep + PIF_PARREP_ipv4_OFF_LW);
        {
            /* extract(udp) */

            /* primitive body */
            {
                __gpr uint32_t _pif_parrep_hdrsz = 0;

                {
                    __lmem uint32_t *lm32;
                    unsigned int sizeLW, sizeB;
                    unsigned int lmoff;
                    unsigned int i;

                    sizeLW = PIF_PARREP_udp_LEN_LW;
                    sizeB = PIF_PARREP_udp_LEN_B;
                    lm32 = _pif_parrep + PIF_PARREP_udp_OFF_LW;

                    if (_pif_read_xbuf_off + sizeB > 24 * 4) {
                        _pif_parrep_pktoff += _pif_read_xbuf_off;
                        _pif_parrep_pktdata += _pif_read_xbuf_off;
                        mem_read32(_pif_read_xbuf, _pif_parrep_pktdata, sizeof(_pif_read_xbuf));
                        _pif_read_xbuf_off = 0;
                    }
                    __critical_path();


                    if (_pif_read_xbuf_off & 0x3) {
                        unsigned int lmval;

                        local_csr_write(local_csr_t_index_byte_index, _pif_t_index + _pif_read_xbuf_off);
                        __asm byte_align_be[--, *$index++];
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                        __asm byte_align_be[lmval, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    } else {
                        unsigned int lmval;

                        __critical_path();
                        local_csr_write(local_csr_t_index, _pif_t_index + _pif_read_xbuf_off);
                         /* unroll lw 0 of 2 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                         /* unroll lw 1 of 2 */
                        __asm alu[lmval, --, B, *$index++];
                        *lm32 = lmval;
                        lm32 += 1;
                    }
                        __implicit_read(_pif_read_xbuf);
                    _pif_read_xbuf_off += sizeB;
                }
                _pif_parrep_hdrsz = PIF_PARREP_udp_LEN_B;

                if (_pif_parrep_pktoff + _pif_read_xbuf_off > _pif_parrep_pktlen) {
                    _pif_parrep_error = PIF_PARSE_ERROR_OUT_OF_PACKET;
                    _pif_parrep_state = PIF_PARREP_STATE_parse_udp;
                    goto _pif_parrep_label_error;
                }
                __critical_path();
                PIF_PARREP_SET_udp_VALID(_pif_ctldata);
                PIF_PARREP_SET_udp_ORIG_LEN(_pif_ctldata, _pif_parrep_hdrsz);
            }
        }
        if (((ipv4->typeServiceDiffServ) == (0x17))) {
            goto __label_parse_shimINT;
        } else {
            goto _pif_parrep_label_exit;
        }
    } /* end of implementation of parse node parse_udp */
_pif_parrep_label_exit:
    pif_pkt_info_spec.pkt_pl_off = _pif_parrep_pktoff + _pif_read_xbuf_off;
    PIF_PARREP_SET_VALID(_pif_ctldata);
#ifndef PIF_GLOBAL_FLOWCACHE_DISABLED
    _pif_parrep_fk_ptr[(*_pif_parrep_fk_len) + 0] = _pif_parrep[PIF_PARREP_CTLDATA_OFF_LW + 0] & 0x89000400;
    _pif_parrep_fk_ptr[(*_pif_parrep_fk_len) + 1] = _pif_parrep[PIF_PARREP_CTLDATA_OFF_LW + 1] & 0x0;
    (*_pif_parrep_fk_len) += PIF_PARREP_CTLDATA_LEN_LW;
#endif /* !PIF_GLOBAL_FLOWCACHE_DISABLED */
    return 0;
_pif_parrep_label_error:
    pif_pkt_info_spec.pkt_pl_off = _pif_parrep_pktoff + _pif_read_xbuf_off;
    pif_global_set_stdmd_parser_error_location(_pif_parrep, _pif_parrep_state);
    return -_pif_parrep_error;
}

extern __forceinline int
pif_parrep_exceptions(__lmem uint32_t *_pif_parrep, int _pif_pe_error, __lmem uint32_t *_pif_parrep_fk_ptr, __gpr uint32_t *_pif_parrep_fk_len)
{
    return -1; /* no exceptions, always fail */
}
