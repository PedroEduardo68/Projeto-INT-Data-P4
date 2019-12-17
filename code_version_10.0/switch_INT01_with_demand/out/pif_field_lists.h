/* Copyright (C) 2015-2016,  Netronome Systems, Inc.  All rights reserved. */

#ifndef __PIF_FIELD_LISTS_H__
#define __PIF_FIELD_LISTS_H__

/* Generated C source defining layout of field lists in memory */
/* Warning: your edits to this file may be lost */

struct pif_field_list_field_list_1 {
    union {
        struct {
            /* ipv4.sourceAddress[32;0] */
            unsigned int __ipv4__sourceAddress:32;
            /* ipv4.destinationAddress[32;0] */
            unsigned int __ipv4__destinationAddress:32;
            /* ipv4.totalLength[16;0] */
            unsigned int __ipv4__totalLength:16;
            /* ipv4.identification[16;0] */
            unsigned int __ipv4__identification:16;
            /* ipv4.fragmentOffset[16;0] */
            unsigned int __ipv4__fragmentOffset:16;
            /* ipv4.typeServiceDiffServ[8;0] */
            unsigned int __ipv4__typeServiceDiffServ:8;
            /* ipv4.timeToLive[8;0] */
            unsigned int __ipv4__timeToLive:8;
            unsigned int _padding_0:16;
            /* ipv4.protocol[8;0] */
            unsigned int __ipv4__protocol:8;
            /* ipv4.version[4;0] */
            unsigned int __ipv4__version:4;
            /* ipv4.headerLength[4;0] */
            unsigned int __ipv4__headerLength:4;
        };
        uint32_t _raw[5];
    };
};

struct pif_field_list_field_list_1_packed {
    union {
        __packed struct {
            /* ipv4.version[4;0] */
            unsigned int __ipv4__version:4;
            /* ipv4.headerLength[4;4] */
            unsigned int __ipv4__headerLength:4;
            /* ipv4.typeServiceDiffServ[8;8] */
            unsigned int __ipv4__typeServiceDiffServ:8;
            /* ipv4.totalLength[16;16] */
            unsigned int __ipv4__totalLength:16;
            /* ipv4.identification[16;32] */
            unsigned int __ipv4__identification:16;
            /* ipv4.fragmentOffset[16;48] */
            unsigned int __ipv4__fragmentOffset:16;
            /* ipv4.timeToLive[8;64] */
            unsigned int __ipv4__timeToLive:8;
            /* ipv4.protocol[8;72] */
            unsigned int __ipv4__protocol:8;
            /* ipv4.sourceAddress[32;80] */
            unsigned int __ipv4__sourceAddress:32;
            /* ipv4.destinationAddress[32;112] */
            unsigned int __ipv4__destinationAddress:32;
            unsigned int _padding:16;
        };
        uint32_t _raw[5];
    };
};

#endif /* __PIF_FIELD_LISTS_H__ */
