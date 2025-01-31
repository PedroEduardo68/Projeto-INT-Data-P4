
/*
 */

#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"

#ifdef INT_TO_SPEC
int pif_plugin_set_tdelta(EXTRACTED_HEADERS_T *headers,
                          MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;

    /* Get the time at parsing from the intrinsic metadata timestamp
     * Note that we do this in two parts __0 being the 32 lsbs and __1 the 16
     * msbs
     */
    ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
    ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;

    ctime = me_tsc_read();

    delta = ctime - ptime;

    pif_plugin_meta_set__meta__tdelta(headers, delta & 0xffffffff);

    return PIF_PLUGIN_RETURN_FORWARD;
}
#else
int pif_plugin_set_tdelta(EXTRACTED_HEADERS_T *headers,
                          MATCH_DATA_T *match_data)
{
    uint64_t ctime;

    ctime = me_tsc_read();

    pif_plugin_meta_set__meta__tdelta(headers, ctime & 0xffffffff);

    return PIF_PLUGIN_RETURN_FORWARD;
}
#endif