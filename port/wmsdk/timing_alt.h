/** @file timing_alt.h
 *
 *  @brief This file contains header for timing alt
 *
 *  Copyright 2008-2020 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its suppliers and/or its
 *  licensors. Title to the Materials remains with NXP, its suppliers and/or its
 *  licensors. The Materials contain trade secrets and proprietary and
 *  confidential information of NXP, its suppliers and/or its licensors. The
 *  Materials are protected by worldwide copyright and trade secret laws and
 *  treaty provisions. No part of the Materials may be used, copied, reproduced,
 *  modified, published, uploaded, posted, transmitted, distributed, or
 *  disclosed in any way without NXP's prior express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

#ifndef TIMING_ALT_H
#define TIMING_ALT_H

#if defined(__arm__)
#include <sys/time.h>
#else
#include <lwip/sockets.h>
#endif
#include <time.h>

#define mbedtls_timing_hr_time timeval

typedef struct {
	struct mbedtls_timing_hr_time	timer;
	uint32_t						int_ms;
	uint32_t						fin_ms;
} mbedtls_timing_delay_context;


unsigned long mbedtls_timing_hardclock(void);

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val,
		int reset);

void mbedtls_set_alarm(int seconds);

int mbedtls_timing_get_delay(void *data);
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);

#endif /* TIMING_ALT_H */
