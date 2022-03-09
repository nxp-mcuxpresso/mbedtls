/** @file threading_alt.c
 *
 *  @brief This file contains threading alt and related functions
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

#include "threading_alt.h"
#include <mbedtls/threading.h>
#include <wm_mbedtls_debug.h>
#include <stdio.h>

static void wmos_wrap_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	char mutex_name_buf[12];
	static int mutex_count = 1;

	snprintf(mutex_name_buf, sizeof(mutex_name_buf),
			"mbd_mtx-%d", mutex_count++);

	if (WM_SUCCESS != os_mutex_create((os_mutex_t *) mutex,
			mutex_name_buf,
			OS_MUTEX_INHERIT)) {
		wm_mbedtls_e("%s: mutex creation failed", __func__);
	}
}

static void wmos_wrap_mutex_free(mbedtls_threading_mutex_t *mutex)
{
	os_mutex_delete((os_mutex_t *) mutex);
}

static int wmos_wrap_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	return os_mutex_get((os_mutex_t *) mutex,
			OS_WAIT_FOREVER);
}

static int wmos_wrap_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	return os_mutex_put((os_mutex_t *) mutex);
}

void wm_mbedtls_set_threading_alt()
{
	mbedtls_threading_set_alt(wmos_wrap_mutex_init,
			wmos_wrap_mutex_free,
			wmos_wrap_mutex_lock,
			wmos_wrap_mutex_unlock);
}
