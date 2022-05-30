/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * @file
 *
 * @ingroup rtems_bsd_rtems
 *
 * @brief TODO.
 */

/*
 * Copyright (C) 2022 embedded brains GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <machine/rtems-bsd-kernel-space.h>

#include <sys/file.h>

/* Avoid referencing the VFS only through rtems_bsd_fget() */
__weak_symbol int
rtems_bsd_sysgen_close(rtems_libio_t *iop)
{

	(void)iop;
	return (-1);
}

int
rtems_bsd_fget(int fd, struct file **fpp, int flags)
{
	rtems_libio_t *iop;
	unsigned int actual_flags;

	if ((uint32_t)fd >= rtems_libio_number_iops) {
		goto bad;
	}

	iop = rtems_libio_iop(fd);
	actual_flags = rtems_libio_iop_hold(iop);

	if ((actual_flags & flags) != flags) {
		goto drop;
	}

	if (iop->pathinfo.handlers->close_h != rtems_bsd_sysgen_close) {
		goto drop;
	}

	*fpp = iop->data1;
	return (0);

drop:
	rtems_libio_iop_drop(iop);

bad:
	*fpp = NULL;
	return (EBADF);
}
