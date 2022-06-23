/**
 * @file
 *
 * @ingroup rtems_bsd_machine
 *
 * @brief LibIO interface for FreeBSD filedesc.
 */

/*
 * Copyright (c) 2020 Chrs Johns.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _RTEMS_BSD_MACHINE_RTEMS_BSD_LIBIO_H_
#define _RTEMS_BSD_MACHINE_RTEMS_BSD_LIBIO_H_

#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/proc.h>

#include <machine/rtems-bsd-vfs.h>

#include <rtems/libio.h>
#include <rtems/libio_.h>
#include <rtems/seterr.h>
#include <stdint.h>

struct rtems_bsd_vfs_loc;

extern const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_nodeops;
extern const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_dirops;
extern const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_fileops;

int rtems_bsd_sysgen_close(rtems_libio_t *iop);

static int inline rtems_bsd_error_to_status_and_errno(int error)
{
	if (error == 0) {
		return 0;
	} else {
		rtems_set_errno_and_return_minus_one(error);
	}
}

static inline u_int
rtems_bsd_libio_flags_to_fflag(uint32_t libio_flags)
{
	u_int fflag = 0;

	if ((libio_flags & LIBIO_FLAGS_READ) == LIBIO_FLAGS_READ) {
		fflag |= FREAD;
	}

	if ((libio_flags & LIBIO_FLAGS_WRITE) == LIBIO_FLAGS_WRITE) {
		fflag |= FWRITE;
	}

	if ((libio_flags & LIBIO_FLAGS_NO_DELAY) == LIBIO_FLAGS_NO_DELAY) {
		fflag |= FNONBLOCK;
	}

	return (fflag);
}

static inline rtems_libio_t *
rtems_bsd_libio_loc_to_iop(const rtems_filesystem_location_info_t *loc)
{
	return (rtems_libio_t *)RTEMS_DECONST(
	    rtems_filesystem_location_info_t *, loc)
	    ->node_access;
}

static struct vnode *
rtems_bsd_libio_loc_to_vnode(const rtems_filesystem_location_info_t *loc)
{
	return (struct vnode *)RTEMS_DECONST(
	    rtems_filesystem_location_info_t *, loc)
	    ->node_access;
}

static struct vnode *
rtems_bsd_libio_loc_to_vnode_dir(const rtems_filesystem_location_info_t *loc)
{
	return (struct vnode *)RTEMS_DECONST(
	    rtems_filesystem_location_info_t *, loc)
	    ->node_access_2;
}

static struct vnode *
rtems_bsd_libio_iop_to_vnode(rtems_libio_t *iop)
{
	return rtems_bsd_libio_loc_to_vnode(&iop->pathinfo);
}

static inline struct file *
rtems_bsd_knote_to_file(const struct knote *kn)
{
	return (((rtems_libio_t *)kn->kn_fp)->data1);
}

struct file *rtems_bsd_iop_to_file(const rtems_libio_t *iop);

/*
 * Set the vnode in the libio location.
 */
void rtems_bsd_libio_loc_set_vnode(
    rtems_filesystem_location_info_t *loc, struct vnode *vn);
void rtems_bsd_libio_loc_set_vnode_dir(
    rtems_filesystem_location_info_t *loc, struct vnode *dvn);

#endif /* _RTEMS_BSD_MACHINE_RTEMS_BSD_LIBIO_H_ */
