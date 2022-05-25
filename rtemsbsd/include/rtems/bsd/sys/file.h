/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * @file
 *
 * @ingroup rtems_bsd_rtems
 *
 * @brief This header file provides a alternative implementation for interfaces
 *   normally provided via <sys/file.h>.
 */

/*
 * Copyright (C) 2013, 2022 embedded brains GmbH
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

#ifndef _SYS_FILE_H_
#define	_SYS_FILE_H_
#define	_SYS_FILEDESC_H_

#include <rtems/libio_.h>
#include <sys/fcntl.h>
#include <sys/refcount.h>
#include <sys/seq.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct filecaps;
struct filedesc;
struct ucred;

extern const rtems_filesystem_file_handlers_r socketops;

#define	file rtems_libio_tt
#define	f_data pathinfo.node_access_2

#define	maxfiles rtems_libio_number_iops

typedef int fo_kqfilter_t(struct file *, struct knote *);

static inline void *
rtems_bsd_loc_to_f_data(const rtems_filesystem_location_info_t *loc)
{
	return loc->node_access_2;
}

static inline uint32_t
rtems_bsd_fflag_to_libio_flags(u_int fflag)
{
	uint32_t libio_flags = 0;

	if ((fflag & FREAD) == FREAD) {
		libio_flags |= LIBIO_FLAGS_READ;
	}

	if ((fflag & FWRITE) == FWRITE) {
		libio_flags |= LIBIO_FLAGS_WRITE;
	}

	if ((fflag & FNONBLOCK) == FNONBLOCK) {
		libio_flags |= LIBIO_FLAGS_NO_DELAY;
	}

	return (libio_flags);
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

static int inline
rtems_bsd_error_to_status_and_errno(int error)
{
	if (error == 0) {
		return 0;
	} else {
		rtems_set_errno_and_return_minus_one(error);
	}
}

struct file *rtems_bsd_get_file(int fd);

static inline int
rtems_bsd_do_fget(int fd, struct file **fpp)
{
	struct file *fp;

	fp = rtems_bsd_get_file(fd);
	*fpp = fp;
	return (fp != NULL ? 0 : EBADF);
}

#undef fget
#define	fget(td, fd, rights, fpp) rtems_bsd_do_fget(fd, fpp)

static inline void
rtems_bsd_finit(struct file *fp, u_int fflag, void *data,
    const rtems_filesystem_file_handlers_r *ops)
{

	fp->f_data = data;
	fp->pathinfo.handlers = ops;
	rtems_libio_iop_flags_set(fp, LIBIO_FLAGS_OPEN |
	    rtems_bsd_fflag_to_libio_flags(fflag));
}

#undef finit
#define	finit(fp, fflag, type, data, ops) rtems_bsd_finit(fp, fflag, data, ops)

/*
 * WARNING: fdalloc() and falloc_caps() do not increment the reference count of
 * the file descriptor in contrast to FreeBSD.  We must not call the fdrop()
 * corresponding to a fdalloc() or falloc_caps().  The reason for this is that
 * FreeBSD performs a lazy cleanup once the reference count reaches zero.
 * RTEMS uses the reference count to determine if a cleanup is allowed.
 */
#define	fdrop(fp, td) rtems_libio_iop_drop(fp)

static inline int
fo_ioctl(struct file *fp, u_long com, void *data, struct ucred *active_cred,
    struct thread *td)
{

	int rv;

	(void)active_cred;
	(void)td;

	errno = 0;
	rv = ((*fp->pathinfo.handlers->ioctl_h)(fp, com, data));
	if (rv == 0) {
		return (0);
	} else {
		return (errno);
	}
}

#define	FILEDESC_XLOCK(fdp)	rtems_libio_lock()
#define	FILEDESC_XUNLOCK(fdp)	rtems_libio_unlock()
#define	FILEDESC_SLOCK(fdp)	rtems_libio_lock()
#define	FILEDESC_SUNLOCK(fdp)	rtems_libio_unlock()

#undef filecaps_free
#define	filecaps_free(fcaps) do { } while (0)

static inline int
rtems_bsd_falloc(struct thread *td, struct file **resultfp, int *resultfd,
    int flags)
{
	rtems_libio_t *iop;

	(void)td;
	(void)flags;

	iop = rtems_libio_allocate();
	*resultfp = iop;
	*resultfd = rtems_libio_iop_to_descriptor(iop);

	if (iop != NULL) {
		iop->pathinfo.mt_entry = &rtems_filesystem_null_mt_entry;
		rtems_filesystem_location_add_to_mt_entry(&iop->pathinfo);
		return (0);
	} else {
		return (ENFILE);
	}
}

#define	falloc_caps(td, resultfp, resultfd, flags, fcaps) \
    rtems_bsd_falloc(td, resultfp, resultfd, flags)

#define	falloc(td, resultfp, resultfd, flags) \
    rtems_bsd_falloc(td, resultfp, resultfd, flags)

static inline int
rtems_bsd_fget_unlocked(struct filedesc *fdp, int fd, struct file **fpp,
    seq_t *seqp)
{
	struct file *fp;

	(void)fdp;
	(void)seqp;
	fp = rtems_bsd_get_file(fd);
	*fpp = fp;
	return (fp != NULL ? 0 : EBADF);
}

#undef fget_unlocked
#define	fget_unlocked(fdp, fd, needrightsp, fpp, seqp) \
    rtems_bsd_fget_unlocked(fdp, fd, fpp, seqp)

/*
 * WARNING: Use of fdrop() after fclose() corrupts the file descriptor.  See
 * fdrop() comment.
 */
static inline void
fdclose(struct thread *td, struct file *fp, int idx)
{
	(void)td;
	(void)idx;

	rtems_libio_free(fp);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** @} */

#endif /* _SYS_FILE_H_ */
