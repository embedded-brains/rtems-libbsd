/**
 * @file
 *
 * @ingroup rtems_bsd_rtems
 *
 * @brief TODO.
 */

/*
 * Copyright 2001 The FreeBSD Project. All Rights Reserved.
 * Copyright 2020 Chris Johns
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE FREEBSD PROJECT ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE FREEBSD PROJECT BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if !defined(RTEMS_BSD_CHECK_READDIR_DIRENT)
#define RTEMS_BSD_CHECK_READDIR_DIRENT 0
#endif

#include <machine/rtems-bsd-kernel-space.h>

#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

#include <machine/rtems-bsd-libio.h>
#include <machine/rtems-bsd-syscall-api.h>
#include <machine/rtems-bsd-vfs.h>

#include <errno.h>
#include <rtems/imfs.h>
#include <rtems/libio.h>
#include <rtems/seterr.h>
#include <stdio.h>

static int rtems_bsd_sysgen_open_error(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode);
static int rtems_bsd_sysgen_opendir(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode);
static int rtems_bsd_sysgen_open(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode);
static ssize_t rtems_bsd_sysgen_read(
    rtems_libio_t *iop, void *buffer, size_t count);
static ssize_t rtems_bsd_sysgen_readv(
    rtems_libio_t *iop, const struct iovec *iov, int iovcnt, ssize_t total);
static ssize_t rtems_bsd_sysgen_write(
    rtems_libio_t *iop, const void *buffer, size_t count);
static ssize_t rtems_bsd_sysgen_writev(
    rtems_libio_t *iop, const struct iovec *iov, int iovcnt, ssize_t total);
static int rtems_bsd_sysgen_ioctl(
    rtems_libio_t *iop, ioctl_command_t request, void *buffer);
static off_t rtems_bsd_sysgen_lseek(
    rtems_libio_t *iop, off_t offset, int whence);
static int rtems_bsd_sysgen_vnstat(
    const rtems_filesystem_location_info_t *loc, struct stat *buf);
static int rtems_bsd_sysgen_fstat(
    const rtems_filesystem_location_info_t *loc, struct stat *buf);
static int rtems_bsd_sysgen_imfsfstat(
    const rtems_filesystem_location_info_t *loc, struct stat *buf);
static int rtems_bsd_sysgen_ftruncate(rtems_libio_t *iop, off_t length);
static int rtems_bsd_sysgen_fsync(rtems_libio_t *iop);
static int rtems_bsd_sysgen_fdatasync(rtems_libio_t *iop);
static int rtems_bsd_sysgen_fcntl(rtems_libio_t *iop, int cmd);
static int rtems_bsd_sysgen_poll(rtems_libio_t *iop, int events);
static int rtems_bsd_sysgen_kqfilter(rtems_libio_t *iop, struct knote *kn);

const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_dirops = {
	.open_h = rtems_bsd_sysgen_opendir,
	.close_h = rtems_bsd_sysgen_close,
	.read_h = rtems_bsd_sysgen_read,
	.write_h = rtems_filesystem_default_write,
	.ioctl_h = rtems_filesystem_default_ioctl,
	.lseek_h = rtems_filesystem_default_lseek_directory,
	.fstat_h = rtems_bsd_sysgen_vnstat,
	.ftruncate_h = rtems_filesystem_default_ftruncate_directory,
	.fsync_h = rtems_filesystem_default_fsync_or_fdatasync,
	.fdatasync_h = rtems_bsd_sysgen_fdatasync,
	.fcntl_h = rtems_filesystem_default_fcntl,
	.kqfilter_h = rtems_filesystem_default_kqfilter,
	.mmap_h = rtems_filesystem_default_mmap,
	.poll_h = rtems_filesystem_default_poll,
	.readv_h = rtems_filesystem_default_readv,
	.writev_h = rtems_filesystem_default_writev
};

const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_fileops = {
	.open_h = rtems_bsd_sysgen_open,
	.close_h = rtems_bsd_sysgen_close,
	.read_h = rtems_bsd_sysgen_read,
	.write_h = rtems_bsd_sysgen_write,
	.ioctl_h = rtems_bsd_sysgen_ioctl,
	.lseek_h = rtems_bsd_sysgen_lseek,
	.fstat_h = rtems_bsd_sysgen_vnstat,
	.ftruncate_h = rtems_bsd_sysgen_ftruncate,
	.fsync_h = rtems_filesystem_default_fsync_or_fdatasync,
	.fdatasync_h = rtems_bsd_sysgen_fdatasync,
	.fcntl_h = rtems_bsd_sysgen_fcntl,
	.kqfilter_h = rtems_bsd_sysgen_kqfilter,
	.mmap_h = rtems_filesystem_default_mmap,
	.poll_h = rtems_bsd_sysgen_poll,
	.readv_h = rtems_bsd_sysgen_readv,
	.writev_h = rtems_bsd_sysgen_writev
};

const rtems_filesystem_file_handlers_r rtems_bsd_sysgen_nodeops = {
	.open_h = rtems_bsd_sysgen_open_error,
	.close_h = rtems_bsd_sysgen_close,
	.read_h = rtems_bsd_sysgen_read,
	.write_h = rtems_bsd_sysgen_write,
	.ioctl_h = rtems_bsd_sysgen_ioctl,
	.lseek_h = rtems_filesystem_default_lseek,
	.fstat_h = rtems_bsd_sysgen_fstat,
	.ftruncate_h = rtems_filesystem_default_ftruncate,
	.fsync_h = rtems_filesystem_default_fsync_or_fdatasync,
	.fdatasync_h = rtems_filesystem_default_fsync_or_fdatasync,
	.fcntl_h = rtems_bsd_sysgen_fcntl,
	.poll_h = rtems_bsd_sysgen_poll,
	.kqfilter_h = rtems_bsd_sysgen_kqfilter,
	.readv_h = rtems_bsd_sysgen_readv,
	.writev_h = rtems_bsd_sysgen_writev,
	.mmap_h = rtems_filesystem_default_mmap
};

struct file *
rtems_bsd_iop_to_file(const rtems_libio_t *iop)
{

	if (iop->pathinfo.handlers->close_h != rtems_bsd_sysgen_close) {
		return (NULL);
	}

	return (iop->data1);
}

int
rtems_bsd_falloc(struct file **resultfp, int *resultfd)
{
	struct file *fp;
	rtems_libio_t *iop;

	fp = malloc(sizeof(*fp), M_TEMP, M_ZERO | M_NOWAIT);
	*resultfp = fp;
	if (fp == NULL) {
		return (ENOMEM);
	}

	iop = rtems_libio_allocate();
	if (iop == NULL) {
		return (ENFILE);
	}

        fp->f_io = iop;
        iop->data1 = fp;
	iop->pathinfo.node_access = iop;
	iop->pathinfo.handlers = &rtems_bsd_sysgen_nodeops;
	iop->pathinfo.mt_entry = &rtems_filesystem_null_mt_entry;
	rtems_filesystem_location_add_to_mt_entry(&iop->pathinfo);
	*resultfd = rtems_libio_iop_to_descriptor(iop);
	return (0);
}

void
rtems_bsd_fdclose(struct file *fp)
{

	rtems_libio_free(fp->f_io);
	free(fp, M_TEMP);
}

static int
rtems_bsd_sysgen_open_error(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode)
{
	return rtems_bsd_error_to_status_and_errno(ENXIO);
}

static int
rtems_bsd_sysgen_open_node(
	rtems_libio_t *iop, const char *path, int oflag, mode_t mode, bool isdir)
{
	struct thread *td = rtems_bsd_get_curthread_or_null();
	struct filedesc *fdp;
	struct file *fp;
	const bool creat = (oflag & O_CREAT) == O_CREAT;
	struct vnode *cdir;
	struct vnode *rdir;
	const char *opath;
	rtems_filesystem_location_info_t *rootloc;
	int opathlen;
	int fd;
	int error;
	struct vnode *vn;

	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: open: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}


	fp = malloc(sizeof(*fp), M_TEMP, M_ZERO | M_NOWAIT);
	if (fp == NULL) {
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}

	refcount_init(&fp->f_count, 1);
	fp->f_cred = crhold(td->td_ucred);
	fp->f_ops = &badfileops;
	fp->f_io = iop;
	iop->data1 = fp;

	fdp = td->td_proc->p_fd;

	rootloc = &iop->pathinfo.mt_entry->mt_fs_root->location;

	/*
	 * There is no easy or clean means to open a vnode and follow the
	 * POSIX open semantics. See `kern_openat`. You can open a vnode but
	 * the extra functionality such as the file pointer, descriptor,
	 * create and truncate are not part of the basic vnode open. All the
	 * calls that provide that functionality take a path as the
	 * argument. As a result find the last token in the path and use the
	 * parent directory vnode to position ourselves in the parent
	 * directory. The pathloc vnode points to the '.' or '..'  directory.
	 */
	if (rtems_bsd_libio_loc_to_vnode(&iop->pathinfo) ==
	    rtems_bsd_libio_loc_to_vnode(rootloc)) {
		opath = ".";
		opathlen = 1;
	} else {
		opath = path + strlen(path);
		opathlen = 0;
		while (opath != path && !rtems_filesystem_is_delimiter(opath[-1])) {
			opath--;
			opathlen++;
		}
	}
	if (rtems_filesystem_is_current_directory(opath, opathlen) ||
	    rtems_filesystem_is_parent_directory(opath, opathlen)) {
		if (((oflag + 1) & _FWRITE) == _FWRITE) {
			if (RTEMS_BSD_SYSCALL_TRACE) {
				printf("bsd: sys: open: write to .  or ..\n");
			}
			return rtems_bsd_error_to_status_and_errno(EPERM);
		}
		opath = ".";
		cdir = rtems_bsd_libio_loc_to_vnode(&iop->pathinfo);
	} else {
		/*
		 * We need the parent directory so open can find the
		 * entry. If we are creating the file the pathinfo
		 * vnode entry is the directory open uses to create
		 * the file in.
		 */
		cdir = rtems_bsd_libio_loc_to_vnode_dir(&iop->pathinfo);
		if (cdir == NULL || creat) {
			cdir = rtems_bsd_libio_loc_to_vnode(&iop->pathinfo);
		}
		if (fdp->fd_cdir == NULL) {
			cdir = rtems_bsd_libio_loc_to_vnode_dir(rootloc);
		}
	}

	FILEDESC_XLOCK(fdp);
	rdir = fdp->fd_cdir;
	fdp->fd_cdir = cdir;
	cdir = rdir;
	rdir = fdp->fd_rdir;
	fdp->fd_rdir = fdp->fd_cdir;
	FILEDESC_XUNLOCK(fdp);

	if (RTEMS_BSD_SYSCALL_TRACE) {
		struct vnode* _vn = rtems_bsd_libio_loc_to_vnode(&iop->pathinfo);
		struct vnode* _dvn = rtems_bsd_libio_loc_to_vnode_dir(&iop->pathinfo);
		printf("bsd: sys: open: path=%s opath=%s vn=%p (%c) dvn=%p (%c) cwd=%p"
		       " flags=%08x mode=%o isdir=%s\n",
		       path, opath,
		       _vn, creat ? 'c' : _vn ? (_vn->v_type == VDIR ? 'd' : 'r') : 'n',
		       _dvn,  _dvn ? (_dvn->v_type == VDIR ? 'd' : 'r') : 'n',
		       fdp->fd_cdir, oflag, mode, isdir ? "yes" : "no");
	}

	VREF(fdp->fd_cdir);

	error = kern_openat(td, AT_FDCWD, RTEMS_DECONST(char *, opath),
	    UIO_USERSPACE, oflag, mode, fp);

	vrele(fdp->fd_cdir);

	if (error != 0) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: open: error = (%d) %s\n", error,
			    strerror(error));
		}
		return rtems_bsd_error_to_status_and_errno(error);
	}

	fd = td->td_retval[0];

	FILEDESC_XLOCK(fdp);
	fdp->fd_cdir = cdir;
	fdp->fd_rdir = rdir;
	rtems_bsd_libio_loc_set_vnode(&iop->pathinfo, fp->f_vnode);
	FILEDESC_XUNLOCK(fdp);

        iop->pathinfo.handlers = &rtems_bsd_sysgen_fileops;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: open: fd = %d vn=%p\n", fd,
		    rtems_bsd_libio_loc_to_vnode(&iop->pathinfo));
	}

	return 0;
}

int
rtems_bsd_sysgen_opendir(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode)
{
	 return rtems_bsd_sysgen_open_node(iop, path, oflag, mode, true);
}

int
rtems_bsd_sysgen_open(
    rtems_libio_t *iop, const char *path, int oflag, mode_t mode)
{
	 return rtems_bsd_sysgen_open_node(iop, path, oflag, mode, false);
}

int
rtems_bsd_sysgen_close(rtems_libio_t *iop)
{
	struct thread *td;
	struct file *fp;
	int error;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: close: %d\n",
		    rtems_libio_iop_to_descriptor(iop));
	}

	td = rtems_bsd_get_curthread_or_null();
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: close: no curthread\n");
		}
		return (rtems_bsd_error_to_status_and_errno(ENOMEM));
	}

	fp = iop->data1;
	BSD_ASSERT(fp->f_count == 1);
	error = (fo_close(fp, td));
	if (error != 0) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: close: error = %d\n", error);
		}
		return (rtems_bsd_error_to_status_and_errno(error));
	}

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: close: success\n");
	}
	FILEDESC_XLOCK(NULL);
	knote_fdclose(td, rtems_libio_iop_to_descriptor(iop));
	FILEDESC_XUNLOCK(NULL);
	crfree(fp->f_cred);
	free(fp, M_TEMP);
	return (0);
}

ssize_t
rtems_bsd_sysgen_read(rtems_libio_t *iop, void *buffer, size_t count)
{
	struct thread *td = curthread;
	struct vnode *vp = rtems_bsd_libio_iop_to_vnode(iop);
	int fd = rtems_libio_iop_to_descriptor(iop);
	int error;
	ssize_t size = 0;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: read: %d -> %d: vn=%p vn-type=%d len=%d\n",
		   rtems_libio_iop_to_descriptor(iop), fd, vp, vp->v_type, count);
	}

	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: read: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}

	if (count > IOSIZE_MAX)
		return rtems_bsd_error_to_status_and_errno(EINVAL);

	if (vp != NULL && vp->v_type == VDIR) {
		off_t offset;
		error = kern_getdirentries(
		    td, fd, buffer, count, &iop->offset, NULL, UIO_USERSPACE);
		size = td->td_retval[0];
		if (RTEMS_BSD_CHECK_READDIR_DIRENT) {
			/*
			 * Helper code for integration of a file system. The
			 * FreeBSD kernel dirent and the newlib structs are not
			 * the same format.
			 */
			size_t offset = 0;
			int c = 0;
			printk(
			    "bsd: sys: readdir: buffer: %p count:%d: size=%d\n",
			    buffer, count, size);
			while (offset < size) {
				struct dirent *dp =
				    (struct dirent *)(((char *)buffer) +
					offset);
				printk(
				    "dirent: %3d: dp=%p off=%d rl=%-3d fn=%-6d name=%-3d '",
				    c, dp, (int)dp->d_off, (int)dp->d_reclen,
				    (int)dp->d_fileno, (int)dp->d_namlen);
				if (dp->d_namlen < sizeof(dp->d_name)) {
					for (int i = 0; i < dp->d_namlen; ++i) {
						printk("%c", dp->d_name[i]);
					}
				} else {
					printk("INVALID NAME LENGTH");
				}
				printk("'\n");
				if (dp->d_reclen <= 0) {
					break;
				}
				c++;
				offset += dp->d_reclen;
				if (offset > count) {
					printf("dirent: buffer overflow\n");
				}
			}
		}
	} else {
		struct iovec aiov = { .iov_base = buffer, .iov_len = count };
		struct uio auio = { .uio_iov = &aiov,
			.uio_iovcnt = 1,
			.uio_offset = iop->offset,
			.uio_resid = count,
			.uio_segflg = UIO_USERSPACE,
			.uio_rw = UIO_READ,
			.uio_td = td };
		error = kern_readv(
		    td, rtems_libio_iop_to_descriptor(iop), &auio);
		if (error == 0)
			size = td->td_retval[0];
	}

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: read: %d: %d: %s size=%i\n",
		    rtems_libio_iop_to_descriptor(iop), error, strerror(error),
		    size);
	}

	if (error != 0)
		return rtems_bsd_error_to_status_and_errno(error);

	return size;
}

ssize_t
rtems_bsd_sysgen_readv(
    rtems_libio_t *iop, const struct iovec *iov, int iovcnt, ssize_t total)
{
	struct thread *td = curthread;
	struct uio auio;
	int error;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: readv: %d len=%d\n",
		    rtems_libio_iop_to_descriptor(iop), total);
	}

	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: readv: readv: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}

	if (total > IOSIZE_MAX)
		return rtems_bsd_error_to_status_and_errno(EINVAL);

	auio.uio_iov = RTEMS_DECONST(struct iovec *, iov);
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = total;
	auio.uio_segflg = UIO_USERSPACE;

	error = kern_readv(td, rtems_libio_iop_to_descriptor(iop), &auio);

	if (error != 0)
		return rtems_bsd_error_to_status_and_errno(error);

	return td->td_retval[0];
}

ssize_t
rtems_bsd_sysgen_write(rtems_libio_t *iop, const void *buffer, size_t count)
{
	struct thread *td = curthread;
	struct uio auio;
	struct iovec aiov;
	int error;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: write: %d len=%d\n",
		    rtems_libio_iop_to_descriptor(iop), count);
	}

	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: write: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}

	if (count > IOSIZE_MAX)
		return (EINVAL);

	aiov.iov_base = RTEMS_DECONST(void *, buffer);
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = count;
	auio.uio_segflg = UIO_USERSPACE;

	error = kern_writev(td, rtems_libio_iop_to_descriptor(iop), &auio);

	if (error != 0)
		return rtems_bsd_error_to_status_and_errno(error);

	return td->td_retval[0];
}

ssize_t
rtems_bsd_sysgen_writev(
    rtems_libio_t *iop, const struct iovec *iov, int iovcnt, ssize_t total)
{
	struct thread *td = curthread;
	struct uio auio;
	int error;

	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: writev: %d iocnt=%d len=%d\n",
		    rtems_libio_iop_to_descriptor(iop), iovcnt, total);
	}

	if (total > IOSIZE_MAX)
		return EINVAL;

	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: writev: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}

	auio.uio_iov = RTEMS_DECONST(struct iovec *, iov);
	auio.uio_iovcnt = iovcnt;
	auio.uio_resid = total;
	auio.uio_segflg = UIO_USERSPACE;

	error = kern_writev(td, rtems_libio_iop_to_descriptor(iop), &auio);

	if (error != 0)
		return rtems_bsd_error_to_status_and_errno(error);

	return td->td_retval[0];
}

int
rtems_bsd_sysgen_ioctl(
    rtems_libio_t *iop, ioctl_command_t request, void *buffer)
{
	struct thread *td = curthread;
	u_long com = request & 0xffffffff;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: ioctl: %d req=%08x\n",
		    rtems_libio_iop_to_descriptor(iop), com);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: ioctl: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	error = kern_ioctl(
	    td, rtems_libio_iop_to_descriptor(iop), com, buffer);
	return rtems_bsd_error_to_status_and_errno(error);
}

off_t
rtems_bsd_sysgen_lseek(rtems_libio_t *iop, off_t offset, int whence)
{
	struct thread *td = curthread;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: lseek: %d offset=%zu whence=%d\n",
		    rtems_libio_iop_to_descriptor(iop), offset, whence);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: lseek: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	error = kern_lseek(
	    td, rtems_libio_iop_to_descriptor(iop), offset, whence);
	if (error != 0) {
		return rtems_bsd_error_to_status_and_errno(error);
	}
	return td->td_uretoff.tdu_off;
}

int
rtems_bsd_sysgen_vnstat(
    const rtems_filesystem_location_info_t *loc, struct stat *buf)
{
	struct thread *td = curthread;
	struct vnode *vp = rtems_bsd_libio_loc_to_vnode(loc);
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: vnstat: %p\n", vp);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: vnstat: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	if (vp == NULL)
		error = EFAULT;
	else {
		VOP_LOCK(vp, LK_SHARED);
		error = vn_stat(vp, buf, td->td_ucred, NOCRED, td);
		VOP_UNLOCK(vp, 0);
	}
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: vnstat: exit %p\n", vp);
	}
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_fstat(
    const rtems_filesystem_location_info_t *loc, struct stat *buf)
{
	struct thread *td = curthread;
	rtems_libio_t *iop = rtems_bsd_libio_loc_to_iop(loc);
	struct file *fp = NULL;
	int error;
	if (iop == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: ffile: no iop\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENXIO);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: fstat: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	fp = rtems_bsd_iop_to_file(iop);
	if (fp != NULL) {
		error = fo_stat(fp, buf, NULL, td);
	} else {
		error = EBADF;
	}
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_ftruncate(rtems_libio_t *iop, off_t length)
{
	struct thread *td = curthread;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: ftruncate: len=%d\n", length);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: ftruncate: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	error = kern_ftruncate(
	    td, rtems_libio_iop_to_descriptor(iop), length);
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_fsync(rtems_libio_t *iop)
{
	struct thread *td = curthread;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: fsync\n");
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: fsync: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	error = kern_fsync(td, rtems_libio_iop_to_descriptor(iop), true);
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_fdatasync(rtems_libio_t *iop)
{
	struct thread *td = curthread;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: fdatasync\n");
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: fdatasync: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	error = kern_fsync(td, rtems_libio_iop_to_descriptor(iop), false);
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_fcntl(rtems_libio_t *iop, int cmd)
{
	struct thread *td = curthread;
	intptr_t arg;
	int error;
	if (RTEMS_BSD_SYSCALL_TRACE) {
		printf("bsd: sys: fcntl: %d cmd=%d\n",
		    rtems_libio_iop_to_descriptor(iop), cmd);
	}
	if (td == NULL) {
		if (RTEMS_BSD_SYSCALL_TRACE) {
			printf("bsd: sys: fcntl: no curthread\n");
		}
		return rtems_bsd_error_to_status_and_errno(ENOMEM);
	}
	switch (cmd) {
	case F_SETFD:
		arg = rtems_libio_to_fcntl_flags(rtems_libio_iop_flags(iop)) &
		    FD_CLOEXEC;
		break;
	case F_SETFL:
		arg = rtems_libio_to_fcntl_flags(rtems_libio_iop_flags(iop)) &
		    FCNTLFLAGS;
		break;
	default:
		arg = -1;
		error = 0;
		break;
	}
	if (arg >= 0) {
		error = kern_fcntl(
		    td, rtems_libio_iop_to_descriptor(iop), cmd, arg);
		/* no return path with the RTEMS API for get calls */
	}
	return rtems_bsd_error_to_status_and_errno(error);
}

int
rtems_bsd_sysgen_poll(rtems_libio_t *iop, int events)
{
	struct thread *td;
	struct file *fp;

	td = rtems_bsd_get_curthread_or_null();
	if (td == NULL) {
		return (ENOMEM);
	}

	fp = iop->data1;
	return (fo_poll(fp, events, td->td_ucred, td));
}

int
rtems_bsd_sysgen_kqfilter(rtems_libio_t *iop, struct knote *kn)
{
	struct file *fp;

	fp = iop->data1;
	return (fo_kqfilter(fp, kn));
}
