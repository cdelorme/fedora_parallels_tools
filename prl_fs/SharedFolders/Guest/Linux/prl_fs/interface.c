/*
 *	prlfs/interface.c
 *
 *	Copyright (C) Parallels Inc, 2008
 *	Author: Vasily Averin <vvs@parallels.com>
 *
 *	Parallels Linux shared folders filesystem
 *
 *	pci toolgate interface functions
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include "prlfs.h"

struct status_table{
	unsigned tg;
	int error;
};
/* toolgate <=> linux error codes matrix */
struct status_table linux_err_tbl[] = {
	{TG_STATUS_SUCCESS,			0},
	{TG_STATUS_PENDING,			EAGAIN},
	{TG_STATUS_CANCELLED,			ERESTARTSYS},
	{TG_STATUS_MALFORMED_REQUEST,		EINVAL},
	{TG_STATUS_INVALID_REQUEST,		EINVAL},
	{TG_STATUS_INVALID_PARAMETER,		EINVAL},
	{TG_STATUS_NO_MEMORY,			ENOMEM},
	{TG_STATUS_NO_RESOURCES,		ENOMEM},
	{TG_STATUS_ACCESS_VIOLATION,		EACCES},
	{TG_STATUS_ACCESS_DENIED,		EPERM},
	{TG_STATUS_BAD_NETWORK_NAME,		EBADF},
	{TG_STATUS_BUFFER_TOO_SMALL,		EINVAL},
	{TG_STATUS_CANNOT_DELETE,		EPERM},
	{TG_STATUS_DIRECTORY_NOT_EMPTY,		ENOTEMPTY},
	{TG_STATUS_DISK_FULL,			ENOSPC},
	{TG_STATUS_EAS_NOT_SUPPORTED,		ENOTSUPP},
	{TG_STATUS_END_OF_FILE,			EINVAL},
	{TG_STATUS_FILE_DELETED,		ENOENT},
	{TG_STATUS_FILE_IS_A_DIRECTORY,		EISDIR},
	{TG_STATUS_INSUFFICIENT_RESOURCES,	ENOMEM},
	{TG_STATUS_INVALID_HANDLE,		EINVAL},
	{TG_STATUS_NO_MORE_FILES,		ENOENT},
	{TG_STATUS_NO_SUCH_FILE,		ENOENT},
	{TG_STATUS_NOT_A_DIRECTORY,		ENOTDIR},
	{TG_STATUS_NOT_IMPLEMENTED,		ENOTSUPP},
	{TG_STATUS_OBJECT_NAME_COLLISION,	ESTALE},
	{TG_STATUS_OBJECT_NAME_INVALID,		EINVAL},
	{TG_STATUS_OBJECT_NAME_NOT_FOUND,	ENOENT},
	{TG_STATUS_OBJECT_PATH_NOT_FOUND,	ENOENT},
	{TG_STATUS_TOO_MANY_OPENED_FILES,	EMFILE},
	{TG_STATUS_UNSUCCESSFUL,		ENOMEM},
	{TG_STATUS_TOOL_NOT_READY,		ENOMEM},
	{TG_STATUS_REQUEST_ALREADY_EXISTS,	EINVAL},
	{TG_STATUS_INCOMPATIBLE_VERSION,	ENODEV},
	{TG_STATUS_SUSPENDED,			ENODEV},
	{TG_STATUS_NOT_HANDLED,			EINTR},
	{TG_STATUS_STALE_HANDLE,		ESTALE},
	{TG_STATUS_NOT_SAME_DEVICE,		EXDEV},
};

static int TG_ERR(unsigned status)
{
	static const int sz = sizeof(linux_err_tbl)/sizeof(struct status_table);
	int i;
	for (i = 0; i < sz; i++)
		if (status == linux_err_tbl[i].tg)
			return linux_err_tbl[i].error;
	DPRINTK("prlfs:WARN unknown error status = %d\n", status);
	return -EINVAL;
}

static void init_req_desc(TG_REQ_DESC *sdesc, TG_REQUEST *src,
			  void *idata, TG_BUFFER *sbuf)
{
	sdesc->src = src;
	sdesc->idata = idata;
	sdesc->sbuf = sbuf;
}

static void init_tg_request(TG_REQUEST *src, unsigned request,
		unsigned short isize, unsigned short bnum)
{
	src->Request = request;
	src->InlineByteCount = isize;
	src->BufferCount = bnum;
}

static void init_tg_buffer(TG_BUFFER *sbuf, void *buffer, size_t size,
							 int write, int user)
{
	sbuf->u.Buffer = buffer;
	sbuf->ByteCount = size;
	sbuf->Writable = (write == 0) ? 0 : 1;
	sbuf->Userspace = (user == 0) ? 0 : 1;
}

int host_request_get_sf_list(struct pci_dev *pdev, void *data, int size)
{
	int blen, ret;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;

	memset(&Req, 0, sizeof(Req));
	blen = sizeof(struct prlfs_sf_parameters);
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_GETSFLIST, 0, 1);
	init_tg_buffer(&Req.Buffer, data, size, 1, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_sf_param(struct pci_dev *pdev, void *data, int size,
					 struct prlfs_sf_parameters *psp)
{
	int blen, ret;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	blen = sizeof(struct prlfs_sf_parameters);
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_GETSFPARM, 0, 2);
	init_tg_buffer(&Req.Buffer[0], (void *)psp, blen, 1, 0);
	init_tg_buffer(&Req.Buffer[1], data, size, 1, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_attr(struct super_block *sb, const char *path, int psize,
						 struct buffer_descriptor *bd)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_ATTR, 0, 2);
	init_tg_buffer(&Req.Buffer[0], (void *)path, psize, 0, 0);
	init_tg_buffer(&Req.Buffer[1], bd->buf, bd->len, bd->write, bd->user);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);
	return ret;
}

int host_request_open(struct super_block *sb, struct prlfs_file_info *pfi,
			const char *p, int plen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;
	prlfs_file_info_to_desc(&pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_OPEN, 0, 2);
	init_tg_buffer(&Req.Buffer[0], (void *)p, plen, 0, 0);
	init_tg_buffer(&Req.Buffer[1], (void *)&pfd, PFD_LEN, 1, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	prlfs_file_desc_to_info(pfi, &pfd);
	return ret;
}

int host_request_release(struct super_block *sb, struct prlfs_file_info *pfi)
{
	int ret;
	int retry = 1000;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;
retry:
	prlfs_file_info_to_desc(&pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RELEASE, 0, 1);
	init_tg_buffer(&Req.Buffer, (void *)&pfd, PFD_LEN, 0, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS)) {
		if (Req.Req.Status == TG_STATUS_CANCELLED) {
			ret = -ERESTARTSYS;
			if (retry-- > 0)
				goto retry;
		} else {
			ret = -TG_ERR(Req.Req.Status);
		}
	}
	return ret;
}

int host_request_readdir(struct super_block *sb, struct prlfs_file_info *pfi,
			 void *buf, int *buflen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	prlfs_file_info_to_desc(&pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_READDIR, 0, 2);
	init_tg_buffer(&Req.Buffer[0], (void *)&pfd, PFD_LEN, 1, 0);
	init_tg_buffer(&Req.Buffer[1], buf, *buflen, 1, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if (ret == 0) {
		if (Req.Req.Status == TG_STATUS_SUCCESS)
			*buflen = Req.Buffer[1].ByteCount;
		else
			ret = -TG_ERR(Req.Req.Status);
	}
	prlfs_file_desc_to_info(pfi, &pfd);
	return ret;
}

int host_request_rw(struct super_block *sb, struct prlfs_file_info *pfi,
						 struct buffer_descriptor *bd)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct prlfs_file_desc pfd;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	prlfs_file_info_to_desc(&pfd, pfi);
	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RW, 0, 2);
	init_tg_buffer(&Req.Buffer[0], (void *)&pfd, PFD_LEN, 0, 0);
	init_tg_buffer(&Req.Buffer[1], bd->buf, bd->len, bd->write, bd->user);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if (ret == 0) {
		if (Req.Req.Status == TG_STATUS_SUCCESS)
			bd->len = Req.Buffer[1].ByteCount;
		else
			ret = -TG_ERR(Req.Req.Status);
	}
	return ret;
}

int host_request_remove(struct super_block *sb, void *buf, int buflen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer;
	} Req;

	memset (&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_REMOVE, 0, 1);
	init_tg_buffer(&Req.Buffer, buf, buflen, 0, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	return ret;
}

int host_request_rename(struct super_block *sb, void *buf, size_t buflen,
				void *nbuf, size_t nlen)
{
	int ret;
	struct pci_dev *pdev;
	TG_REQ_DESC sdesc;
	struct {
		TG_REQUEST Req;
		TG_BUFFER Buffer[2];
	} Req;

	memset(&Req, 0, sizeof(Req));
	init_tg_request(&Req.Req, TG_REQUEST_FS_L_RENAME, 0, 2);
	init_tg_buffer(&Req.Buffer[0], buf, buflen, 0, 0);
	init_tg_buffer(&Req.Buffer[1], nbuf, nlen, 0, 0);
	init_req_desc(&sdesc, &Req.Req, NULL, &Req.Buffer[0]);
	pdev = PRLFS_SB(sb)->pdev;
	ret = call_tg_sync(pdev, &sdesc);
	if ((ret == 0) && (Req.Req.Status != TG_STATUS_SUCCESS))
		ret = -TG_ERR(Req.Req.Status);

	return ret;
}
