/*
 *   prlfs/file.c
 *
 *   Copyright (C) Parallels Inc, 2008
 *   Author: Vasily Averin <vvs@parallels.com>
 *
 *   Parallels Linux shared folders filesystem
 *
 *   File related functions and definitions
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include "prlfs.h"

static int prlfs_open(struct inode *inode, struct file *filp)
{
	char *buf, *p;
	int buflen, ret;
	struct super_block *sb = inode->i_sb;
	struct dentry *dentry = filp->f_dentry;
	struct prlfs_file_info pfi;
	struct prlfs_fd *pfd;

	DPRINTK("ENTER\n");
	init_pfi(&pfi, 0, 0, 0, filp->f_flags);
	buflen = PATH_MAX;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf, 0, buflen);
	p = prlfs_get_path(dentry, buf, &buflen);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out_free;
	}
	pfd = kmalloc(sizeof(struct prlfs_fd), GFP_KERNEL);
	if (pfd == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}
	memset(pfd, 0, sizeof(struct prlfs_fd));
	DPRINTK("file %s\n", p);
	DPRINTK("flags %x\n", pfi.flags);
	ret = host_request_open(sb, &pfi, p, buflen);
	if (ret < 0)
		kfree(pfd);
	else {
		pfd->fd = pfi.fd;
		pfd->sfid = pfi.sfid;
		filp->private_data = pfd;
	}
	dentry->d_time = 0;
out_free:
	kfree(buf);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_release(struct inode *inode, struct file *filp)
{
	struct super_block *sb = inode->i_sb;
	struct prlfs_file_info pfi;
	int ret;

	DPRINTK("ENTER\n");
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid, 0, 0);
	ret = host_request_release(sb, &pfi);
	if (ret < 0)
		printk(KERN_ERR "prlfs_release returns error (%d)\n", ret);
	kfree(filp->private_data);
	filp->private_data = NULL;
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static unsigned char prlfs_filetype_table[PRLFS_FILE_TYPE_MAX] = {
	DT_UNKNOWN,
	DT_REG,
	DT_DIR,
	DT_LNK,
};

static int prlfs_fill_dir(struct file *filp, void *dirent, filldir_t filldir,
					loff_t *pos, void *buf, int buflen)
{
	struct super_block *sb;
	prlfs_dirent *de;
	int offset, ret, err, name_len, rec_len;
	u64 ino;
	u8 type;

	DPRINTK("ENTER\n");
	assert(filp->f_dentry);
	assert(filp->f_dentry->d_sb);
	sb = filp->f_dentry->d_sb;
	offset = 0;
	ret = 0;

	while (1) {
		de = (prlfs_dirent *)(buf + offset);
		if (offset + sizeof(prlfs_dirent) > buflen)
			goto out;

		name_len = de->name_len;
		if (name_len == 0)
			goto out;

		rec_len = PRLFS_DIR_REC_LEN(name_len);
		if (rec_len + offset > buflen) {
			printk(PFX "invalid rec_len %d "
			       "(name_len %d offset %d buflen %d)\n",
				rec_len, name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		if (de->name[name_len] != 0) {
			printk(PFX "invalid file name "
			       "(name_len %d offset %d buflen %d)\n",
				name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		type = de->file_type;
		if (type >= PRLFS_FILE_TYPE_MAX) {
			printk(PFX "invalid file type: %x, "
				"use UNKNOWN type instead "
				"(name_len %d offset %d buflen %d)\n",
				type, name_len, offset, buflen);
			type = PRLFS_FILE_TYPE_UNKNOWN;
		}
		type = prlfs_filetype_table[type];
		ino = iunique(sb, PRLFS_GOOD_INO);
		DPRINTK("filldir: name %s len %d, offset %lld, "
						"de->type %d -> type %d\n",
			 de->name, name_len, (*pos), de->file_type, type);
		err = filldir(dirent, de->name, name_len, (*pos), ino, type);
		if (err < 0)
			goto out;

		offset += rec_len;
		(*pos)++;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct prlfs_file_info pfi;
	struct super_block *sb;
	int ret, len, buflen;
	void *buf;
	off_t prev_offset;

	DPRINTK("ENTER\n");
	ret = 0;
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid, filp->f_pos, 0);
	assert(filp->f_dentry);
	assert(filp->f_dentry->d_sb);
	sb = filp->f_dentry->d_sb;
	buflen = PAGE_SIZE;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	while (pfi.flags == 0) {
		len = buflen;
		memset(buf, 0, len);
		ret = host_request_readdir(sb, &pfi, buf, &len);
		if (ret < 0)
			break;

		prev_offset = pfi.offset;
		ret = prlfs_fill_dir(filp, dirent, filldir,
					&pfi.offset, buf, len);
		if (ret < 0)
			break;
		if (pfi.offset == prev_offset)
			break;
	}
	kfree(buf);
	filp->f_pos = pfi.offset;
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static ssize_t prlfs_rw(struct file *filp, char *buf, size_t size,
			loff_t *off, unsigned int rw, int user)
{
	ssize_t ret;
	struct dentry *dentry;
	struct super_block *sb;
	struct prlfs_file_info pfi;
	struct buffer_descriptor bd;

	DPRINTK("ENTER\n");
	if (rw >= 2) {
		printk(PFX "Incorrect rw operation %d\n", rw);
		BUG();
	}
	ret = 0;
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid, *off, rw);
	dentry = filp->f_dentry;

	if (size == 0)
		goto out;

	sb = dentry->d_sb;
	init_buffer_descriptor(&bd, buf, size,(rw == 0) ? 1 : 0,
						(user == 0) ? 0 : 1);
	ret = host_request_rw(sb, &pfi, &bd);
	if (ret < 0)
		goto out;

	size = bd.len;
	(*off) += size;
	ret = size;
out:
	DPRINTK("EXIT returning %lld\n", (long long)ret);
	return ret;
}

static ssize_t prlfs_read(struct file *filp, char *buf, size_t size,
								loff_t *off)
{
	return prlfs_rw(filp, buf, size, off, 0, 1);
}

static ssize_t prlfs_write(struct file *filp, const char *buf, size_t size,
								 loff_t *off)
{
	ssize_t ret;
	struct dentry *dentry = filp->f_dentry;
	struct inode *inode = dentry->d_inode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	mutex_lock(&inode->i_mutex);
#else
	down(&inode->i_sem);
#endif
	ret = prlfs_rw(filp, (char *)buf, size, off, 1, 1);
	dentry->d_time = 0;
	if (ret < 0)
		goto out;

	if (inode->i_size < *off)
		inode->i_size = *off;
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	mutex_unlock(&inode->i_mutex);
#else
	up(&inode->i_sem);
#endif
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define SET_PAGE(a)
#define SET_FAULT(a)	do {	\
	retval = a;		\
} while (0)
#else
#define SET_PAGE(a) do {	\
	page = a;		\
} while (0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define SET_FAULT(a)	do {	\
	if (type)		\
		*type = (a);	\
} while (0)
#else
#define SET_FAULT(a)
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
static int prlfs_fault (struct vm_area_struct *vma, struct vm_fault *vmf)
#else
static struct page *prlfs_nopage(struct vm_area_struct *vma,
				 unsigned long address,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
				 int *type
#else
				 int unused
#endif
	)
#endif
{
	struct page *page;
	loff_t off;
	char *buf;
	size_t ret, size = PAGE_SIZE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	int retval;
#endif

	DPRINTK("ENTER\n");
	if (!vma->vm_file) {
		SET_FAULT(VM_FAULT_SIGBUS);
		SET_PAGE(NOPAGE_SIGBUS);
		goto out;
	}
	page = alloc_page(GFP_KERNEL);
	if (!page) {
		SET_FAULT(VM_FAULT_OOM);
		SET_PAGE(NOPAGE_OOM);
		goto out;
	}
	buf = kmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	off = vmf->pgoff << PAGE_SHIFT;
#else
	off = (address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
#endif

	ret = prlfs_rw(vma->vm_file, buf, size, &off, 0, 0);
	if (ret < 0) {
		kunmap(page);
		put_page(page);
		SET_FAULT(VM_FAULT_SIGBUS);
		SET_PAGE(NOPAGE_SIGBUS);
		goto out;
	}
	if (ret < size)
		memset (buf + ret, 0, size - ret);
	flush_dcache_page(page);
	kunmap(page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	retval = 0;
	vmf->page = page;
#else
	SET_FAULT(VM_FAULT_MAJOR);
#endif
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	DPRINTK("EXIT returning %ld\n", retval);
	return retval;
#else
	DPRINTK("EXIT returning %ld\n", PTR_ERR(page));
	return page;
#endif
}

static struct vm_operations_struct prlfs_vm_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	.fault	= prlfs_fault
#else
	.nopage	= prlfs_nopage
#endif
};

static int prlfs_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	DPRINTK("ENTER\n");
	/* currently prlfs do not implement ->writepage */
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE)) {
		ret = -EINVAL;
		goto out;
	}
	vma->vm_ops = &prlfs_vm_ops;
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#ifdef PRL_SIMPLE_SYNC_FILE
int simple_sync_file(struct file *filp, struct dentry *dentry, int datasync)
{
	return 0;
}
#endif
#endif

struct file_operations prlfs_file_fops = {
	.open		= prlfs_open,
	.read           = prlfs_read,
	.write		= prlfs_write,
	.llseek         = generic_file_llseek,
	.release	= prlfs_release,
	.mmap		= prlfs_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	.fsync		= noop_fsync,
#else
	.fsync		= simple_sync_file,
#endif
};

struct file_operations prlfs_dir_fops = {
	.open		= prlfs_open,
	.readdir	= prlfs_readdir,
	.release	= prlfs_release,
	.read		= generic_read_dir,
};

static int prlfs_root_readdir(struct file *filp, void *dirent,
							 filldir_t filldir)
{
	struct super_block *sb;
	struct inode* inode;
	int ret, buflen;
	int sfnum, *sflist;
	void *buf;
	off_t nr;

	DPRINTK("ENTER\n");
	ret = 0;
	nr = filp->f_pos;
	inode = filp->f_dentry->d_inode;

	switch(nr)
	{
	case 0:
		if (filldir(dirent, ".", 1, nr, inode->i_ino, DT_DIR) < 0)
			goto out;
		nr++;
	case 1:
		if (filldir(dirent, "..", 2, nr, inode->i_ino, DT_DIR) < 0)
			goto out;
		nr++;
	default:
		break;
	}
	buflen = PAGE_SIZE;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf, 0, buflen);
	sb = inode->i_sb;
	ret = host_request_get_sf_list(PRLFS_SB(sb)->pdev, buf, buflen);
	if (ret < 0)
		goto out_free;

	sflist = (unsigned int *)buf;
	sfnum = *sflist;
	if ((sfnum == 0) || ((nr - 1) > sfnum))
		goto out_free;

	if (sfnum >= (buflen / sizeof(int)) - 1) {
		ret = -EINVAL;
		goto out_free;
	}
	sflist += nr - 1;
	while ((nr - 1) <= sfnum) {
		struct prlfs_sf_parameters psp;
		struct prlfs_sf_response *prsp;
		void *p;
		int len, out;
		u64 ino;

		out = 0;
		p = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (p == NULL)
			goto skip;
		memset(p, 0, PAGE_SIZE);
		memset(&psp, 0, sizeof(struct prlfs_sf_parameters));
		psp.index = *(unsigned int *)sflist;
		psp.id = GET_SF_INFO;
		strncpy((char *)&psp.locale, PRLFS_SB(sb)->nls,
						 LOCALE_NAME_LEN - 1);
		out = host_request_sf_param(PRLFS_SB(sb)->pdev, p,
						 PAGE_SIZE, &psp);
		if (out < 0)
			goto skip_free;

		prsp = p;
		if (prsp->ret == 0)
			goto skip_free;

		*((char *)prsp + PAGE_SIZE - 1) = 0;
		len = strlen(prsp->buf);
		ino = iunique(sb, PRLFS_GOOD_INO);
		out = filldir(dirent, prsp->buf, len, nr, ino, DT_DIR);
	skip_free:
		kfree(p);
		if (out < 0)
			break;
	skip:
		nr++;
		sflist++;
	}
out_free:
	kfree(buf);
out:
	filp->f_pos = nr;
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}
struct file_operations prlfs_root_fops = {
	.readdir	= prlfs_root_readdir,
	.read		= generic_read_dir,
};
