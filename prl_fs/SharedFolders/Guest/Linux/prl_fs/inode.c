/*
 *   prlfs/inode.c
 *
 *   Copyright (C) Parallels Inc, 2008
 *   Author: Vasily Averin <vvs@parallels.com>
 *
 *   Parallels linux shared folders filesystem
 *
 *   Inode related functions
 */

#include <linux/module.h>
#include <linux/fs.h>
#include "prlfs.h"
#include <linux/ctype.h>

extern struct file_operations prlfs_file_fops;
extern struct file_operations prlfs_dir_fops;
extern struct inode *prlfs_iget(struct super_block *sb, ino_t ino);

struct inode *prlfs_get_inode(struct super_block *sb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
);
struct dentry_operations prlfs_dentry_ops;

unsigned long *prlfs_dfl( struct dentry *de)
{
	return (unsigned long *)&(de->d_fsdata);
}

void init_buffer_descriptor(struct buffer_descriptor *bd, void *buf,
			    unsigned long long len, int write, int user)
{
	bd->buf = buf;
	bd->len = len;
	bd->write = (write == 0) ? 0 : 1;
	bd->user = (user == 0) ? 0 : segment_eq(get_fs(), USER_DS) ? 1 : 0;
}

void *prlfs_get_path(struct dentry *dentry, void *buf, int *plen)
{
	int len;
	char *p;

	DPRINTK("ENTER\n");
	len = *plen;
	p = buf;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
	if ((dentry->d_name.len > NAME_MAX) || (len < 2)) {
		p = ERR_PTR(-ENAMETOOLONG);
		goto out;
	}
	p += --len;
	*p = '\0';
	spin_lock(&dcache_lock);
	while (!IS_ROOT(dentry)) {
		int nlen;
		struct dentry *parent;

                parent = dentry->d_parent;
		prefetch(parent);
		nlen = dentry->d_name.len;
		if (len < nlen + 1) {
			p = ERR_PTR(-ENAMETOOLONG);
			goto out_lock;
		}
		len -= nlen + 1;
		p -= nlen;
		memcpy(p, dentry->d_name.name, nlen);
		*(--p) = '/';
		dentry = parent;
	}
	if (*p != '/') {
		*(--p) = '/';
		--len;
	}
out_lock:
	spin_unlock(&dcache_lock);
	if (!IS_ERR(p))
		*plen -= len;
out:
#else
	p = dentry_path_raw(dentry, p, len);
	*plen = strnlen(p, PAGE_SIZE-1) + 1;
#endif
	DPRINTK("EXIT returning %p\n", p);
	return p;
}

#define PRLFS_STD_INODE_HEAD(d)			\
	char *buf, *p;				\
	int buflen, ret;			\
	struct super_block *sb;			\
						\
	DPRINTK("ENTER\n");			\
	buflen = PATH_MAX;			\
	buf = kmalloc(buflen, GFP_KERNEL);	\
	if (buf == NULL) {			\
		ret = -ENOMEM;			\
		goto out;			\
	}					\
	memset(buf, 0, buflen);			\
	p = prlfs_get_path((d), buf, &buflen);	\
	if (IS_ERR(p)) {			\
		ret = PTR_ERR(p);		\
		goto out_free;			\
	}					\
	sb = (d)->d_sb;

#define PRLFS_STD_INODE_TAIL			\
out_free:					\
	kfree(buf);				\
out:						\
	DPRINTK("EXIT returning %d\n", ret);	\
	return ret;

static int prlfs_inode_open(struct dentry *dentry, int mode)
{
	struct prlfs_file_info pfi;
	PRLFS_STD_INODE_HEAD(dentry)
	init_pfi(&pfi, 0, 0, mode, O_CREAT | O_RDWR);
	ret = host_request_open(sb, &pfi, p, buflen);
	PRLFS_STD_INODE_TAIL
}

static int prlfs_delete(struct dentry *dentry)
{
	PRLFS_STD_INODE_HEAD(dentry)
	ret = host_request_remove(dentry->d_sb, p, buflen);
	PRLFS_STD_INODE_TAIL
}

static int do_prlfs_getattr(struct dentry *dentry, struct prlfs_attr *attr)
{
	struct buffer_descriptor bd;
	PRLFS_STD_INODE_HEAD(dentry)
	init_buffer_descriptor(&bd, attr, PATTR_STRUCT_SIZE, 1, 0);
	ret = host_request_attr(sb, p, buflen, &bd);
	PRLFS_STD_INODE_TAIL
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define SET_INODE_TIME(t, time)	do { (t) = (time); } while (0)
#define GET_INODE_TIME(t)	(t)
static inline void i_size_write(struct inode *inode, loff_t size)
{
	inode->i_size = size;
}
#else
#define SET_INODE_TIME(t, time)	do { (t).tv_sec = (time); } while (0)
#define GET_INODE_TIME(t)	(t).tv_sec
#endif

static void prlfs_change_attributes(struct inode *inode,
				    struct prlfs_attr *attr)
{
	struct prlfs_sb_info *sbi = PRLFS_SB(inode->i_sb);

	if (attr->valid & _PATTR_SIZE)
		i_size_write(inode, attr->size);
	if (attr->valid & _PATTR_ATIME)
		SET_INODE_TIME(inode->i_atime, attr->atime);
	if (attr->valid & _PATTR_MTIME)
		SET_INODE_TIME(inode->i_mtime, attr->mtime);
	if (attr->valid & _PATTR_CTIME)
		SET_INODE_TIME(inode->i_ctime, attr->ctime);
	if (attr->valid & _PATTR_MODE)
		inode->i_mode = (inode->i_mode & S_IFMT) | (attr->mode & 0777);
	if ((attr->valid & _PATTR_UID) &&
	    (sbi->plain || sbi->share || attr->uid == -1))
		inode->i_uid = attr->uid;
	if ((attr->valid & _PATTR_GID) &&
	    (sbi->plain || sbi->share || attr->gid == -1))
		inode->i_gid = attr->gid;
	return;
}

static int attr_to_pattr(struct iattr *attr, struct prlfs_attr *pattr)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = 0;
	DPRINTK("ia_valid %x\n", attr->ia_valid);
	memset(pattr, 0, sizeof(struct prlfs_attr));
	if (attr->ia_valid & ATTR_SIZE) {
		pattr->size = attr->ia_size;
		pattr->valid |= _PATTR_SIZE;
	}
	if ((attr->ia_valid & (ATTR_ATIME | ATTR_MTIME)) ==
					(ATTR_ATIME | ATTR_MTIME)) {
		pattr->atime = GET_INODE_TIME(attr->ia_atime);
		pattr->mtime = GET_INODE_TIME(attr->ia_mtime);
		pattr->valid |= _PATTR_ATIME | _PATTR_MTIME;
	}
	if (attr->ia_valid & ATTR_CTIME) {
		pattr->ctime = GET_INODE_TIME(attr->ia_ctime);
		pattr->valid |= _PATTR_CTIME;
	}
	if (attr->ia_valid & ATTR_MODE) {
		if (attr->ia_mode & 07000) {
			ret = -EACCES;
			goto out;
		}
		pattr->mode = (attr->ia_mode & 00777);
		pattr->valid |= _PATTR_MODE;
	}
	if (attr->ia_valid & ATTR_UID) {
		pattr->uid = attr->ia_uid;
		pattr->valid = _PATTR_UID;
	}
	if (attr->ia_valid & ATTR_GID) {
		pattr->gid = attr->ia_gid;
		pattr->valid = _PATTR_GID;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_mknod(struct inode *dir, struct dentry *dentry, int mode)
{
	struct inode * inode;
	int ret;

	DPRINTK("ENTER\n");
	ret = 0;
	dentry->d_time = 0;
	inode = prlfs_get_inode(dir->i_sb, mode);
	if (inode)
		d_instantiate(dentry, inode);
         else
		ret = -ENOSPC;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_create(struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
			, bool excl
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			, struct nameidata *nd
#endif
	)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = prlfs_inode_open(dentry, mode | S_IFREG);
	if (ret == 0)
		ret = prlfs_mknod(dir, dentry, mode | S_IFREG);
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static struct dentry *prlfs_lookup(struct inode *dir, struct dentry *dentry
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
			, unsigned int flags
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			, struct nameidata *nd
#endif
	)
{
	int ret;
	struct prlfs_attr attr;
	struct inode *inode;

	DPRINTK("ENTER\n");
	DPRINTK("dir ino %lld entry name \"%s\"\n",
		 (u64)dir->i_ino, dentry->d_name.name);
	ret = do_prlfs_getattr(dentry, &attr);
	if (ret < 0 ) {
		if (ret == -ENOENT) {
			inode = NULL;
			ret = 0;
		} else
			goto out;
	} else {
		inode = prlfs_get_inode(dentry->d_sb, attr.mode);
		if (inode)
			prlfs_change_attributes(inode, &attr);
	}
	dentry->d_time = jiffies;
	d_add(dentry, inode);
	d_set_d_op(dentry, &prlfs_dentry_ops);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ERR_PTR(ret);
}

static int prlfs_unlink(struct inode *dir, struct dentry *dentry)
{
        int ret;
	unsigned long *dfl = prlfs_dfl(dentry);

	DPRINTK("ENTER\n");
	ret = prlfs_delete(dentry);
	if (!ret)
		 *dfl |= PRL_DFL_UNLINKED;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_mkdir(struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
			)
{
        int ret;

	DPRINTK("ENTER\n");
	ret = prlfs_inode_open(dentry, mode | S_IFDIR);
	if (ret == 0)
		ret = prlfs_mknod(dir, dentry, mode | S_IFDIR);
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_rmdir(struct inode *dir, struct dentry *dentry)
{
        int ret;
	unsigned long *dfl = prlfs_dfl(dentry);

	DPRINTK("ENTER\n");
	ret = prlfs_delete(dentry);
	if (!ret)
		*dfl |= PRL_DFL_UNLINKED;
	DPRINTK("EXIT returning %d\n", ret);
        return ret;
}

static int prlfs_rename(struct inode *old_dir, struct dentry *old_de,
			struct inode *new_dir, struct dentry *new_de)
{
	void *np, *nbuf;
	int nbuflen;
	PRLFS_STD_INODE_HEAD(old_de)
	nbuflen = PATH_MAX;
	nbuf = kmalloc(nbuflen, GFP_KERNEL);
	if (nbuf == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}
	memset(nbuf, 0, nbuflen);
	np = prlfs_get_path(new_de, nbuf, &nbuflen);
	if (IS_ERR(np)) {
		ret = PTR_ERR(np);
		goto out_free1;
	}
	ret = host_request_rename(sb, p, buflen, np, nbuflen);
	old_de->d_time = 0;
	new_de->d_time = 0;
out_free1:
	kfree(nbuf);
	PRLFS_STD_INODE_TAIL
}

/*
 * FIXME: Move fs specific data to inode.
 * Current implementation used full path to as a reference to opened file.
 * So {set,get}attr result access to another not unlinked file with the same
 * path.
 */
static int check_dentry(struct dentry *dentry)
{
	return *prlfs_dfl(dentry) & PRL_DFL_UNLINKED;
}

static int prlfs_inode_setattr(struct inode *inode, struct iattr *attr)
{
	int ret = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	ret = inode_setattr(inode, attr);
#else
	if ((attr->ia_valid & ATTR_SIZE &&
			attr->ia_size != i_size_read(inode))) {
		ret = inode_newsize_ok(inode, attr->ia_size);
		if (ret)
			goto out;
		truncate_setsize(inode, attr->ia_size);
	}
	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
out:
#endif
	return ret;
}

static int prlfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct prlfs_attr pattr;
	struct buffer_descriptor bd;
	PRLFS_STD_INODE_HEAD(dentry)
	ret = attr_to_pattr(attr, &pattr);
	if (ret < 0)
		goto out_free;

	if (check_dentry(dentry)) {
		ret = - ESTALE;
		goto out_free;
	}
	init_buffer_descriptor(&bd, &pattr, PATTR_STRUCT_SIZE, 0, 0);
	ret = host_request_attr(sb, p, buflen, &bd);
	if (ret == 0)
		ret = prlfs_inode_setattr(dentry->d_inode, attr);
	dentry->d_time = 0;
	PRLFS_STD_INODE_TAIL
}

static int prlfs_i_revalidate(struct dentry *dentry)
{
	struct prlfs_attr attr;
	struct inode *inode;
	int ret;

	DPRINTK("ENTER\n");
	if (!dentry || !dentry->d_inode) {
		ret = -ENOENT;
		goto out;
	}
	if (dentry->d_time != 0 &&
	    jiffies - dentry->d_time < PRLFS_SB(dentry->d_sb)->ttl) {
		ret = 0;
		goto out;
	}
	inode = dentry->d_inode;
	ret = do_prlfs_getattr(dentry, &attr);
	if (ret < 0)
		goto out;

	if ((inode->i_mode ^ attr.mode) & S_IFMT) {
		DPRINTK("inode <%p> i_mode %x attr.mode %x\n", inode, inode->i_mode, attr.mode);
		make_bad_inode(inode);
		ret = -EIO;
	} else {
		prlfs_change_attributes(inode, &attr);
	}
	dentry->d_time = jiffies;
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_d_revalidate(struct dentry *dentry,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
					int flags
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
					struct nameidata *nd
#else
					unsigned int flags
#endif
	)
{
	int ret;

	DPRINTK("ENTER\n");
	ret = (prlfs_i_revalidate(dentry) == 0) ? 1 : 0;
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

struct dentry_operations prlfs_dentry_ops = {
	.d_revalidate = prlfs_d_revalidate,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int prlfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
						 struct kstat *stat)
{
	int ret;
	DPRINTK("ENTER\n");
	if (check_dentry(dentry)) {
		ret = - ESTALE;
		goto out;
	}

	ret = prlfs_i_revalidate(dentry);
	if (ret < 0)
		goto out;

	generic_fillattr(dentry->d_inode, stat);
	if (PRLFS_SB(dentry->d_sb)->share) {
		if (stat->uid != -1)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
			stat->uid = current->fsuid;
#else
			stat->uid = current->cred->fsuid;
#endif
		if (stat->gid != -1)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
			stat->gid = current->fsgid;
#else
			stat->gid = current->cred->fsgid;
#endif
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,40)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
/* Fedora 15 uses 2.6.4x kernel version enumeration instead of 3.x */
#define MINOR_3X_LINUX_VERSION	LINUX_VERSION_CODE - KERNEL_VERSION(2,6,40)
#define REAL_LINUX_VERSION_CODE	KERNEL_VERSION(3,MINOR_3X_LINUX_VERSION,0)
#else
#define REAL_LINUX_VERSION_CODE	LINUX_VERSION_CODE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
/* 2.4.x */
static int prlfs_permission(struct inode *inode, int mask)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* 2.6.0 ... 2.6.26 */
static int prlfs_permission(struct inode *inode, int mask, struct nameidata *nd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
/* 2.6.27 ... 2.6.37 */
static int prlfs_permission(struct inode *inode, int mask)
#elif REAL_LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
/* 2.6.38 ... 3.0 */
static int prlfs_permission(struct inode *inode, int mask, unsigned int flags)
#define PERMISSION_PRECHECK	(flags & IPERM_FLAG_RCU)
#else
/* 3.1 ... ? */
static int prlfs_permission(struct inode *inode, int mask)
#define PERMISSION_PRECHECK	(mask & MAY_NOT_BLOCK)
#endif
{
	int isdir, mode;

	DPRINTK("ENTER\n");
#ifdef PERMISSION_PRECHECK
	if (PERMISSION_PRECHECK)
		return -ECHILD;
#endif
	mode = inode->i_mode;
	isdir = S_ISDIR(mode);

	if (inode->i_uid != -1)
		mode = mode >> 6;
	else if (inode->i_gid != -1)
		mode = mode >> 3;
	mode &= 0007;
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;

	DPRINTK("mask 0x%x mode %o\n", mask, mode);

	if ((mask & ~mode) == 0)
		return 0;

	if (!(mask & MAY_EXEC) || (isdir || (mode & S_IXUGO)))
		if (capable(CAP_DAC_OVERRIDE))
			return 0;

	 if (mask == MAY_READ || (isdir && !(mask & MAY_WRITE)))
		if (capable(CAP_DAC_READ_SEARCH))
			return 0;

	DPRINTK("EXIT returning EACCES\n");
	return -EACCES;
}




struct inode_operations prlfs_file_iops = {
	.setattr	= prlfs_setattr,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
};

struct inode_operations prlfs_share_file_iops = {
	.setattr	= prlfs_setattr,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
	.permission	= prlfs_permission,
};

struct inode_operations prlfs_dir_iops = {
	.create		= prlfs_create,
	.lookup		= prlfs_lookup,
	.unlink		= prlfs_unlink,
	.mkdir		= prlfs_mkdir,
	.rmdir		= prlfs_rmdir,
	.rename		= prlfs_rename,
	.setattr	= prlfs_setattr,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
};

struct inode_operations prlfs_share_dir_iops = {
	.create		= prlfs_create,
	.lookup		= prlfs_lookup,
	.unlink		= prlfs_unlink,
	.mkdir		= prlfs_mkdir,
	.rmdir		= prlfs_rmdir,
	.rename		= prlfs_rename,
	.setattr	= prlfs_setattr,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	.revalidate	= prlfs_i_revalidate,
#else
        .getattr	= prlfs_getattr,
#endif
	.permission	= prlfs_permission,
};

static int prlfs_root_revalidate(struct dentry *dentry,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
					int flags
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
					struct nameidata *nd
#else
					unsigned int flags
#endif
	)
{
	return 1;
}

struct dentry_operations prlfs_root_dops = {
	.d_revalidate = prlfs_root_revalidate,
};

static struct dentry *prlfs_root_lookup(struct inode *dir,
					struct dentry *dentry
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					, struct nameidata *nd
#endif
	)
{
	struct prlfs_sf_parameters psp;
	struct prlfs_sf_response *prsp;
	int ret;
	void *p;
	struct super_block *sb;
	struct inode *inode;
	struct prlfs_attr attr;

	DPRINTK("ENTER\n");
	DPRINTK("dir ino %lld entry name \"%s\"\n",
		 (u64)dir->i_ino, dentry->d_name.name);

	p = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (p == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(p, 0, PAGE_SIZE);
	memset(&psp, 0, sizeof(struct prlfs_sf_parameters));
	psp.id = GET_SF_ID_BY_NAME;
	sb = dentry->d_sb;
	strncpy((char *)&psp.locale, PRLFS_SB(sb)->nls, LOCALE_NAME_LEN - 1);
	prsp = p;
	inode = NULL;
	strncpy (prsp->buf, dentry->d_name.name, dentry->d_name.len);
	ret = host_request_sf_param(PRLFS_SB(sb)->pdev, p, PAGE_SIZE, &psp);
	if (ret < 0) {
		ret = 0;
		kfree(p);
		goto out;
	}
	if (do_prlfs_getattr(dentry, &attr) < 0)
		inode = prlfs_get_inode(sb, S_IFDIR | S_IRUGO | S_IXUGO);
	else {
		inode = prlfs_get_inode(sb, attr.mode);
		if (inode)
			prlfs_change_attributes(inode, &attr);
	}
	kfree(p);
	d_set_d_op(dentry, &prlfs_root_dops);
	dentry->d_time = jiffies;
	d_add(dentry, inode);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ERR_PTR(ret);
}

struct inode_operations prlfs_root_iops = {
	.lookup		= prlfs_root_lookup,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define SET_INODE_INO(inode) do { } while (0)
#else
#define SET_INODE_INO(inode) do { (inode)->i_ino = get_next_ino(); } while (0)
#endif

struct inode *prlfs_get_inode(struct super_block *sb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
			umode_t mode
#else
			int mode
#endif
			)
{
	struct inode * inode;

	DPRINTK("ENTER\n");
	inode = new_inode(sb);
	if (inode) {
		inode->i_mode = mode;
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		inode->i_uid = PRLFS_SB(sb)->uid;
		inode->i_gid = PRLFS_SB(sb)->gid;
		SET_INODE_INO(inode);
		switch (mode & S_IFMT) {
		case S_IFDIR:
			if (PRLFS_SB(sb)->share)
				inode->i_op = &prlfs_share_dir_iops;
			else
				inode->i_op = &prlfs_dir_iops;
			inode->i_fop = &prlfs_dir_fops;
			break;
		case 0: case S_IFREG:
			if (PRLFS_SB(sb)->share)
				inode->i_op = &prlfs_share_file_iops;
			else
				inode->i_op = &prlfs_file_iops;
			inode->i_fop =  &prlfs_file_fops;
			break;
		}
	}
	DPRINTK("EXIT returning %p\n", inode);
	return inode;
}
