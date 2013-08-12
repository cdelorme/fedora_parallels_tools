/*
 * Copyright (C) 2008 Parallels Inc. All Rights Reserved.
 * Parallels linux shared folders filesystem definitions
 */

#ifndef __PRL_FS_H__
#define __PRL_FS_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/param.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>

#include "SharedFolders/Interfaces/sf_lin.h"
#include "Toolgate/Interfaces/Tg.h"
#include "Toolgate/Guest/Linux/Interfaces/prltg_call.h"

#define PRLFS_MAGIC	0x7C7C6673 /* "||fs" */

struct prlfs_sb_info {
	struct	pci_dev *pdev;
	unsigned sfid;
	unsigned ttl;
	uid_t uid;
	gid_t gid;
	int readonly;
	int share;
	int plain;
	char nls[LOCALE_NAME_LEN];
};

struct prlfs_fd {
	unsigned long long	fd;
	unsigned int		sfid;
};

#define PFD(a)	((struct prlfs_fd *)(a)->private_data)

static inline void init_pfi(struct prlfs_file_info *pfi, unsigned long long fd,
				unsigned int sfid, unsigned long long offset,
				unsigned int flags)
{
	pfi->fd = fd;
	pfi->sfid = sfid;
	pfi->offset = offset;
	pfi->flags = flags;
}

struct buffer_descriptor {
	void *buf;
	unsigned long long len;
	int write;
	int user;
};

void init_buffer_descriptor(struct buffer_descriptor *bd, void *buf,
			    unsigned long long len, int write, int user);

void *prlfs_get_path(struct dentry *dentry, void *buf, int *plen);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define	PRLFS_ALLOC_SB_INFO(sb) \
do {				\
	sb->s_fs_info = kmalloc(sizeof(struct prlfs_sb_info), GFP_KERNEL); \
} while (0)

static inline struct prlfs_sb_info * PRLFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
#else
#define PRLFS_ALLOC_SB_INFO(sb) \
do {				\
	sb->u.generic_sbp = kmalloc(sizeof(struct prlfs_sb_info), GFP_KERNEL);\
} while (0)
static inline struct prlfs_sb_info * PRLFS_SB(struct super_block *sb)
{
	return (struct prlfs_sb_info *)(sb->u.generic_sbp);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define d_set_d_op(_dentry, _d_op)	do { _dentry->d_op = _d_op; } while (0)
#endif

int host_request_get_sf_list(struct pci_dev *pdev, void *data, int size);
int host_request_sf_param(struct pci_dev *pdev, void *data, int size,
					 struct prlfs_sf_parameters *psp);
int host_request_attr (struct super_block *sb, const char *path, int psize,
						struct buffer_descriptor *bd);
int host_request_mount(struct super_block *sb,
				 struct prlfs_sf_parameters *psp);
int host_request_open(struct super_block *sb, struct prlfs_file_info *pfi,
						const char *p, int plen);
int host_request_release(struct super_block *sb, struct prlfs_file_info *pfi);
int host_request_readdir(struct super_block *sb, struct prlfs_file_info *pfi,
						 void *buf, int *buflen);
int host_request_rw(struct super_block *sb, struct prlfs_file_info *pfi,
						 struct buffer_descriptor *bd);
int host_request_remove(struct super_block *sb, void *buf, int buflen);
int host_request_rename(struct super_block *sb, void *buf, size_t buflen,
				void *nbuf, size_t nlen);

/* define to 1 to enable copious debugging info */
#undef DRV_DEBUG

/* define to 1 to disable lightweight runtime debugging checks */
#undef DRV_NDEBUG

#ifdef DRV_DEBUG
/* note: prints function name for you */
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif

#ifdef DRV_NDEBUG
#  define assert(expr) do {} while (0)
#else
#  define assert(expr) \
	if(!(expr)) {					\
	printk( "Assertion failed! %s,%s,%s,line=%d\n",	\
	#expr,__FILE__,__FUNCTION__,__LINE__);		\
	}
#endif

#define MODNAME		"prlfs"
#define DRV_VERSION	"1.0.0"
#define PFX		MODNAME ": "

#define PRLFS_ROOT_INO 2
#define PRLFS_GOOD_INO 8
#define ID_STR_LEN 16

#ifndef PCI_VENDOR_ID_PARALLELS
#define PCI_VENDOR_ID_PARALLELS		0x1ab8
#endif
#ifndef PCI_DEVICE_ID_TOOLGATE
#define PCI_DEVICE_ID_TOOLGATE		0x4000
#endif

/* Dentry prlfs speciffic flags stored in dentry->d_fsdata */
enum {
	PRL_DFL_TAG = 0x1UL, /* tagged detnry, used for debuging purposes */
	PRL_DFL_UNLINKED = 0x2UL, /* Unlinked dentry. */
};

unsigned long *prlfs_dfl( struct dentry *de);
#endif /* __PRL_FS_H__ */
