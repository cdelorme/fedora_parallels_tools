/*
 * Copyright (C) 2008 Parallels Inc. All Rights Reserved.
 * Linux guest specific PCI toolgate userspace interface definitions
 */

#ifndef __PRL_TG_H__
#define __PRL_TG_H__
typedef struct _TG_BUFFER {
	union {
		void *Buffer;
		unsigned long long Va;
	} u;
	unsigned ByteCount;
	unsigned Writable:1;
	unsigned Userspace:1; /* used in kernelspace requests only,
			       * ignored in userspace requests */
	unsigned Reserved:30;
} __attribute__((aligned(8))) TG_BUFFER;

typedef struct _TG_REQUEST {
	unsigned Request;
	unsigned Status;
	unsigned short InlineByteCount;
	unsigned short BufferCount;
	unsigned Reserved;
} __attribute__((aligned(8))) TG_REQUEST;

typedef struct _TG_REQ_DESC {
	TG_REQUEST *src;
	void *idata;
	TG_BUFFER *sbuf;
} TG_REQ_DESC;

#define PROC_PREFIX			"/proc/driver/"
#define TOOLGATE_NICK_NAME		"prl_tg"
#define VIDEO_TOOLGATE_NICK_NAME	"prl_vtg"

#define PRL_TG_FILE	PROC_PREFIX TOOLGATE_NICK_NAME
#define PRL_VTG_FILE	PROC_PREFIX VIDEO_TOOLGATE_NICK_NAME

struct draw_bdesc {
	union {
		void *pbuf;
		unsigned long long va;
	} u;
	unsigned int id;
	unsigned int bsize;
	unsigned int used;
	unsigned int pad; /* not used, only for structure alignment */
};

#define VIDTG_CREATE_DRAWABLE _IO('|',0)
#define VIDTG_CLIP_DRAWABLE _IOWR('|',1, struct draw_bdesc)
#define VIDTG_DESTROY_DRAWABLE _IO('|',2)

#endif
