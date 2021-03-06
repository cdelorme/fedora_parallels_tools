//////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2007 Parallels Inc. All Rights Reserved.
/// http://www.parallels.com
///
/// PCI toolgate structures and constants that walk
/// from guest kernel mode to host application
///
/// note that this interface must be common for
/// 32 and 64 bit architectures
///
/// @author sergeyv@
///
//////////////////////////////////////////////////////////////////////////
#ifndef __TG_H__
#define __TG_H__

#ifdef _MSC_VER
typedef unsigned __int64 TG_UINT64;
#else
typedef unsigned long long TG_UINT64;
#endif

typedef unsigned TG_STATUS;

typedef struct _TG_PAGED_BUFFER {
	TG_UINT64 Va;
	unsigned ByteCount;
	unsigned Writable:1;
	unsigned Reserved:31;
	// TG_UINT64 Pages[];
} TG_PAGED_BUFFER;

struct _ASSERT_TG_PAGED_BUFFER {
	char test[sizeof(TG_PAGED_BUFFER) == 16 ? 1 : -1];
};

typedef struct _TG_PAGED_REQUEST {
	unsigned Request;
	unsigned Status;
	unsigned RequestSize;
	unsigned short InlineByteCount;
	unsigned short BufferCount;
	TG_UINT64 RequestPages[1/*RequestPageCount*/];
	// char InlineBytes[(InlineByteCount + 7) & ~7];
	// TG_PAGED_BUFFER Buffers[BufferCount];
} TG_PAGED_REQUEST;

/////////////////////////////////////////////////////////////////////////////
//
// Interrupt status/mask register bits
//

#define TG_INTBIT_COMPLETE	(0)
#define TG_INTBIT_ERROR		(1)
#define TG_INTBIT_SFILTER	(2)

#define TG_MASK_COMPLETE	(1 << TG_INTBIT_COMPLETE)
#define TG_MASK_ERROR		(1 << TG_INTBIT_ERROR)
#define TG_MASK_SFILTER		(1 << TG_INTBIT_SFILTER)

/////////////////////////////////////////////////////////////////////////////
//
// well known Request codes
// requests up to TG_REQUEST_SECURED_MAX are for drivers only and are
// denied by guest driver if come from user space to maintain guest
// kernel integrity (prevent malicious code from sending FS requests)
// dynamically assigned requests start from TG_REQUEST_MIN_DYNAMIC
//
#define TG_REQUEST_INVALID 0
#define TG_REQUEST_SECURED_MAX 0x00007fff
#define TG_REQUEST_DYNAMIC_MIN 0x00010000

// mouse pointer requests (from PCI video)
#define TG_REQUEST_SET_MOUSE_POINTER 0x100
#define TG_REQUEST_HIDE_MOUSE_POINTER 0x101
#define TG_REQUEST_DISABLE_MOUSE_POINTER 0x102

// multi-head support (from PCI video)
#define TG_REQUEST_VID_QUERY_HEADS 0x110
#define TG_REQUEST_VID_ENABLE_HEAD 0x111
#define TG_REQUEST_VID_DISABLE_HEAD 0x112
#define TG_REQUEST_VID_SET_MODE 0x114
#define TG_REQUEST_VID_SET_OFFSET 0x115
#define TG_REQUEST_VID_SET_PALETTE 0x116
#define TG_REQUEST_VID_SHARE_STATE 0x117
#define TG_REQUEST_VID_MAX 0x11f

// shared folders requests
// Version 1 requests:
#define TG_REQUEST_FS_MIN 0x200
#define TG_REQUEST_FS_GETLIST 0x200
#define TG_REQUEST_FS_CONNECTROOT 0x201
#define TG_REQUEST_FS_CREATEFILE 0x202
#define TG_REQUEST_FS_QUERYDIRINIT 0x203
#define TG_REQUEST_FS_QUERYDIRGETDATA 0x204
#define TG_REQUEST_FS_QUERYDIRCLOSE 0x205
#define TG_REQUEST_FS_CLOSEHANDLE 0x206
#define TG_REQUEST_FS_READDATA 0x207
#define TG_REQUEST_FS_SETDISPOSITION 0x208
#define TG_REQUEST_FS_WRITEDATA 0x209
#define TG_REQUEST_FS_SETBASICINFO 0x20a
#define TG_REQUEST_FS_SETALLOCINFO 0x20b
#define TG_REQUEST_FS_RENAMEFILE 0x20c
#define TG_REQUEST_FS_SETFILESIZE 0x20d
#define TG_REQUEST_FS_GETSIZEINFO 0x20e
#define TG_REQUEST_FS_NOTIFYCHANGEDIR 0x20f	// version 3 request
#define TG_REQUEST_FS_FLUSHBUFFERS 0x210

#define TG_REQUEST_FS_L_GETSFLIST 0x220
#define TG_REQUEST_FS_L_GETSFPARM 0x221
#define TG_REQUEST_FS_L_ATTR 0x222
#define TG_REQUEST_FS_L_OPEN 0x223
#define TG_REQUEST_FS_L_RELEASE 0x224
#define TG_REQUEST_FS_L_READDIR 0x225
#define TG_REQUEST_FS_L_RW 0x226
#define TG_REQUEST_FS_L_REMOVE 0x227
#define TG_REQUEST_FS_L_RENAME 0x228

// Version 2 requests:
#define TG_REQUEST_FS_NOOP 0x229

#define TG_REQUEST_FS_CREATEFILEX 0x22a
#define TG_REQUEST_FS_CLOSEHANDLES 0x22b

#define TG_REQUEST_FS_CONTROL 0x23d	// version 4 request
#define TG_REQUEST_FS_GETVERSION 0x23e
#define TG_REQUEST_FS_MAX 0x23f

//Direct3d request
//////////////////////////////////
// old d3d request [0x300, 0x321]
#define TG_REQUEST_DIRECT3D_HOST_PROFILE 0x400
#define TG_REQUEST_DIRECT3D_CREATE_CONTEXT 0x401
#define TG_REQUEST_DIRECT3D_DESTROY_PROCESS 0x402
#define TG_REQUEST_DIRECT3D_DESTROY_CONTEXT2 0x405
#define TG_REQUEST_DIRECT3D_SETCOLORKEY_SURFACE 0x406

#define TG_REQUEST_DDRAW_FLIP_OVERLAY 0x407
#define TG_REQUEST_DDRAW_UPDATE_OVERLAY 0x408
#define TG_REQUEST_DDRAW_DESTROY_OVERLAY 0x409
#define TG_REQUEST_DDRAW_SETPOSITION_OVERLAY 0x40a

#define TG_REQUEST_DIRECT3D_DEBUG_STRING 0x40b

#define TG_REQUEST_DDRAW_CANCREATE_OVERLAY 0x40c

#define TG_REQUEST_DIRECT3D_FLUSH2 0x40d

#define TG_REQUEST_DIRECT3D_MAP_APERTURE 0x410
#define TG_REQUEST_DIRECT3D_UNMAP_APERTURE 0x411
#define TG_REQUEST_DIRECT3D_MAX 0x41f

// utility tool requests
#define TG_REQUEST_UT_MIN		0x8000
#define TG_REQUEST_UT_COMMAND	0x8000
#define TG_REQUEST_UT_MAX		0x8001

// CPTool requests
#define TG_REQUEST_CPTOOL_MIN					0x8010
#define TG_REQUEST_CPTOOL_HOST_TO_GUEST_COMMAND	0x8010
#define TG_REQUEST_CPTOOL_GUEST_TO_HOST_COMMAND	0x8011
#define TG_REQUEST_CPTOOL_MAX					0x8012

// Shell integration tool
#define TG_REQUEST_SHELLINT_MIN				0x8020
#define TG_REQUEST_SHELLINT_ENABLED			0x8020
#define TG_REQUEST_SHELLINT_DISABLED		0x8021
#define TG_REQUEST_SHELLINT_WAITCOMMAND		0x8022
#define TG_REQUEST_SHELLINT_SMGETPOS		0x8023
#define TG_REQUEST_SHELLINT_SMCLOSED		0x8024
#define TG_REQUEST_SHELLINT_TRAYINFO		0x8025
#define TG_REQUEST_SHELLINT_TRAYCLEAR		0x8026
#define TG_REQUEST_SHELLINT_WAITCOMMAND_1	0x8027
#define TG_REQUEST_SHELLINT_GETICONPOS		0x8028
#define TG_REQUEST_SHELLINT_MAX				0x8029

#define TG_REQUEST_LAYOUTSYNC_MIN			0x8030
#define TG_REQUEST_LAYOUTSYNC_LISTEN		0x8030
#define TG_REQUEST_LAYOUTSYNC_NOTIFY		0x8031
#define TG_REQUEST_LAYOUTSYNC_MAX			0x8032

// unprivileged mouse pointer requests (from PCI video)
#define TG_REQUEST_MOUSE_SET_POINTER 0x8100
#define TG_REQUEST_MOUSE_HIDE_POINTER 0x8101
#define TG_REQUEST_MOUSE_DISABLE_POINTER 0x8102

// unprivileged multi-head support (from PCI video)
#define TG_REQUEST_MM_QUERY_HEADS 0x8110
#define TG_REQUEST_MM_ENABLE_HEAD 0x8111
#define TG_REQUEST_MM_DISABLE_HEAD 0x8112
#define TG_REQUEST_MM_SET_MODE 0x8114
#define TG_REQUEST_MM_SET_OFFSET 0x8115
#define TG_REQUEST_MM_SET_PALETTE 0x8116
#define TG_REQUEST_MM_SHARE_STATE 0x8117
#define TG_REQUEST_MM_MAX 0x811f

// Walking Mouse (Sliding Mouse for VT-d)
#define TG_REQUEST_WM_MIN				0x8120
#define TG_REQUEST_WM_DISPLAY_CHANGED	0x8120
#define TG_REQUEST_WM_DISPLAY_JUMP		0x8121
#define TG_REQUEST_WM_CTL				0x8122
#define TG_REQUEST_WM_CAN_START			0x8123
#define TG_REQUEST_WM_MAX				0x8129

// OpenGL
#define TG_REQUEST_GL_VERSION         0x8130
#define TG_REQUEST_GL_CREATE_PROCESS  0x8131
#define TG_REQUEST_GL_DESTROY_PROCESS 0x8132
#define TG_REQUEST_GL_CREATE_CONTEXT  0x8133
#define TG_REQUEST_GL_DESTROY_CONTEXT 0x8134
#define TG_REQUEST_GL_COPY_CONTEXT    0x8135
#define TG_REQUEST_GL_SHARE_CONTEXT   0x8136
#define TG_REQUEST_GL_CREATE_BUFFER   0x8137
#define TG_REQUEST_GL_DESTROY_BUFFER  0x8138
#define TG_REQUEST_GL_COMMAND         0x8139
#define TG_REQUEST_GL_SYNCHRONIZE     0x813a
#define TG_REQUEST_GL_RECREATE_BUFFER 0x813b
#define TG_REQUEST_GL_MAX             0x813f

// graceful shutdown tool requests
#define TG_REQUEST_GS_MIN		0x8200
#define TG_REQUEST_GS_COMMAND	0x8200
#define TG_REQUEST_GS_RESULT		0x8201
#define TG_REQUEST_GS_MAX		0x8202

// Suspen/Resume support tool requests
#define TG_TOOLSCENTER_REQUEST_MIN		0x8210
#define TG_TOOLSCENTER_REQUEST_COMMAND	0x8210
#define TG_TOOLSCENTER_REQUEST_MAX		0x8211

// Shared Internet Applications tool requests
#define TG_REQUEST_SIA_MIN		0x8220
#define TG_REQUEST_SIA_CMD		0x8220
#define TG_REQUEST_SIA_MAX		0x8221

// Coherence tool requests
#define TG_REQUEST_COHERENCE_MIN	0x8230
#define TG_REQUEST_COHERENCE		0x8230
#define TG_REQUEST_COHERENCE_MAX	0x8231

// [requests for different stuff ported from PD30]
// Shared Host Applications
#define TG_REQUEST_WINMICROAPPS			0x8301
// Shared Guest Applications
#define TG_REQUEST_FAVRUNAPPS			0x8302
// Legacy Utility Tool
#define TG_REQUEST_LEGACY_UTILITY_TOOL	0x8303
// Drag&Drop Tool
#define TG_REQUEST_DNDTOOL     			0x8304
// [/requests for different stuff ported from PD30]

// shared host applications
#define TG_REQUEST_VIRTEX_MIN			0x8320
#define TG_REQUEST_VIRTEX_FSTAT			0x8320
#define TG_REQUEST_VIRTEX_FCTL			0x8321
#define TG_REQUEST_VIRTEX_UITHEME		0x8322 // deprecated
#define TG_REQUEST_VIRTEX_CRASH			0x8323
#define TG_REQUEST_VIRTEX_VCONFIGGET	0x8324
#define TG_REQUEST_VIRTEX_VCONFIGLISTEN	0x8325
#define TG_REQUEST_VIRTEX_GENHOTKEY		0x8326
#define TG_REQUEST_VIRTEX_MAX			0x8327

// User Input Emulation requests
#define TG_REQUEST_UIEMU_MIN			0x8340
#define TG_REQUEST_UIEMU_CTL			0x8340
#define TG_REQUEST_UIEMU_ELEMENT_AT_POS	0x8341
#define TG_REQUEST_UIEMU_CARET_INFO		0x8342
#define TG_REQUEST_UIEMU_INPUT_INFO		0x8343
#define TG_REQUEST_UIEMU_AUTOKEYBOARD	0x8344
#define TG_REQUEST_UIEMU_HINTING_INFO	0x8345
#define TG_REQUEST_UIEMU_MAX			0x8346

// Shared Profile requests
#define TG_REQUEST_SP_BASE		0x8410
#define TG_REQUEST_SP_MAX		0x8411

// Inversed Sharing requests
#define TG_REQUEST_INVSHARING		0x8420
#define TG_REQUEST_INVSHARING_MAX	0x8440

// Desktop Utilities Tool requests
#define TG_REQUEST_DU_COMMAND_MIN 0x8500
#define TG_REQUEST_DU_COMMAND	0x8500 // for taskbar and desktop state
#define TG_REQUEST_DU_COMMAND_KBD_LAYOUT 0x8501 // for keyboard hotkeys
#define TG_REQUEST_DU_COMMAND_MAX 0x8502

// Balooning control requests
#define TG_REQUEST_BALOONING_GET_SIZE	0x8600
#define TG_REQUEST_BALOONING_STOP		0x8601

// Storage filter requests
#define TG_REQUEST_SFLT_CONNECT_DISK	0x8700
#define TG_REQUEST_SFLT_SRB		0x8701
#define TG_REQUEST_SFLT_INIT_DISK	0x8702

#define TG_REQUEST_SFLT_MIN		TG_REQUEST_SFLT_CONNECT_DISK
#define TG_REQUEST_SFLT_MAX		TG_REQUEST_SFLT_INIT_DISK

// CEP requests
#define TG_REQUEST_CEP_COMMAND_MIN		0x8800
#define TG_REQUEST_CEP_COMMAND			0x8800
#define TG_REQUEST_CEP_COMMAND_MAX		0x8801

#define TG_REQUEST_PRINTING_TOOL		0x8900

#define TG_REQUEST_SINGLE_SIGN_ON_TOOL	0x9000

#define TG_REQUEST_COOKIE_MIN			0x9010
#define TG_REQUEST_COOKIE_GET			0x9010
#define TG_REQUEST_COOKIE_LISTEN		0x9011
#define TG_REQUEST_COOKIE_MAX			0x9012

/////////////////////////////////////////////////////////////////////////////
//
// request Status codes
// these are cross-platform numbers
//
#define TG_STATUS_SUCCESS 0
#define TG_STATUS_PENDING 0xffffffff
#define TG_STATUS_CANCELLED 0xf0000000

#define TG_STATUS_MALFORMED_REQUEST 0xf0000001
#define TG_STATUS_INVALID_REQUEST 0xf0000002
#define TG_STATUS_INVALID_PARAMETER 0xf0000003
#define TG_STATUS_NO_MEMORY 0xf0000004
#define TG_STATUS_NO_RESOURCES 0xf0000005

#define TG_STATUS_ACCESS_VIOLATION 0xf0000006
#define TG_STATUS_ACCESS_DENIED 0xf0000007
#define TG_STATUS_BAD_NETWORK_NAME 0xf0000008
#define TG_STATUS_BUFFER_TOO_SMALL 0xf0000009
#define TG_STATUS_CANNOT_DELETE 0xf000000a
#define TG_STATUS_DIRECTORY_NOT_EMPTY 0xf000000b
#define TG_STATUS_DISK_FULL 0xf000000c
#define TG_STATUS_EAS_NOT_SUPPORTED 0xf000000d
#define TG_STATUS_END_OF_FILE 0xf000000e
#define TG_STATUS_FILE_DELETED 0xf000000f
#define TG_STATUS_FILE_IS_A_DIRECTORY 0xf0000010
#define TG_STATUS_INSUFFICIENT_RESOURCES 0xf0000011
#define TG_STATUS_INVALID_HANDLE 0xf0000012
#define TG_STATUS_NO_MORE_FILES 0xf0000013
#define TG_STATUS_NO_SUCH_FILE  0xf0000014
#define TG_STATUS_NOT_A_DIRECTORY 0xf0000015
#define	TG_STATUS_NOT_IMPLEMENTED 0xf0000016
#define TG_STATUS_OBJECT_NAME_COLLISION 0xf0000017
#define TG_STATUS_OBJECT_NAME_INVALID 0xf0000018
#define TG_STATUS_OBJECT_NAME_NOT_FOUND 0xf0000019
#define TG_STATUS_OBJECT_PATH_NOT_FOUND 0xf000001a
#define TG_STATUS_TOO_MANY_OPENED_FILES 0xf000001b
#define TG_STATUS_UNSUCCESSFUL 0xf000001c

#define TG_STATUS_TOOL_NOT_READY 0xf000001d
#define TG_STATUS_REQUEST_ALREADY_EXISTS 0xf000001e

#define TG_STATUS_INCOMPATIBLE_VERSION 0xf000001f
#define TG_STATUS_SUSPENDED				0xf0000020
#define TG_STATUS_NOT_HANDLED			0xf0000021
#define TG_STATUS_STALE_HANDLE 0xf0000022
#define TG_STATUS_NOT_SAME_DEVICE 0xf0000023
#define TG_STATUS_REPLACED 0xf0000024
#define TG_STATUS_RETRY 0xf0000025

#define TG_STATUS_CONTEXT_LOST 0xf0000026

// ...

#endif // __TG_H__
