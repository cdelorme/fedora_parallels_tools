//////////////////////////////////////////////////////////////////////////
///
/// @file ParallelsTypes.h
///
/// @brief Base Parallels types declarations
///
/// @author maximk, misha
///
/// Ideally, all user - and - kernel space components are
/// supposed to use types, declared in this module.
/// Does not need any additional headers.
///
/// Copyright (c) 2006 Parallels Inc.
/// All Rights Reserved.
/// http://www.parallels.com
///
//////////////////////////////////////////////////////////////////////////

#ifndef __PARALLELS_TYPES_H__
#define __PARALLELS_TYPES_H__

// this is PREfast tool tune parameters (for DDK/WDK PREfast)
#if defined(_WIN_) && (_MSC_VER >= 1000) && !defined(__midl) && defined(_PREFAST_)
typedef int __declspec("SAL_nokernel") __declspec("SAL_nodriver") __prefast_flag_kernel_driver_mode;
#pragma prefast(disable: 28110 28159 28146 28285, "useless noise for UM apps")
#endif

// Force compilation errors if the platform defines are in conflict states
// (e.g. _X86_ is defined for __x86_64__)
#define FORCE_PLATFORM_CHECK

// Determining current architecture
#if defined(__x86_64__) || defined(_M_X64) || defined (_AMD64_) || defined(_WIN64) || defined(_M_AMD64) || defined(_M_IA64)
#ifndef _64BIT_
	#define _64BIT_
#endif
#ifndef _AMD64_
	#define _AMD64_
#endif
#if defined(FORCE_PLATFORM_CHECK) && defined(_X86_)
	#error "Define _X86_ is incompatible with 64-bit platform!"
#endif
#elif defined(_X86_) || defined(__i386__) || defined(_M_IX86)
#ifndef _32BIT_
	#define _32BIT_
#endif
#ifndef _X86_
	#define _X86_
#endif
#if defined(FORCE_PLATFORM_CHECK) && defined(_AMD64_)
	#error "Define _AMD64_ is incompatible with 32-bit platform!"
#endif
#elif defined(__arm__)
#ifndef _32BIT_
	#define _32BIT_
#endif
#else
	#error "Failed to determine processor architecture"
#endif

/**
 * Base types declaration, used by all Parallels software,
 * including user and kernel space components.
 */

/* Don't declare BOOL for obj-c */
#ifndef OBJC_BOOL_DEFINED
typedef	int				BOOL;
#endif

typedef char			CHAR;
typedef unsigned char	UCHAR;
typedef	unsigned char	BYTE;
typedef	short			SHORT;
typedef	unsigned short	USHORT;
typedef	unsigned short	WORD;
typedef int				INT;
typedef unsigned int	UINT;
#if defined(_X86_) || defined(_WIN_)
typedef long		LONG;
typedef unsigned long	ULONG;
#else
typedef int		LONG;
typedef unsigned int	ULONG;
#endif
#ifdef _WIN_
typedef	unsigned long	DWORD;
#else
typedef	unsigned int	DWORD;
#endif

#define BITS_PER_UINT	(sizeof(UINT) * 8)



/**
 * There are some differences in 64-bit variables declarations
 * on windows and unix compilers.
 */
#ifdef _WIN_
	typedef __int64			LONG64;
	typedef unsigned __int64	ULONG64;
	typedef unsigned __int64	QWORD;

#else
	#undef LONG64
	#undef ULONG64
	typedef unsigned long long	__int64;
	typedef long long		LONG64;
	typedef unsigned long long	ULONG64;
	typedef unsigned long long	QWORD;
#endif

typedef unsigned int ULONG32;

#if defined (_32BIT_)
	typedef	unsigned long	SIZE_T;
	typedef	unsigned long	ULONG_PTR;
	typedef signed long     LONG_PTR;
#elif defined (_64BIT_)
	typedef	ULONG64			SIZE_T;
	typedef	ULONG64			ULONG_PTR;
	typedef LONG64			LONG_PTR;
#endif

/*
 * Compiler-dependent suffixes for 64-bit constants.
 */
#ifdef __GNUC__
	// gcc
	#define L64(x)	(x##LL)
	#define UL64(x)	(x##ULL)
#elif defined(_MSC_VER)
	// icc and cl
	#define L64(x)	(x##i64)
	#define UL64(x)	(x##ui64)
#else
	#define L64(x)	(x)
	#define UL64(x)	(x)
#endif

/**
 * The history of these 2 macros is very strage.
 * The problem is that stupid COMPILERS like gcc, msvc, icc
 * tend to perfrom 32->64 bit conversion of unsigned values
 * using signed !!! extension.
 *
 * Found no other way then to use these macroses...
 */
#define PTR_TO_64(ptr) \
	((sizeof(void*) == 4) \
	 ? ((ULONG64)(ULONG_PTR)(ptr) & 0x00000000ffffffff) \
	 : ((ULONG64)(ULONG_PTR)(ptr)))

typedef UINT HYPERSTATUS;

#define HYP_STATUS_SUCCESS		    	(0x00000000)
#define HYP_INSUFFICIENT_RESOURCES		(0x80000001)
#define HYP_INVALID_PARAMETERS			(0x80000002)
#define HYP_UNKNOWN_HPC_CALL			(0x80000003)
#define HYP_INVALID_DEVICE_STATE		(0x80000004)
#define HYP_ALREADY_MAPPED			    (0x80000005)
#define HYP_SYSTEM_OVERCOMMIT			(0x80000006)
#define HYP_MIN_WSET_REACHED			(0x80000007)
#define HYP_TOO_SMALL_BUFFER			(0x80000008)
#define HYP_NOT_CANONICAL_ADDRESS		(0x80000009)
#define HYP_INTERNAL_INCOHERENCE		(0x8000000a)
#define HYP_STATUS_UNSUCCESSFUL			(0xffffffff)


/**
 * Declaring pointers to the base classes - we're not sure if
 * this is a good idea to keep this, but many developers already use it.
 */
#define VOID		void

typedef VOID		*PVOID;
typedef VOID		*LPVOID;

typedef BOOL		*PBOOL;
typedef CHAR		*PCHAR;
typedef UCHAR		*PUCHAR;
typedef BYTE		*PBYTE;
typedef SHORT		*PSHORT;
typedef USHORT		*PUSHORT;
typedef WORD		*PWORD;
typedef INT			*PINT;
typedef UINT		*PUINT;
typedef LONG		*PLONG;
typedef	DWORD		*PDWORD;
typedef ULONG		*PULONG;
typedef ULONG32		*PULONG32;
typedef LONG64		*PLONG64;
typedef ULONG64		*PULONG64;
typedef ULONG_PTR	*PULONG_PTR;


#ifndef EFIAPI

typedef UCHAR		UINT8,  *PUINT8;
typedef USHORT		UINT16, *PUINT16;
typedef SHORT		INT16,  *PINT16;
typedef UINT		UINT32, *PUINT32;
typedef INT			INT32,  *PINT32;
typedef ULONG64				UINT64;

#endif // EFIAPI

// INT64 format specifier
#if (defined(_LIN_) || defined(_MAC_))
	#define I64X "%#llx"
	#define I64D "%lld"
	#define I64U "%llu"
#else
	#define I64X "%#I64x"
	#define I64D "%I64d"
	#define I64U "%I64u"
#endif

/**
 * Some very common declarations - not sure where to keep them,
 * this place seems to be the best one
 */
#ifndef PAGE_SIZE
	#define PAGE_SIZE	0x1000
#endif

/* Best definition is in Linux kernel, X86_L1_CACHE_SHIFT:
 *   arch/x86/Kconfig.cpu
 */
#define CACHELINE_SIZE	64

#define CPUMASK_ALL		((UINT)0xFFFFFFFF)
#define CPUMASK_NONE	0

#ifndef TRUE
	#define TRUE	1
#endif

#ifndef FALSE
	#define FALSE	0
#endif

#ifndef NULL
#	ifdef __cplusplus
#		define NULL    0
#	else
#		define NULL    ((void *)0)
#	endif
#endif

#ifndef MAX
	#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
	#define MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))
#endif

#ifndef ARRAY_AND_SIZE
	#define ARRAY_AND_SIZE(a)	(a), ARRAY_SIZE(a)
#endif

/**
 * For platforms compatibility, we need to to have some
 * very common macros one each platform.
 */
#ifdef __GNUC__

	#define UNUSED			__attribute__((unused))
#ifndef EFIAPI
	#define PACKED			__attribute__((packed))
#endif

	/* force caller to check result, e.g. for error codes... */
#ifndef __must_check
	#define __must_check	 __attribute__((warn_unused_result))
#endif

	/* check types of %x parameters as for printf() in compile time... */
#ifndef __printf
	#define __printf(a,b)	__attribute__((format(printf,a,b)))
#endif

	/* tell gcc that condition is likely/unlikely always evaluates to true,
	 * so unlikely case will be branched out of main stream of instructions.
	 * Likely case goes w/o jumps and thus faster... */
	#define likely(x)		__builtin_expect(!!(x), 1)
	#define unlikely(x)		__builtin_expect(!!(x), 0)
#ifndef __cold
	#define __cold
#endif

#ifndef __always_inline
	#define __always_inline	inline __attribute__((always_inline))
#endif

	#define _ReturnAddress() __builtin_return_address(0)

	#define NAKED			__attribute__((naked))
	#define NORETURN		__attribute__((noreturn))
	#define DLLEXPORT
#if defined(_64BIT_) && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 4) || __GNUC__ > 4)
	#define MS_ABI			__attribute__((ms_abi))
	#define MS_ABI_SUPPORTED
#else
	#define MS_ABI
#endif
#ifndef PRL_ALIGN
	#define PRL_ALIGN(x)		__attribute__((aligned(x)))
#endif
#ifndef __cdecl
#ifdef _64BIT_
	#define __cdecl
#else
	#define __cdecl			__attribute__((__cdecl__))
#endif
#endif
#ifndef __stdcall
#ifdef _64BIT_
	#define __stdcall
#else
	#define __stdcall		__attribute__((__stdcall__))
#endif
#endif
#ifndef __fastcall
#ifdef _64BIT_
	#define __fastcall
#else
	#define __fastcall		__attribute__((__fastcall__))
#endif
#endif

#else /* All other compilers (MS, Intel) */

	#define UNUSED
	#define PACKED

	#define __must_check
	#define __printf(a,b)

#ifdef __ICL
	 /* tell ICL that condition is likely/unlikely always evaluates to true,
	 * so unlikely case will be branched out of main stream of instructions.
	 * Likely case goes w/o jumps and thus faster... */
	#define likely(x)               __builtin_expect(!!(x), 1)
	#define unlikely(x)             __builtin_expect(!!(x), 0)

#else
	#define likely(x)	x
	#define unlikely(x)	x
#endif

#ifndef __cold
	#define __cold
#endif

	#define __always_inline	__inline

	/* Visual Studio 2005 warnings madness workaround
	   (eliminating "deprecation" warnings) */
	#ifndef _CRT_SECURE_NO_DEPRECATE
		#define _CRT_SECURE_NO_DEPRECATE
	#endif

	#define NAKED			__declspec(naked)
	#define NORETURN		__declspec(noreturn)
	#define DLLEXPORT		__declspec(dllexport)
	#define PRL_ALIGN(x)	__declspec(align(x))
	#define MS_ABI

#endif

#ifdef BUILD_BUG_ON
#undef BUILD_BUG_ON
#endif

#define __PRL_UNIQUE_NAME(x,y) x##y
#define PRL_UNIQUE_NAME(x,y) __PRL_UNIQUE_NAME(x,y)

#ifndef __COUNTER__		/* gcc-4.2 or less. cl, icl, clang are OK */
#define __COUNTER__		__LINE__
#endif

// Validate constant condition on compilation stage. If condition is true
// array invalid size error occured
#define BUILD_BUG_ON(condition) \
	extern void UNUSED PRL_UNIQUE_NAME(__build_bug_on_dummy, \
									   __COUNTER__)(char a[1 - 2*!!(condition)])

#define UNUSED_PARAM(x)		(void)x

#if defined(_WIN_) && !defined(_MONITOR_)
/* stddef.h defines offsetof() as well and will complain if included after us */
#include <stddef.h>
#endif

#if defined(_LIN_)
/* linux/stddef.h defines offsetof() and undefines our correct implementation */
#include <linux/stddef.h>
#endif

#undef offsetof
#ifdef __GNUC__
#if __GNUC__ >= 4
	#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif
#endif
#ifndef offsetof
	#define offsetof(TYPE, MEMBER) ((ULONG_PTR) &((TYPE*)0)->MEMBER)
#endif

#undef container_of
#ifdef __GNUC__
/* version of container_of with type checking inside */
#define container_of(ptr, type, member) ({                    \
		const typeof( ((type *)0)->member ) *__xptr = (ptr);  \
		(type *)( (char *)__xptr - offsetof(type,member) );})
#else
#define container_of(ptr, type, member) \
		((type *)(((char *)(ptr)) - offsetof(type,member)))
#endif

/**
 * Maximum number of hooked devices
 */
#define PRL_MAX_GENERIC_PCI_DEVICES VTD_MAX_DEVICE_COUNT
#define VTD_MAX_DEVICE_COUNT (10)

/**
 * Empty define to mark variables that are frequently accessed.
 */
#ifdef _LIN_
#define __vmexit_hot __attribute__((__section__(".data.hot")))
#else
#define __vmexit_hot
#endif

#if !defined(EXTERNALLY_AVAILABLE_BUILD) && (defined(_MAC_) || defined(_LIN_))
	#define VALGRIND_ENABLED
#endif

#endif // __PARALLELS_TYPES_H__
