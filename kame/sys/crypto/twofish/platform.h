/***************************************************************************
	PLATFORM.C	-- Platform-specific defines for TWOFISH code

	Submitters:
		Bruce Schneier, Counterpane Systems
		Doug Whiting,	Hi/fn
		John Kelsey,	Counterpane Systems
		Chris Hall,		Counterpane Systems
		David Wagner,	UC Berkeley
		Niels Ferguson, Counterpane Systems
			
	Code Author:		Doug Whiting,	Hi/fn
		
	Version  1.10		August 1999
		
	Copyright 1998-99, Hi/fn and Counterpane Systems.  All rights reserved.
		
	Notes:
		*	Tab size is set to 4 characters in this file

	GENERAL PORTING INSTRUCTIONS:

		For the Twofish code to work properly on a given CPU and compiler, 
		the following types must be defined correctly:
			
			BYTE		 -- must be an 8-bit unsigned quantity
			DWORD		 -- must be a 32-bit unsigned quantity
			LittleEndian -- must be defined as
								1 for little-endian CPUs (e.g., x86)
								0 for big-endian CPUs (e.g., 68K)
			ALIGN32		 -- must be defined as
								1 if misaligned 32-bit accesses are not allowed
								0 if misaligned 32-bit accesses are allowed

		Typically, these definitions are selected by including a #ifdef 
		that is true only for the given platform and defining each of these 
		quanitities	appropriately.  See the examples below (x86 and 68K), as
		well as the "template" for _MY_AES_PLATFORM.  The definitions below 
		for BYTE and DWORD should work automatically for most platforms.

		In addition, to maximimize performance, it is recommended that 
		the following macros should	be modified to use instrinsic CPU opcodes, 
		if possible:
			a) ROL and ROR
			b) for big endian CPUs, BSWAP(x) and _b(x,N)

		Note that porting this Twofish code to a platform where a C "char" 
		is not 8 bits in size may be very difficult!
*/

	
			
/***************************************************************************/

/* Generic rotation ops (Use intrinsic rotate for performance, if possible) */
#define	ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define	ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#ifdef _MSC_VER							/* optimize rotates in Microsoft C */
#include	<stdlib.h>					/* get prototypes for rotation functions */
#undef	ROL
#undef	ROR
#pragma intrinsic(_lrotl,_lrotr)		/* use intrinsic compiler rotations */
#define	ROL(x,n)	_lrotl(x,n)			
#define	ROR(x,n)	_lrotr(x,n)
#endif

#ifndef _M_IX86
#ifdef	__BORLANDC__
#define	_M_IX86					300		/* make sure this is defined for Intel CPUs */
#endif
#endif

typedef		unsigned char BYTE;			/*  8-bit unsigned quantity */

#include	<limits.h>					/* get size limit definitions */
#if   UINT_MAX  == 0xFFFFFFFF			/* "auto-select" a 32-bit definition */
typedef		unsigned int  DWORD;
#elif ULONG_MAX == 0xFFFFFFFF
typedef		unsigned long DWORD;
#elif USHRT_MAX == 0xFFFFFFFF
typedef		unsigned short DWORD;
#else
#error !! Need a 32-bit DWORD definition (PLATFORM.H) !!
#endif


#if defined(_M_IX86)					/* settings for the Intel x86 family */
#define		LittleEndian		1		/* x86 is little-endian */
#define		ALIGN32				0		/* x86 can do misaligned accesses */
#endif

#if defined(_68K_)						/* example settings for 68K family */
#define		LittleEndian		0		/* 68K is big-endian */
#define		ALIGN32				1		/* 68K can't do misaligned accesses */
#endif

#if defined(_MY_AES_PLATFORM_)			/* template for other platforms */
#define		LittleEndian		?
#define		ALIGN32				?
#endif


/* Compile-time sanity checks: make sure that some platform was defined! */
#ifndef LittleEndian
#error Need to define LittleEndian for this platform! (in PLATFORM.H)
#endif

#ifndef ALIGN32
#error Need to define ALIGN32 for this platform! (in PLATFORM.H)
#endif


/*  Build higher-level constructs based on endianness setting  */
#if LittleEndian
#define		Bswap(x)			(x)		/* NOP for little-endian machines */
#define		ADDR_XOR			0		/* NOP for little-endian machines */
#else
#define		Bswap(x)			((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define		ADDR_XOR			3		/* convert byte address in dword */
#endif

/*	Macros for extracting bytes from dwords (correct for endianness) */
#define	_b(x,N)	(((BYTE *)&x)[((N) & 3) ^ ADDR_XOR]) /* pick bytes out of a dword */

#define		b0(x)			_b(x,0)		/* extract LSB of DWORD */
#define		b1(x)			_b(x,1)
#define		b2(x)			_b(x,2)
#define		b3(x)			_b(x,3)		/* extract MSB of DWORD */
