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

/* XXX the following decl should be expanded */
#define BYTE	u_int8_t
#define DWORD	u_int32_t

#if BYTE_ORDER == LITTLE_ENDIAN
#define LittleEndian		1
#endif
#if BYTE_ORDER == BIG_ENDIAN
#define LittleEndian		0
#endif

/* XXX should use ALIGNBYTES, however, we cannot do that at runtime */
#define ALIGN32		1

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
