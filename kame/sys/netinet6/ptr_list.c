/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$Id: ptr_list.c,v 1.1 1999/08/12 12:41:12 shin Exp $
//#
//#------------------------------------------------------------------------
*/

/*	#include <stdio.h>					*/
#include <sys/param.h>
#include <sys/malloc.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#endif
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/in6.h>

#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_list.h>


/*
//##
//#------------------------------------------------------------------------
//#	Typedefs and Miscellaneous definitions
//#------------------------------------------------------------------------
*/

#if !defined(NULL)
#define	NULL			0
#endif

#define	CELL_NUMS		64
#define	CELL_PAGE		(CELL_NUMS * sizeof(Cell))

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static MALLOC_DEFINE(M_PM, "SuMiRe", "Packet Management by SuMiRe");
#endif

/*
//##
//#------------------------------------------------------------------------
//#	Typedefs and Miscellaneous definitions
//#------------------------------------------------------------------------
*/

static	int	 _cell_used;
static	int	 _cell_free;
static	Cell	*_cell_freeList;
static	Cell	*_cell_mallBlock;

static	Cell	*_getCell	__P((void));
static	Cell	*_getEmptyCell	__P((void));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

Cell *
LST_cons(void *c_car, void *c_cdr)
{
    Cell    *ptr = NULL;

    ptr = _getCell();
    CAR(ptr) = c_car;
    CDR(ptr) = c_cdr;

    _cell_used++;
    _cell_free--;

    return (ptr);
}


void
LST_free(Cell *cell)
{
    if (CAR(cell) != CELL_FREE_MARKER)
    {
	CAR(cell) = CELL_FREE_MARKER;
	CDR(cell) = _cell_freeList;
	_cell_freeList = cell;

	_cell_used--;
	_cell_free++;
    }
}


Cell *
LST_last(Cell *list)
{
    register	Cell	*ptr = NULL;

    if (list == NULL)
	ptr = NULL;
    else
	for (ptr = list; CDR(ptr) != NULL; ptr = CDR(ptr)) ;

    return (ptr);
}


int
LST_length(Cell *list)
{
    register	int	retval = 0;

    if (list == NULL)
	retval = 0;
   else
   {
       register	   Cell	   *ptr;

       for (ptr = list; ptr; retval++, ptr = CDR(ptr)) ;
   }

    return (retval);
}


Cell *
LST_hookup(Cell *list, void *elem)
{
    register	Cell	*ptr = NULL;

    if (list == NULL)
	ptr = LST_cons(elem, NULL);
    else
	CDR(LST_last(list)) = LST_cons(elem, NULL);

    return (ptr);
}


Cell *
LST_hookup_list(Cell **list, void *elem)
{
    register	Cell	*ptr = NULL;

    if (*list == NULL)
	*list = LST_cons(elem, NULL);
    else
	CDR(LST_last(*list)) = LST_cons(elem, NULL);

    return (ptr);
}


Cell *
LST_remove_elem(Cell **list, void *elem)
{
    register	Cell	*p, *q;

    if (*list == NULL)
	return (NULL);

    for (p = *list, q = NULL; p; q = p, p = CDR(p))
    {
	if (CAR(p) == elem)
	{
	    if (q == NULL)
		*list = CDR(p);
	    else
		CDR(q) = CDR(p);

	    LST_free(p);
	    return (elem);
	}
    }

    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	Cell *
_getCell()
{
    Cell    *ptr = NULL;

    if (_cell_freeList == NULL)
	_cell_freeList = _getEmptyCell();

    ptr = _cell_freeList;
    _cell_freeList = CDR(_cell_freeList);

    return (ptr);
}


static	Cell *
_getEmptyCell()
{
    register	int	iter;
    register	Cell	*ptr = NULL;
    register	Cell	*p;

    MALLOC(ptr, Cell *, CELL_PAGE, M_PM, M_NOWAIT);
    if (ptr == NULL)
    {
	printf("ENOBUFS in _getEmptyCell %d\n", __LINE__);
	return (ptr);
    }

    CAR(ptr) = (Cell *)ptr;
    CDR(ptr) = NULL;

    if (_cell_mallBlock == NULL)
	_cell_mallBlock = ptr;
    else
	CDR(LST_last(_cell_mallBlock)) = ptr;

    ptr++;
    for (iter = CELL_NUMS - 2 , p = ptr; iter; iter-- , p++)
	CAR(p) = CELL_WEIRD_ADDR, CDR(p) = p + 1;
    CAR(p) = CELL_WEIRD_ADDR;
    CDR(p) = NULL;
    _cell_free += CELL_NUMS - 1;
    
    return (ptr);
}
