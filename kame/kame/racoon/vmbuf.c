/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* YIPS @(#)$Id: vmbuf.c,v 1.2 1999/08/23 02:49:55 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "debug.h"

vchar_t *vmalloc(size_t size)
{
	vchar_t *var;

	if ((var = (vchar_t *)malloc(sizeof(*var))) == NULL)
		return NULL;

	var->t = 0;
	var->l = size;

	if ((var->v = (caddr_t)calloc(size, sizeof(u_char))) == NULL) {
		(void)free(var);
		return NULL;
	}

	return var;
}

vchar_t *vrealloc(vchar_t *ptr, size_t size)
{
	caddr_t v;

	if (ptr != NULL) {
		if ((v = (caddr_t)realloc(ptr->v, size)) == NULL) {
			(void)vfree(ptr);
			return NULL;
		}
		ptr->v = v;
		ptr->l = size;

	} else {
		if ((ptr = vmalloc(size)) == NULL)
			return NULL;
	}

	return ptr;
}

void vfree(vchar_t *var)
{
	if (var == NULL)
		return;

	if (var->v)
		(void)free(var->v);

	(void)free(var);

	return;
}

vchar_t *vdup(vchar_t *src)
{
	vchar_t *new;

	if ((new = vmalloc(src->l)) == NULL)
		return NULL;

	memcpy(new->v, src->v, src->l);

	return new;
}

int pvdump(vchar_t *var)
{
	int i;

	for (i = 0; i < var->l; i++) {
		if (i != 0 && i % 32 == 0) printf("\n");
		if (i % 4 == 0) printf(" ");
		printf("%02x", (unsigned char)(var->v)[i]);
	}

	printf("\n");

	return 0;
}
