/*	$KAME: random.c,v 1.1 2000/10/05 06:28:20 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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
/*
 * a stub function to make random() to return good random numbers.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>

#include <openssl/rand.h>

long
random()
{
	long v;
	double lavg[1];

	while (RAND_bytes((u_char *)&v, sizeof(v)) != 1) {
		/* XXX need a better random number souce! */

		/* load average */
		getloadavg(lavg, sizeof(lavg)/sizeof(lavg[0]));
		RAND_seed(&lavg[0], sizeof(lavg[0]));
	}
	return v;
}

void
srandom(seed)
	unsigned long seed;
{
	double lavg[1];

	RAND_seed(&seed, sizeof(seed));

	/* load average */
	getloadavg(lavg, sizeof(lavg)/sizeof(lavg[0]));
	RAND_seed(&lavg[0], sizeof(lavg[0]));
}
