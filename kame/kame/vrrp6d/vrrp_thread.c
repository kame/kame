/*	$KAME: vrrp_thread.c,v 1.2 2002/07/10 04:54:16 itojun Exp $	*/

/*
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "vrrp_thread.h"

/* addresses table of all struct vrrp_vr * initialized by threads */
struct vrrp_vr *vr_ptr[VRRP_PROTOCOL_MAX_VRID];
/* actual position on this table */
u_char          vr_ptr_pos = 0;
pthread_mutex_t pth_mutex, pth_mutex_bpf;
sem_t           sem;

void 
vrrp_thread_mutex_lock(void)
{
	pthread_mutex_lock(&pth_mutex);

	return;
}

void 
vrrp_thread_mutex_unlock(void)
{
	pthread_mutex_unlock(&pth_mutex);

	return;
}

void 
vrrp_thread_mutex_lock_bpf(void)
{
	pthread_mutex_lock(&pth_mutex_bpf);

	return;
}

void 
vrrp_thread_mutex_unlock_bpf(void)
{
	pthread_mutex_unlock(&pth_mutex_bpf);

	return;
}

void 
vrrp_thread_launch_vrrprouter(void *args)
{
	struct vrrp_vr *vr = (struct vrrp_vr *) args;

	if (vr_ptr_pos == 255) {
		syslog(LOG_ERR, "cannot configure more than 255 VRID... exiting\n");
		exit(-1);
	}
	vr_ptr[vr_ptr_pos] = vr;
	vr_ptr_pos++;
	sem_post(&sem);
	for (;;) {
		switch (vr->state) {
		case VRRP_STATE_INITIALIZE:
			vrrp_state_initialize(vr);
			break;
		case VRRP_STATE_MASTER:
			vrrp_state_master(vr);
			break;
		case VRRP_STATE_BACKUP:
			vrrp_state_backup(vr);
			break;
		}
	}

	/* Normally never executed */
	return;
}

char 
vrrp_thread_initialize(void)
{
	if (pthread_mutex_init(&pth_mutex, NULL) != 0) {
		syslog(LOG_ERR, "can't initialize thread for socket reading [ PTH_MUTEX, NULL ]");
		return -1;
	}
	if (sem_init(&sem, 0, 0) == -1) {
		syslog(LOG_ERR, "can't initialize an unnamed semaphore [ SEM, 0, 0 ]");
		return -1;
	}
	return 0;
}

char 
vrrp_thread_create_vrid(struct vrrp_vr * vr)
{
	pthread_t       pth;
	pthread_attr_t  pth_attr = NULL;

	if (pthread_attr_init(&pth_attr) != 0) {
		syslog(LOG_ERR, "can't initialize thread attributes [ PTH_ATTR ]");
		return -1;
	}
	if (pthread_attr_setdetachstate(&pth_attr, PTHREAD_CREATE_DETACHED) != 0) {
		syslog(LOG_ERR, "can't set thread attributes [ PTH_ATTR, PTHREAD_CREATE_DETACHED ]");
		return -1;
	}
	if (pthread_create(&pth, &pth_attr, (void *)&vrrp_thread_launch_vrrprouter, vr) != 0) {
		syslog(LOG_ERR, "can't create new thread [ PTH, PTH_ATTR, VRRP_THREAD_READ_SOCKET ]");
		return -1;
	}
	sem_wait(&sem);

	return 0;
}
