/*	$KAME: dccp_tfrc_print.h,v 1.7 2004/05/21 08:35:48 itojun Exp $	*/

/*
 * Copyright (c) 2003  Nils-Erik Mattsson 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Id: dccp_tfrc_print.h,v 1.10 2003/05/28 17:36:43 nilmat-8 Exp
 */

/* Prints debug information for TFRC */

#ifndef _NETINET_DCCP_TFRC_PRINT_H_
#define _NETINET_DCCP_TFRC_PRINT_H_

#define PRINTFLOAT(x) \
        do { \
		TFRC_DEBUG((LOG_INFO, "%lld/%lld", (x)->num, (x)->denom)); \
	} while (0)

#define PRINTTIMEVALu(tvp)    \
        do{  TFRC_DEBUG((LOG_INFO,"%u s, %u us",(u_int32_t) (tvp)->tv_sec,(u_int32_t) (tvp)->tv_usec)); \
        } while (0)
#define PRINTTIMEVALi(tvp)    \
        do{  TFRC_DEBUG((LOG_INFO,"%i s, %i us",(int) (tvp)->tv_sec,(int) (tvp)->tv_usec)); \
        } while (0)

#define PRINTSHISTENTRY(shp) \
        do {  TFRC_DEBUG((LOG_INFO,"Entry: seq=%u, win_count=%u t_sent=(",(shp)->seq,(shp)->win_count)); \
              PRINTTIMEVALu(&((shp)->t_sent)); \
              TFRC_DEBUG((LOG_INFO,")\n")); \
        } while (0)

#define PRINTSENDHIST(ccbp,elmp) \
        do {    \
            if (TAILQ_EMPTY(&((ccbp)->hist))) \
               TFRC_DEBUG((LOG_INFO, "Send history is empty\n")); \
            else {   \
                TFRC_DEBUG((LOG_INFO, "Send history:\n")); \
	      (elmp)= TAILQ_FIRST(&((ccbp)->hist)); \
	      while ((elmp) != NULL) {  \
		 PRINTSHISTENTRY((elmp)); \
                 (elmp) = TAILQ_NEXT((elmp),linfo); \
	      }\
	    }\
         } while (0)


#define PRINTRHISTENTRY(rhp) \
        do {  TFRC_DEBUG((LOG_INFO,"Entry: type=%u, seq=%u, win_count=%u, ndp=%u, t_recv=(",(rhp)->type,(rhp)->seq,(rhp)->win_count,(rhp)->ndp)); \
              PRINTTIMEVALu(&((rhp)->t_recv)); \
              TFRC_DEBUG((LOG_INFO,")\n")); \
        } while (0)

#define PRINTRECVHIST(ccbp,elmp) \
        do {    \
            if (TAILQ_EMPTY(&((ccbp)->hist))) \
               TFRC_DEBUG((LOG_INFO, "Recv history is empty\n")); \
            else {   \
                TFRC_DEBUG((LOG_INFO, "Recv history:\n")); \
	      (elmp)= TAILQ_FIRST(&((ccbp)->hist)); \
	      while ((elmp) != NULL) {  \
		 PRINTRHISTENTRY((elmp)); \
                 (elmp) = TAILQ_NEXT((elmp),linfo); \
	      }\
	    }\
         } while (0)

#define PRINTLIHISTENTRY(lihp) \
        do {  TFRC_DEBUG((LOG_INFO,"Entry: seqstart=%u, win_count=%u, interval=%u\n",(lihp)->seq,(lihp)->win_count,(lihp)->interval)); \
        } while (0)

#define PRINTLIHIST(ccbp,elmp) \
        do {    \
            if (TAILQ_EMPTY(&((ccbp)->li_hist))) \
               TFRC_DEBUG((LOG_INFO, "Loss interval history is empty\n")); \
            else {   \
                TFRC_DEBUG((LOG_INFO, "Loss interval history:\n")); \
	      (elmp)= TAILQ_FIRST(&((ccbp)->li_hist)); \
	      while ((elmp) != NULL) {  \
		 PRINTLIHISTENTRY((elmp)); \
                 (elmp) = TAILQ_NEXT((elmp),linfo); \
	      }\
	    }\
         } while (0)


#define PRINTSCCB(ccbp,elmp)\
        do{   \
           TFRC_DEBUG((LOG_INFO,"Sender CCB state=%u\nx=",(ccbp)->state));  \
           PRINTFLOAT((ccbp)->x);\
	   TFRC_DEBUG((LOG_INFO,",x_recv="));  \
           PRINTFLOAT((ccbp)->x_recv);\
	   TFRC_DEBUG((LOG_INFO,",x_calc=")); \
	   PRINTFLOAT((ccbp)->x_calc);  \
           TFRC_DEBUG((LOG_INFO, "\ns=%u, rtt= %u, p=",(ccbp)->s,(ccbp)->rtt)); \
           PRINTFLOAT((ccbp)->p);  \
           TFRC_DEBUG((LOG_INFO, "\nlast_win_count=%u, t_last_win_count=(",(ccbp)->last_win_count)); \
           PRINTTIMEVALu(&((ccbp)->t_last_win_count)); \
           TFRC_DEBUG((LOG_INFO, "\nidle=%u, t_rto=%u, t_ld=(",(ccbp)->idle,(ccbp)->t_rto)); \
           PRINTTIMEVALi(&((ccbp)->t_ld)); \
           TFRC_DEBUG((LOG_INFO, ")\nt_nom=(")); \
           PRINTTIMEVALu(&((ccbp)->t_nom)); \
           TFRC_DEBUG((LOG_INFO, ") t_ipi=("));   \
           PRINTTIMEVALu(&((ccbp)->t_ipi)); \
           TFRC_DEBUG((LOG_INFO, ") delta=("));   \
           PRINTTIMEVALu(&((ccbp)->delta)); \
           TFRC_DEBUG((LOG_INFO, ")\n"));   \
           PRINTSENDHIST(ccbp,elmp); \
           TFRC_DEBUG((LOG_INFO, "\n")); \
        } while (0)

#define PRINTRCCB(ccbp,relmp,lielmp)\
        do{   \
           TFRC_DEBUG((LOG_INFO,"Receiver CCB state=%u, s=%u, p=",(ccbp)->state,(ccbp)->s));  \
           PRINTFLOAT((ccbp)->p); \
           TFRC_DEBUG((LOG_INFO, "\nlast_counter=%u, seq_last_counter=%u\n",(ccbp)->last_counter,(ccbp)->seq_last_counter)); \
           TFRC_DEBUG((LOG_INFO, "bytes_recv=%u, t_last_feedback=(",(ccbp)->bytes_recv)); \
           PRINTTIMEVALi(&((ccbp)->t_last_feedback)); \
           TFRC_DEBUG((LOG_INFO, ")\n")); \
           PRINTRECVHIST(ccbp,relmp); \
           PRINTLIHIST(ccbp,lielmp); \
           TFRC_DEBUG((LOG_INFO, "\n")); \
        } while (0)

#endif
