/*
 * Copyright (C) 1998 WIDE Project.
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
 *  What we advertise. 
 *    A Hold Timer value of 4 minutes is suggested. See [Page 32].
 */
#define BGP_HOLDTIME            240    /*  sec */

/*
 * How long to wait before retrying connect (should be multple of slot size)
 */
/*
#define BGPCONN_SHORT           32
*/
#define BGPCONN_SHORT           10     /*  sec */
#define BGP_ADV_DELAY       200000     /* usec */


/*
 * Minimum length of a BGP message is the length of the header.  If you
 * haven't got this, you haven't got anything.
 */
#define BGP_HEADER_LEN          19
#define BGP_HEADER_MARKER_LEN   16

struct bgphdr {
  u_char     bh_marker[BGP_HEADER_MARKER_LEN];
  u_int16_t  bh_length;
  u_int8_t   bh_type;
};

struct bgpoptparm {
  u_int8_t     bop_type;
  u_int8_t     bop_len;
};

#define BGP_PORT                179     /* Port number to use with BGP */


/*
   A message is processed only after it is entirely received.  The maximum
   message size is 4096 octets.  All implementations are required to
   support this maximum message size.         [draft-ietf-idr-bgp4-08.txt]
*/
#define BGPMAXPACKETSIZE       4096

/*
 * BGP message types
 */
#define BGP_OPEN        1               /* open message */
#define BGP_UPDATE      2               /* update message */
#define BGP_NOTIFY      3               /* notification message */
#define BGP_KEEPALIVE   4               /* keepalive message */


#define BGP_TYPE_VALID(a) (BGP_OPEN      <= (a) &&\
			   BGP_KEEPALIVE >= (a))


#define BGP_VERSION_4   4



/*
 * BGP error processing is a little tedious.  The following are
 * the error codes/subcodes we use.
 */
#define BGP_ERR_HEADER          1       /* message header error */
#define BGP_ERR_OPEN            2       /* open message error */
#define BGP_ERR_UPDATE          3       /* update message error */
#define BGP_ERR_HOLDTIME        4       /* hold timer expired */
#define BGP_ERR_FSM             5       /* finite state machine error */
#define BGP_CEASE               6       /* cease message (not an error) */
/*
 * The unspecified subcode is sent when we don't have anything better.
 */
#define BGP_ERR_UNSPEC          0
/*
 *   Message Header Error subcodes:
 */
#define BGP_ERRHDR_UNSYNC       1     /* Connection Not Synchronized */
#define BGP_ERRHDR_LENGTH       2     /* Bad Message Length */
#define BGP_ERRHDR_TYPE         3     /* Bad Message Type */

/*
 *   OPEN Message Error subcodes:
 */
#define BGP_ERROPN_VERSION      1       /* Unsupported Version number */
#define BGP_ERROPN_AS           2       /* Bad peer AS */
#define BGP_ERROPN_BGPID        3       /* Bad BGP Identifier */
#define BGP_ERROPN_OPTION       4       /* Unsupported Optional Parameter */
#define BGP_ERROPN_AUTH         5       /* Authentication Failure */
#define BGP_ERROPN_BADHOLDTIME  6       /* Unacceptable Hold Time */
#define BGP_ERROPN_CAPABILITY   7       /* Unsupported Capability */

/*
 *   UPDATE Message Error subcodes:
 */
#define BGP_ERRUPD_ATTRLIST     1      /* Malformed Attribute List */
#define BGP_ERRUPD_UNKNOWN      2      /* Unrecognized Well-known Attribute */
#define BGP_ERRUPD_MISSING      3      /* Missing Well-known Attribute */
#define BGP_ERRUPD_FLAGS        4      /* Attribute Flags Error */
#define BGP_ERRUPD_LENGTH       5      /* Attribute Length Error */
#define BGP_ERRUPD_ORIGIN       6      /* Invalid ORIGIN Attribute */
#define BGP_ERRUPD_ASLOOP       7      /* AS Routing Loop */
#define BGP_ERRUPD_NEXTHOP      8      /* Invalid NEXT_HOP Attribute */
#define BGP_ERRUPD_OPTATTR      9      /* Optional Attribute Error */
#define BGP_ERRUPD_BADNET       10     /* Invalid Network Field */
#define BGP_ERRUPD_ASPATH       11     /* Malformed AS_PATH */

/*
 * Protocol States
 */
#define BGPSTATE_IDLE           1       /* idle state - ignore everything */
#define BGPSTATE_CONNECT        2       /* connect state - trying to connect */
#define BGPSTATE_ACTIVE         3       /* waiting for a connection */
#define BGPSTATE_OPENSENT       4       /* open packet has been sent */
#define BGPSTATE_OPENCONFIRM    5       /* waiting for a keepalive or notify */
#define BGPSTATE_ESTABLISHED    6       /* connection has been established */

/*
 *   Optional Parameter Type in OPEN message
 */

#define BGP_OPTPARAM_AUTH       1       /* Authentication Information */
#define BGP_OPTPARAM_CAPA       2       /* Capabilities */
