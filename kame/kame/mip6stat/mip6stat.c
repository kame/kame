/*	$KAME: mip6stat.c,v 1.14 2002/08/28 12:17:54 keiichi Exp $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet6/ip6_var.h>
#include <netinet6/mip6_var.h>

#define KEIICHI

static kvm_t *kvm;
static char kvm_err[_POSIX2_LINE_MAX];
struct nlist kvm_namelist[] = {
	{ "_mip6stat" },
#define NL_MIP6STAT 0
	{ "_ip6stat" },
#define NL_IP6STAT 1
	{""},
};

static const char *binding_ack_status_desc[] = {
	"binding update accepted",
	"#1",
	"#2",
	"#3",
	"#4",
	"#5",
	"#6",
	"#7",
	"#8",
	"#9",
	"#10",
	"#11",
	"#12",
	"#13",
	"#14",
	"#15",
	"#16",
	"#17",
	"#18",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"#30",
	"#31",
	"#32",
	"#33",
	"#34",
	"#35",
	"#36",
	"#37",
	"#38",
	"#39",
	"#40",
	"#41",
	"#42",
	"#43",
	"#44",
	"#45",
	"#46",
	"#47",
	"#48",
	"#49",
	"#50",
	"#51",
	"#52",
	"#53",
	"#54",
	"#55",
	"#56",
	"#57",
	"#58",
	"#59",
	"#60",
	"#61",
	"#62",
	"#63",
	"#64",
	"#65",
	"#66",
	"#67",
	"#68",
	"#69",
	"#70",
	"#71",
	"#72",
	"#73",
	"#74",
	"#75",
	"#76",
	"#77",
	"#78",
	"#79",
	"#80",
	"#81",
	"#82",
	"#83",
	"#84",
	"#85",
	"#86",
	"#87",
	"#88",
	"#89",
	"#90",
	"#91",
	"#92",
	"#93",
	"#94",
	"#95",
	"#96",
	"#97",
	"#98",
	"#99",
	"#100",
	"#101",
	"#102",
	"#103",
	"#104",
	"#105",
	"#106",
	"#107",
	"#108",
	"#109",
	"#110",
	"#111",
	"#112",
	"#113",
	"#114",
	"#115",
	"#116",
	"#117",
	"#118",
	"#119",
	"#120",
	"#121",
	"#122",
	"#123",
	"#124",
	"#125",
	"#126",
	"#127",
	"reason unspecified",
	"administratively prohibited",
	"Insufficient resources",
	"home registration not supported",
	"not home subnet",
	"not home agent for this mobile node",
	"duplicate address detection failed",
	"sequence number out of window",
	"route optimization unnecessary due to low traffic",
	"invalid authenticator",
	"expired home nonce index",
	"expired care-of nonce index",
	"#140",
	"#141",
	"#142",
	"#143",
	"#144",
	"#145",
	"#146",
	"#147",
	"#148",
	"#149",
	"#150",
	"#151",
	"#152",
	"#153",
	"#154",
	"#155",
	"#156",
	"#157",
	"#158",
	"#159",
	"#160",
	"#161",
	"#162",
	"#163",
	"#164",
	"#165",
	"#166",
	"#167",
	"#168",
	"#169",
	"#170",
	"#171",
	"#172",
	"#173",
	"#174",
	"#175",
	"#176",
	"#177",
	"#178",
	"#179",
	"#180",
	"#181",
	"#182",
	"#183",
	"#184",
	"#185",
	"#186",
	"#187",
	"#188",
	"#189",
	"#190",
	"#191",
	"#192",
	"#193",
	"#194",
	"#195",
	"#196",
	"#197",
	"#198",
	"#199",
	"#200",
	"#201",
	"#202",
	"#203",
	"#204",
	"#205",
	"#206",
	"#207",
	"#208",
	"#209",
	"#210",
	"#211",
	"#212",
	"#213",
	"#214",
	"#215",
	"#216",
	"#217",
	"#218",
	"#219",
	"#220",
	"#221",
	"#222",
	"#223",
	"#224",
	"#225",
	"#226",
	"#227",
	"#228",
	"#229",
	"#230",
	"#231",
	"#232",
	"#233",
	"#234",
	"#235",
	"#236",
	"#237",
	"#238",
	"#239",
	"#240",
	"#241",
	"#242",
	"#243",
	"#244",
	"#245",
	"#246",
	"#247",
	"#248",
	"#249",
	"#250",
	"#251",
	"#252",
	"#253",
	"#254",
	"#255"
};

static const char *binding_error_status_desc[] = {
	"#0",
	"Home Address Option used without a binding",
	"received message had an unknown MH type",
	"#3",
	"#4",
	"#5",
	"#6",
	"#7",
	"#8",
	"#9",
	"#10",
	"#11",
	"#12",
	"#13",
	"#14",
	"#15",
	"#16",
	"#17",
	"#18",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"#30",
	"#31",
	"#32",
	"#33",
	"#34",
	"#35",
	"#36",
	"#37",
	"#38",
	"#39",
	"#40",
	"#41",
	"#42",
	"#43",
	"#44",
	"#45",
	"#46",
	"#47",
	"#48",
	"#49",
	"#50",
	"#51",
	"#52",
	"#53",
	"#54",
	"#55",
	"#56",
	"#57",
	"#58",
	"#59",
	"#60",
	"#61",
	"#62",
	"#63",
	"#64",
	"#65",
	"#66",
	"#67",
	"#68",
	"#69",
	"#70",
	"#71",
	"#72",
	"#73",
	"#74",
	"#75",
	"#76",
	"#77",
	"#78",
	"#79",
	"#80",
	"#81",
	"#82",
	"#83",
	"#84",
	"#85",
	"#86",
	"#87",
	"#88",
	"#89",
	"#90",
	"#91",
	"#92",
	"#93",
	"#94",
	"#95",
	"#96",
	"#97",
	"#98",
	"#99",
	"#100",
	"#101",
	"#102",
	"#103",
	"#104",
	"#105",
	"#106",
	"#107",
	"#108",
	"#109",
	"#110",
	"#111",
	"#112",
	"#113",
	"#114",
	"#115",
	"#116",
	"#117",
	"#118",
	"#119",
	"#120",
	"#121",
	"#122",
	"#123",
	"#124",
	"#125",
	"#126",
	"#127",
	"#128",
	"#129",
	"#130",
	"#131",
	"#132",
	"#133",
	"#134",
	"#135",
	"#136",
	"#137",
	"#138",
	"#139",
	"#140",
	"#141",
	"#142",
	"#143",
	"#144",
	"#145",
	"#146",
	"#147",
	"#148",
	"#149",
	"#150",
	"#151",
	"#152",
	"#153",
	"#154",
	"#155",
	"#156",
	"#157",
	"#158",
	"#159",
	"#160",
	"#161",
	"#162",
	"#163",
	"#164",
	"#165",
	"#166",
	"#167",
	"#168",
	"#169",
	"#170",
	"#171",
	"#172",
	"#173",
	"#174",
	"#175",
	"#176",
	"#177",
	"#178",
	"#179",
	"#180",
	"#181",
	"#182",
	"#183",
	"#184",
	"#185",
	"#186",
	"#187",
	"#188",
	"#189",
	"#190",
	"#191",
	"#192",
	"#193",
	"#194",
	"#195",
	"#196",
	"#197",
	"#198",
	"#199",
	"#200",
	"#201",
	"#202",
	"#203",
	"#204",
	"#205",
	"#206",
	"#207",
	"#208",
	"#209",
	"#210",
	"#211",
	"#212",
	"#213",
	"#214",
	"#215",
	"#216",
	"#217",
	"#218",
	"#219",
	"#220",
	"#221",
	"#222",
	"#223",
	"#224",
	"#225",
	"#226",
	"#227",
	"#228",
	"#229",
	"#230",
	"#231",
	"#232",
	"#233",
	"#234",
	"#235",
	"#236",
	"#237",
	"#238",
	"#239",
	"#240",
	"#241",
	"#242",
	"#243",
	"#244",
	"#245",
	"#246",
	"#247",
	"#248",
	"#249",
	"#250",
	"#251",
	"#252",
	"#253",
	"#254",
	"#255"
};

static int showdetail (struct mip6stat *);
static int tmpshow(struct ip6stat *, struct mip6stat *);

struct mip6stat mip6stat;
struct ip6stat ip6stat;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
#ifdef KEIICHI
	int keiichi = 0;
#endif

	while ((ch = getopt(argc, argv, "K")) != -1) {
		switch(ch) {
#ifdef KEIICHI
		case 'K':
			keiichi = 1;
			break;
		}
#endif
	}

	kvm = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, kvm_err);
	if (kvm == NULL) {
		fprintf(stderr, "%s\n", kvm_err);
		exit(1);
	}
	if (kvm_nlist(kvm, kvm_namelist) < 0) {
		fprintf(stderr, "no namelist\n");
		exit(1);
	}

	if (kvm_read(kvm, kvm_namelist[NL_MIP6STAT].n_value,
	    (void *)&mip6stat, sizeof(mip6stat)) < 0) {
		fprintf(stderr, "mip6stat read error\n");
		exit(1);
	}
	if (kvm_read(kvm, kvm_namelist[NL_IP6STAT].n_value,
	    (void *)&ip6stat, sizeof(ip6stat)) < 0) {
		fprintf(stderr, "ip6stat read error\n");
		exit(1);
	}

#ifdef KEIICHI
	if (keiichi == 1)
		tmpshow(&ip6stat, &mip6stat);
	else
#endif
	showdetail(&mip6stat);

	exit(0);
}


#define PS(msg, variable) printf("\t%qu " msg "\n", mip6stat->variable)
static int
showdetail(mip6stat)
	struct mip6stat *mip6stat;
{
	int i;

	printf("Input:\n");
	PS("Mobility Headers", mip6s_mobility);
	PS("HoTI messages", mip6s_hoti);
	PS("CoTI messages", mip6s_coti);
	PS("HoT messages", mip6s_hot);
	PS("CoT messages", mip6s_cot);
	PS("BU messages", mip6s_bu);
	PS("BA messages", mip6s_ba);
	for (i =0; i < 256; i++) {
		if (mip6stat->mip6s_ba_hist[i] != 0) {
			printf("\t\t%qu %s\n", mip6stat->mip6s_ba_hist[i],
			    binding_ack_status_desc[i]);
		}
	}
	PS("BR messages", mip6s_br);
	PS("BE messages", mip6s_be);
	for (i =0; i < 256; i++) {
		if (mip6stat->mip6s_be_hist[i] != 0) {
			printf("\t\t%qu %s\n", mip6stat->mip6s_be_hist[i],
			    binding_error_status_desc[i]);
		}
	}
	PS("Home Address Option", mip6s_hao);
	PS("unverified Home Address Option", mip6s_unverifiedhao);
	PS("Routing Header type 2", mip6s_rthdr2);
	PS("bad MH checksum", mip6s_checksum);
	PS("bad payload protocol", mip6s_payloadproto);
	PS("unknown MH type", mip6s_unknowntype);
	PS("not my home address", mip6s_nohif);
	PS("no related binding update entry", mip6s_nobue);
	PS("HoT cookie mismatch", mip6s_hotcookie);
	PS("CoT cookie mismatch", mip6s_cotcookie);
	PS("unprotected binding signaling packets", mip6s_unprotected);
	PS("BUs discarded due to bad HAO", mip6s_haopolicy);
	PS("RR authentication failed", mip6s_rrauthfail);
	PS("seqno mismatch", mip6s_seqno);
	PS("parameter problem for HAO", mip6s_paramprobhao);
	PS("parameter problem for MH", mip6s_paramprobmh);

	printf("Output:\n");
	PS("Mobility Headers", mip6s_omobility);
	PS("HoTI messages", mip6s_ohoti);
	PS("CoTI messages", mip6s_ocoti);
	PS("HoT messages", mip6s_ohot);
	PS("CoT messages", mip6s_ocot);
	PS("BU messages", mip6s_obu);
	PS("BA messages", mip6s_oba);
	for (i =0; i < 256; i++) {
		if (mip6stat->mip6s_oba_hist[i] != 0) {
			printf("\t\t%qu %s\n", mip6stat->mip6s_oba_hist[i],
			    binding_ack_status_desc[i]);
		}
	}
	PS("BR messages", mip6s_obr);
	PS("BE messages", mip6s_obe);
	for (i =0; i < 256; i++) {
		if (mip6stat->mip6s_obe_hist[i] != 0) {
			printf("\t\t%qu %s\n", mip6stat->mip6s_obe_hist[i],
			    binding_error_status_desc[i]);
		}
	}
	PS("Home Address Option", mip6s_ohao);
	PS("Routing Header type 2", mip6s_orthdr2);

	return (0);
}
#undef PS

#ifdef KEIICHI
#define M(variable) printf(#variable ":%qu,", mip6stat->variable)
int
tmpshow(ip6stat, mip6stat)
	struct ip6stat *ip6stat;
	struct mip6stat *mip6stat;
{
	int i;

	printf("ip6:%qu,", ip6stat->ip6s_total);
	M(mip6s_mobility);
	M(mip6s_hoti);
	M(mip6s_coti);
	M(mip6s_hot);
	M(mip6s_cot);
	M(mip6s_bu);
	M(mip6s_ba);
	for (i = 0; i < 256; i++) {
		if (mip6stat->mip6s_ba_hist[i] != 0)
			printf("mip6s_ba_hist_%03u:%qu,",
			    i, mip6stat->mip6s_ba_hist[i]);
	}
	M(mip6s_br);
	M(mip6s_be);
	for (i = 0; i < 256; i++) {
		if (mip6stat->mip6s_be_hist[i] != 0)
			printf("mip6s_be_hist_%03u:%qu,",
			    i, mip6stat->mip6s_be_hist[i]);
	}
	M(mip6s_hao);
	M(mip6s_unverifiedhao);
	M(mip6s_rthdr2);
	M(mip6s_paramprobhao);
	M(mip6s_paramprobmh);

	printf("oip6:%qu,", ip6stat->ip6s_localout);
	M(mip6s_omobility);
	M(mip6s_ohoti);
	M(mip6s_ocoti);
	M(mip6s_ohot);
	M(mip6s_ocot);
	M(mip6s_obu);
	M(mip6s_oba);
	for (i = 0; i < 256; i++) {
		if (mip6stat->mip6s_oba_hist[i] != 0)
			printf("mip6s_oba_hist_%03u:%qu,",
			    i, mip6stat->mip6s_oba_hist[i]);
	}
	M(mip6s_obr);
	M(mip6s_obe);
	for (i = 0; i < 256; i++) {
		if (mip6stat->mip6s_obe_hist[i] != 0)
			printf("mip6s_obe_hist_%03u:%qu,",
			    i, mip6stat->mip6s_obe_hist[i]);
	}
	M(mip6s_ohao);
	M(mip6s_orthdr2);

	printf("ENDOFDATA\n");
	return (0);
}
#undef M
#endif
