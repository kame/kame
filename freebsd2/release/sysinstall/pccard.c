/*
 * PC-card support for sysinstall
 *
 * $Id: pccard.c,v 1.1 1999/09/13 08:50:40 itojun Exp $
 *
 * Copyright (c) 1997
 *	Tatsumi Hosokawa <hosokawa@jp.FreeBSD.org>.  All rights reserved.
 *
 * This software may be used, modified, copied, and distributed, in
 * both source and binary form provided that the above copyright and
 * these terms are retained. Under no circumstances is the author
 * responsible for the proper functioning of this software, nor does
 * the author assume any responsibility for damages incurred with its
 * use.
 */

#include "sysinstall.h"
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pccard/cardinfo.h>

#ifdef	PCCARD

int	pccard_mode = 0;

static int
replaceEtc(dialogMenuItem *self)
{
    msgNotify("Replacing /etc files....");
    vsystem("/stand/PAO/etc/etcinst.sh");
    variable_set2("pccard_enable", "YES");
    return DITEM_SUCCESS;
}

static int
makeBackup(dialogMenuItem *self)
{
    msgNotify("Copying the backup of kernel sources\n"
	      "into /usr/src/sys.2.2.8-RELEASE....");
    vsystem("/stand/PAO/sys/sysbackup.sh");
    return DITEM_SUCCESS;
}

static int
replaceKernel(dialogMenuItem *self)
{
    msgNotify("Compiling and installing the new kernel.\n"
	      "It will take a long time... \n"
	      "(about 10 - 100 minutes on 486/Pentium machines)");
    vsystem("/stand/PAO/sys/syspatch.sh");
    return DITEM_SUCCESS;
}

static int
installBin(dialogMenuItem *self)
{
    msgNotify("Installing new system binaries for laptops.");
    vsystem("/stand/PAO/bin/bininstall.sh");
    return DITEM_SUCCESS;
}


DMenu MenuPCICMem = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Please select free address area used by PC-card controller",
    "PC-card controller uses memory area to get card information.\n"
    "Please specify an address that is not used by other devices.\n"
    "If you're uncertain of detailed specification of your hardware,\n"
    "leave it untouched (default == 0xd0000).",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Default",  "I/O address 0xd0000 - 0xd3fff",
	    NULL, dmenuSetVariable, NULL, "pcicmem=0"},
	{ "D4", "I/O address 0xd4000 - 0xd7fff",
	    NULL, dmenuSetVariable, NULL, "pcicmem=1"},
	{ "D8", "I/O address 0xd8000 - 0xdbfff",
	    NULL,  dmenuSetVariable, NULL, "pcicmem=2"},
	{ "DC", "I/O address 0xdc000 - 0xdffff",
	    NULL,  dmenuSetVariable, NULL, "pcicmem=3"},
	{ NULL } },
};

DMenu MenuCardIRQ = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Please select IRQs that CANNOT be used by PC-cards",
    "Please specify an IRQs that CANNOT be used by PC-card.\n"
    "For example, if you have a sound card that can't be probed by\n"
    "this installation floppy and it uses IRQ 5, you have to specify\n"
    "IRQ 5 from this menu.  If you're using CardBus machine, you may\n"
    "have to use \"Option 3\" or \"Option 4\".\n",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Default",  "No IRQ is reserved",
	    NULL, dmenuSetVariable, NULL, "cardirq=0"},
	{ "Option 1", "IRQ 5 (ex. soundcard on IRQ 5)",
	    NULL, dmenuSetVariable, NULL, "cardirq=1"},
	{ "Option 2", "IRQ 10 (ex. soundcard on IRQ 10)",
	    NULL, dmenuSetVariable, NULL, "cardirq=2"},
	{ "Option 3", "IRQ 1-9 (ex. CardBus machine)",
	    NULL, dmenuSetVariable, NULL, "cardirq=3"},
	{ "Option 4", "IRQ 1-10 (ex. CardBus machine)",
	    NULL, dmenuSetVariable, NULL, "cardirq=4"},
	{ NULL } },
};

DMenu MenuReplaceEtc = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Do you want to install new /etc files for PC-card support?",
    "To use PC-card on FreeBSD, you must replace some /etc files with\n"
    "newer version.  Do you want to do it automatically?  If you don't\n"
    "want to do it, select [Cancel] button.\n\n"
    "CAUTION!: This operation will overrides all changes you made in\n"
    "/etc/rc.conf (e.g. hostname, IP address, keyboard configuration,\n"
    "etc.).  It will backup original /etc/rc.conf as /etc/rc.conf.orig.\n"
    "Please modify new /etc/rc.conf manually.  Sorry.",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Replace",  "Replace /etc files.",
	    NULL, replaceEtc },
	{ NULL } },
};

DMenu MenuBackupKernel = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Do you want to backup kernel source?",
    "To enable PC-card support, you must apply patch to the kernel sources\n"
    "and recompile the kernel.  If you want to backup original kernel sources\n"
    "before applying patches, select \"Backup\".  If you don't want to do it\n"
    "(ex., because of the shortage of disks), select [Cancel] button.",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Backup",  "Backup kernel source at /usr/src/sys-2.2.8-RELEASE.",
	    NULL, makeBackup },
	{ NULL } },
};

DMenu MenuPatchKernel = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Do you want to compile new kernel and install it?",
    "This installer automatically applies patches to the kernel sources\n"
    "and replace the kernel with patched one.  If you don't want to do it,\n"
    "select [Cancel] button.  Otherwise select \"Proceed\" to proceed. The\n"
    "old kernel is saved as /kernel.old.  If you have any problems with \n"
    "the new kernel, you can boot the old kernel by typing \"kernel.old\"\n"
    "from boot prompt.\n",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Proceed",  "Apply patch, compile, and install the new kernel",
	    NULL, replaceKernel },
	{ NULL } },
};

DMenu MenuBinInstall = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Do you want to install some system binaries for laptops?",
    "This installer replaces two system binaries (apm and shutdown) and\n"
    "install new one (wlconfig).  If you don't want to do it, select\n"
    "[Cancel] button.  Otherwise select \"Proceed\" to proceed.",
    "Press F1 for more HELP",
    "pccard",
    {	{ "Proceed",  "Install new system binaries",
	    NULL, installBin },
	{ NULL } },
};

static u_int pccard_sysconfig = 0;
#define PCCARD_SYSCONFIG_APM         0x0001
#define PCCARD_SYSCONFIG_PCCARD      0x0002

DMenu MenuPCCardSysconfig = {
    DMENU_CHECKLIST_TYPE | DMENU_SELECTION_RETURNS,
    "PC-card Configuration",
    "Enable/disable APM and PC-Card support.\n"
    "Please read PAO-FAQ (http://www.jp.FreeBSD.org/PAO/#faq) if you want to\n"
    "use automatic network configuration, etc.\n"
    "Note that there are some broken implementation of protected mode APM \n"
    "BIOS.  Enabling APM support on such machines will result in system crash.\n"
    "If you enabled APM support on such machines, please disable APM driver\n"
    "from UserConfig [boot: -c] screen.",
    "Press F1 for more HELP",
    "pccard",
    { { "A Enable APM",	"Enable APM (Advanced Power Management) BIOS",
	dmenuFlagCheck,	dmenuSetFlag, NULL, &pccard_sysconfig, '[', 'X', ']', PCCARD_SYSCONFIG_APM },
      { "P Enable PC-Card",	"Enable PC-Card (aka. PCMCIA) management",
	dmenuFlagCheck,	dmenuSetFlag, NULL, &pccard_sysconfig, '[', 'X', ']', PCCARD_SYSCONFIG_PCCARD},
      { NULL } },
};

#define	SOCKET_NAME	"/pccardd_socket"
#define	CSOCKET_NAME	"/cpccardd_socket"

static char *
communicate(int s, char *cmd, struct sockaddr_un *sun)
{
    static char buffer[256];
    int	len;
    fd_set rfds;
    struct timeval tv;
    
    len = strlen(cmd);
    
    if (sendto(s, cmd, len, 0, (struct sockaddr *)sun, SUN_LEN(sun)) != len) {
	msgFatal("Sendto server failed. CMD: %s", cmd);
    }

    tv.tv_sec = 20;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);

    if (select(16, &rfds, 0, 0, &tv) < 0) {
	msgFatal("Select server failed.");
    }

    if (!FD_ISSET(s, &rfds)) {
	msgFatal("Select server timeout.");
    }

    if ((len = recv(s, buffer, sizeof(buffer), 0)) < 0) { 
	msgFatal("Recv server failed. CMD: %s", cmd);
    }

    buffer[len] = 0;

    return buffer;
}

static int
parse_pccard_info(char *info)
{
    char *slot, *manuf, *vers, *drv, *stat;
    char *p;
    char *tokens[8];	/* actually, 5 */
    int tilde = 1;
    char *lasttilde = 0;
    int i = 0;
    
    for (p = info; *p && i <= 5; p++) {
	if (tilde) {
	    if (*p != '~') {
		tokens[i] = p;
		tilde = 0;
		if (lasttilde) {
		    *lasttilde = 0;
		}
		i++;
	    }
	    else {
		tokens[i] = "";
		if (lasttilde) {
		    *lasttilde = 0;
		}
		lasttilde = p;
		i++;
	    }
	}
	else if (*p == '~') {
	    tilde = 1;
	    lasttilde = p;
	}
    }

    slot = tokens[0];
    manuf = tokens[1];
    vers = tokens[2];
    drv = tokens[3];
    stat = tokens[4];

    if (strlen(manuf) == 0 && strlen(vers) == 0) {
	msgNotify("Slot %s: Empty slot", slot);
	sleep(1);
	return 0;
    }

    if (strlen(drv) == 0) {
	msgConfirm("Slot %s: Card \"%s(%s)\"\nUnsupported card!",
		   slot, manuf, vers);
	return 0;
    }

    msgNotify("Slot %s: Card \"%s(%s)\"\nAssigned %s driver.",
	       slot, manuf, vers, drv);

    return 1;
}

void
pccardInitialize(void)
{
    int i;
    int fd;
    int s = 0;
    int t;
    int slotnum;
    int found[MAXSLOT];
    int	pcic_mem = 0xd0000;
    int validcard = 0;
    char *r;
    char card_device[16];
    char *card_irq = "";
    char *spcic_mem;
    char *scard_irq;
    char pccardd_cmd[256];
    struct sockaddr_un sun;
    struct sockaddr_un csun;
    struct stat sb;

    pccard_mode = 1;
    
    if (!RunningAsInit && !Fake) {
	/* It's not my job... */
	return;
    }

    dmenuOpenSimple(&MenuPCICMem, FALSE);
    spcic_mem = variable_get("pcicmem");
    dmenuOpenSimple(&MenuCardIRQ, FALSE);
    scard_irq = variable_get("cardirq");

    sscanf(spcic_mem, "%d", &t);
    switch (t) {
      case 0:
	pcic_mem = 0xd0000;
	break;
      case 1:
	pcic_mem = 0xd4000;
	break;
      case 2:
	pcic_mem = 0xd8000;
	break;
      case 3:
	pcic_mem = 0xdc000;
	break;
    }

    sscanf(scard_irq, "%d", &t);

    switch (t) {
      case 0:
	card_irq = " ";
	break;
      case 1:
	card_irq = " -i 5 ";
	break;
      case 2:
	card_irq = " -i 10 ";
	break;
      case 3:
	card_irq = " -i 1 -i 2 -i 3 -i 4 -i 5 -i 6 -i 7 -i 8 -i 9 ";
	break;
      case 4:
	card_irq = " -i 1 -i 2 -i 3 -i 4 -i 5 -i 6 -i 7 -i 8 -i 9 -i 10 ";
	break;
    }

    sprintf(card_device, CARD_DEVICE, 0);
    
    dialog_clear();
    msgConfirm("Now starts initializing PC-card controller and cards.\n"
	       "If you've executed this installer from PC-card floppy\n"
	       "drive, this is the last chance to replace it with\n"
	       "installation media (PC-card Ethernet, SCSI, etc.).\n"
	       "Please insert installation media and press [Enter].\n"
	       "If you've not plugged the PC-card installation media\n"
	       "yet, please plug it now and press [Enter].\n"
	       "Otherwise, just press [Enter] to proceed."); 

    dialog_clear();
    msgNotify("Initializing PC-card controller....");
    
    if (!Fake) {
	if ((fd = open(card_device, O_RDWR)) < 1) {
	    msgNotify("Can't open PC-card controller %s.\n", 
		      card_device);
	    return;
	}

	if (ioctl(fd, PIOCRWMEM, &pcic_mem) < 0){
	    msgNotify("ioctl %s failed.\n", card_device);
	    return;
	}
    }

    strcpy(pccardd_cmd, "/stand/pccardd ");
    strcat(pccardd_cmd, card_irq);
    strcat(pccardd_cmd, " -n -s " SOCKET_NAME " &");
    vsystem(pccardd_cmd);

    if (!Fake) {
	if ((s = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
	    msgFatal("Can't create pccard socket.");
	}

	for (i = 0; i < 30; i++) {
	    sleep(1);
	    if (stat(SOCKET_NAME, &sb) == 0) {
		goto found;
	    }
	}
	msgFatal("Timeout: Can't find " SOCKET_NAME);
	/*NOTREACHED*/
    }

  found:
    if (Fake) {
	slotnum = 2;
    }
    else {
	if ((sb.st_mode & S_IFMT) != S_IFSOCK) {
	    msgFatal(SOCKET_NAME " is not a socket.");
	}
	
	bzero(&sun, sizeof(sun));
    
	sun.sun_family = PF_UNIX;
	strcpy(sun.sun_path, SOCKET_NAME);
	csun.sun_family = PF_UNIX;
	strcpy(csun.sun_path, CSOCKET_NAME);

	if (bind(s, (struct sockaddr *)&csun, SUN_LEN(&csun)) < 0) {
	    msgFatal("Binding client socket failed.");
	}

	sleep(3);

	r = communicate(s, "S", &sun);
    
	if (sscanf(r, "%d", &slotnum) < 1) {
	    msgFatal("Can't find PC-card slot(s).  Message:\"%s\"", r);
	}
    }
    msgNotify("Found %d PC-card slot(s).\n"
	      "Initializing PC-cards....\n"
	      "(about 20 seconds)",
	      slotnum); 
    if (!Fake) {
	sleep(20);

	dialog_clear();

	bzero(found, sizeof(found));
    
	for (i = 0; i < slotnum; i++) {
	    int len;
	    int j;
	    int cnt;
	
	    char buf[16];

	    sprintf(buf, "N%d", i);
	    r = communicate(s, buf, &sun);
	    len = strlen(r);
	    cnt = 0;

	    for (j = 0; j < len; j++) {
		if (r[j] == '~') {
		    cnt++;
		}
	    }

	    if (cnt != 4) {
		msgConfirm("Slot %d: invalid card information", i);
	    }
	    else {
		validcard |= parse_pccard_info(r);
		sleep(2);
	    }
	}
    }
    if (!validcard) {
	msgConfirm("No cards are initialized.  Maybe your card is unsupported or\n"
		   "hardware information you specified is invalid.  If you\n"
		   "want to install FreeBSD from PC-card device, please reboot\n"
		   "the machine and check your hardware configuration. For details,\n"
		   "type [ENTER] and read PC-card section in documentation menu.");
    }
}

void
cleanPCcardSockets(void)
{
    unlink(SOCKET_NAME);
    unlink(CSOCKET_NAME);
}

int
configPCcard(dialogMenuItem *self)
{
    if (RunningAsInit) {
	msgConfirm("This option may only be used after the system is installed, sorry!");
	return DITEM_FAILURE;
    }

    dialog_clear();

    msgConfirm("This menu item can be used just after the 2.2.8-RELEASE system\n"
	       "is installed.  If you've done any patches to kernel sources,\n"
	       "this operation may fail.\n"
	       "If you don't want to do this operation automatically, please\n"
	       "select [Cancel] button for all three questions and execute\n"
	       "scripts in /stand/PAO/bin, /stand/PAO/etc and /stand/PAO/sys\n"
	       "manually.\n"
	       "If you're installing other version of FreeBSD than 2.2.8-RELEASE,\n"
	       "don't execute these operations anyway.\n"
	       "Please read PC-card section in documentation menu for details.");
    
    dmenuOpenSimple(&MenuReplaceEtc, FALSE);
    dmenuOpenSimple(&MenuBackupKernel, FALSE);
    dmenuOpenSimple(&MenuPatchKernel, FALSE);
    dmenuOpenSimple(&MenuBinInstall, FALSE);
    dmenuOpenSimple(&MenuPCCardSysconfig, FALSE);
    if (pccard_sysconfig & PCCARD_SYSCONFIG_APM)
        variable_set2("apm_enable", "YES");
    if (pccard_sysconfig & PCCARD_SYSCONFIG_PCCARD)
        variable_set2("pccard_enable", "YES");
    dialog_clear();
    msgConfirm("FreeBSD PC-card support is compiled and installed.  The old kernel\n"
	       "was saved as /kernel.old, and GENERIC kernel still remains as \n"
	       "/kernel.GENERIC.  If you have any problem with new the kernel,\n"
	       "reboot the system with old kernels.\n"
	       "PAO-FAQ (http://www.jp.FreeBSD.org/PAO/#faq) will help you if\n"
	       "you have typical troubles with this system.\n"
	       "Exit this installer, and type \"reboot[Enter]\" to reboot the system.");
    return DITEM_SUCCESS | DITEM_RESTORE;
}
#endif	/* PCCARD */
