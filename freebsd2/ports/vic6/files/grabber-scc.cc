/*
 * Copyright (c) 1996 The Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the Network Research
 * 	Group at Lawrence Berkeley National Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 *
 * This module contributed by Koji OKAMURA <oka@kobe-u.ac.jp>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/fcntl.h>  
#include <sys/ioctl.h>
#include <sys/time.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>


extern "C" {
#if defined(__linux__)
#include <scc.h>
#elif defined(__FreeBSD__)
#include <machine/scc.h>
#endif
}

#include "grabber.h"
#include "Tcl.h"
#include "device-input.h"
#include "module.h"

#define NTSC_WIDTH  320
#define NTSC_HEIGHT 240
#define PAL_WIDTH   384
#define PAL_HEIGHT  288
#define CIF_WIDTH   352
#define CIF_HEIGHT  288

#define CF_422 0
#define CF_411 1
#define CF_CIF 2

class SCCGrabber : public Grabber {
 public:
	SCCGrabber(const char * cformat);
	virtual ~SCCGrabber();
	virtual void start();
	struct scc_geomet scc_;
	int format_;
 protected:
	virtual int command(int argc, const char*const* argv);
	virtual int grab();
	virtual void SCCgrab();
	virtual void format();
	virtual void setsize();

	int fd;
	short buf[CIF_WIDTH*CIF_HEIGHT];
	u_int basewidth_;
	u_int baseheight_;
	u_int decimate_;
	int cformat_;
};

class SCCDevice : public InputDevice {
 public:
	SCCDevice(const char*);
	virtual int command(int argc, const char*const* argv);
};

static SCCDevice SCC_device("scc0");

SCCDevice::SCCDevice(const char* name) : InputDevice(name)
{

  if(access("/dev/scc0",R_OK) == 0)
   	{
    	attributes_ = " \
		format { 422 411 } \
		size { small cif  } \
		port { Input-1 } ";
  	} else
    	attributes_ = "disabled";
}

int SCCDevice::command(int argc, const char*const* argv)
{
	Tcl& tcl = Tcl::instance();
	if (argc == 3) {
		if (strcmp(argv[1], "open") == 0) {
			TclObject* o = 0;
			o = new SCCGrabber(argv[2]);
			if (o != 0)
				tcl.result(o->name());
			return (TCL_OK);
		}
	}
	return (InputDevice::command(argc, argv));
}

SCCGrabber::SCCGrabber(const char *cformat)
{

  fd=open("/dev/scc0",O_RDONLY);
  if(fd<0){
    fprintf(stderr,"open failed: %s %s \n",
	    "/dev/scc0",strerror(errno));
    exit(1);
  }

  if(!strcmp(cformat, "422")) cformat_ = CF_422;
  if(!strcmp(cformat, "cif")) cformat_ = CF_CIF;

  decimate_ =2;
  basewidth_ =NTSC_WIDTH *decimate_;
  baseheight_=NTSC_HEIGHT*decimate_;

  scc_.width = basewidth_ /decimate_;
  scc_.height= baseheight_/decimate_;
  if(ioctl(fd,SCCSETGEO,&scc_)){
    perror("ioctl");
    exit(1);
  }

  format_ = SCC_YUV422;
  if(ioctl(fd,SCCSETFMT,&format_)){
    perror("ioctl");
    exit(1);
  }

}

SCCGrabber::~SCCGrabber()
{
  close(fd);
}

void SCCGrabber::start()
{
  format();
  Grabber::start();
}

int SCCGrabber::command(int argc, const char*const* argv)
{

  if (argc == 3) {
    if (strcmp(argv[1], "decimate") == 0) {
      int dec = atoi(argv[2]);
      Tcl& tcl = Tcl::instance();
      if (dec <= 0) {
	tcl.resultf("%s: divide by zero", argv[0]);
	return (TCL_ERROR);
      }
      if (dec != decimate_) {
	decimate_ = dec;

	scc_.width = basewidth_ /decimate_;
	scc_.height= baseheight_/decimate_;

	if(ioctl(fd,SCCSETGEO,&scc_)){
	  perror("ioctl");
	  exit(1);
	}

	setsize();
      }
    } else if (strcmp(argv[1], "format") == 0) {
      if (running_)
	format();
      return (TCL_OK);	
    } else if (strcmp(argv[1], "contrast") == 0) {
      contrast(atof(argv[2]));
      return (TCL_OK);	
    }
  }
  
  return (Grabber::command(argc, argv));

}

void SCCGrabber::SCCgrab()
{
  int i,j, yy, uv;
  int n=0;
  unsigned char *y,*u,*v;

  lseek(fd,0,SEEK_SET);
  read(fd,buf,inh_*inw_*2);

  y=frame_;
  u=frame_+outh_*outw_;

  if(cformat_ == CF_422)
    v=u+outh_*outw_/2;
  else
    v=u+outh_*outw_/4;

  switch(outw_){

  case NTSC_WIDTH/2 :

    for(i=0;i<outh_;i++)
      for(j=0;j<outw_;){

	yy = i*outw_+ j;
	uv = i*outw_/2+ j/2;

	y[yy]   = (unsigned char)((buf[(i+4)*inw_+j]&0xff00) >> 8); 
	u[uv]   = (unsigned char)((buf[(i+4)*inw_+j]&0x00ff) ^0x80) ;
	j++;
	y[yy+1] = (unsigned char)((buf[(i+4)*inw_+j]&0xff00) >> 8); 
	v[uv]   = (unsigned char)((buf[(i+4)*inw_+j]&0x00ff) ^0x80) ;
	j++;

      }
  
    break;

  case NTSC_WIDTH :
  case CIF_WIDTH/2 :
  case CIF_WIDTH :

    for(i=0;i<inh_;i++)
      for(j=0;j<inw_;){

	yy=(i+(outh_-inh_)/2)*outw_+(outw_-inw_)/2+j;

	if(cformat_ == CF_422)
	  uv=i*outw_/2+j/2;
	else
	  uv=i*outw_/4+j/2+(outh_-inh_)*outw_/8+(outw_-inw_)/4;

	if(!(i%2)){

	  y[yy]   = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	  u[uv]   = (unsigned char)((buf[i*inw_+j]&0x00ff) ^0x80);
	  j++;
	  y[yy+1] = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	  v[uv]   = (unsigned char)((buf[i*inw_+j]&0x00ff) ^0x80);
	  j++;

	} else {

	  if(cformat_==CF_422){

	    y[yy]   = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	    u[uv]   = (unsigned char)((buf[i*inw_+j]&0x00ff) ^0x80);
	    j++;
	    y[yy+1] = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	    v[uv]   = (unsigned char)((buf[i*inw_+j]&0x00ff) ^0x80);
	    j++;

	  }else{ // CF_CIF

	    y[yy]   = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	    j++;
	    y[yy+1] = (unsigned char)((buf[i*inw_+j]&0xff00) >> 8); 
	    j++;
	    
	  }
	}
      }
    break;
  }

}

int SCCGrabber::grab()
{

  SCCgrab();

  suppress(frame_);
  saveblks(frame_);
  YuvFrame f(media_ts(), frame_, crvec_, outw_, outh_);
  return (target_->consume(&f));
}

void SCCGrabber::setsize()
{

  switch(cformat_){
  case CF_422:
    set_size_422(basewidth_ / decimate_, baseheight_ / decimate_);
    break;
  case CF_CIF:
    set_size_cif(basewidth_ / decimate_, baseheight_ / decimate_);
    break;
  }

  allocref();
}

void SCCGrabber::format()
{
  setsize();
}
