# $Id$

## This originally was from the apache module makefile thing You may
## have to diddle with this yourself, unless you use the built in
## Apache config tools

# If you link against Tcl like so: "-ltcl", leave this blank.
TCL_VERSION=8.2

OPTIM=-O3
CC=gcc
CFLAGS_SHLIB=-fpic -DSHARED_MODULE
LDFLAGS_SHLIB=-Bshareable
CFLAGS1= -Wall -DLINUX=2 -DSTATUS -DNO_DBM_REWRITEMAP -DUSE_HSREGEX -fpic -DSHARED_CORE

CFLAGS=$(OPTIM) $(CFLAGS1) $(EXTRA_CFLAGS)
# You must change the following line unless you have the Debian apache-dev package
INCLUDES=-I/usr/include/apache-1.3/
LDFLAGS=$(LDFLAGS1) $(EXTRA_LDFLAGS)
INCDIR=$(SRCDIR)/include
SHLIBS= mod_dtcl.so
SHLIBS_OBJ= mod_dtcl-so.o

all: lib shlib

lib:	$(LIB)

shlib:	$(SHLIBS)

.SUFFIXES: .so

.c.so:
	$(CC) -g -c $(INCLUDES) $(CFLAGS) $(CFLAGS_SHLIB) $(SPACER) -DDTCL_VERSION=\"`cat VERSION`\" $< && mv $*.o $*-so.o
	$(LD) $(LDFLAGS_SHLIB) -o $@ $*-so.o -ltcl$(TCL_VERSION)

clean: 
	rm -f $(SHLIBS) $(SHLIBS_OBJ) $(LIB) $(SHLIB)

version: 
	./cvsversion.tcl

dist: clean version all
	(cd .. ; tar -czvf mod_dtcl-`cat mod_dtcl/VERSION`.tar.gz mod_dtcl/ ; )
