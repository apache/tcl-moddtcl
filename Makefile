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
MFLAGS_STATIC=--no-print-directory

CFLAGS=$(OPTIM) $(CFLAGS1) $(EXTRA_CFLAGS)
# You must change the following line unless you have the Debian apache-dev package
INCLUDES=-I/usr/include/apache-1.3/
LDFLAGS=$(LDFLAGS1) $(EXTRA_LDFLAGS)
INCDIR=$(SRCDIR)/include
SHLIBS= mod_dtcl.so
SHLIBS_OBJ= mod_dtcl-so.o

all: lib shlib

other: all txt testdtcl 

extra: other code2html

lib:	$(LIB)

shlib:	$(SHLIBS)


.SUFFIXES: .o .so

.c.o:
	$(CC) -g -c $(INCLUDES) $(CFLAGS) $(SPACER) $<

.c.so:
	$(CC) -g -c $(INCLUDES) $(CFLAGS) $(CFLAGS_SHLIB) $(SPACER)  $< && mv $*.o $*-so.o
	$(LD) $(LDFLAGS_SHLIB) -o $@ $*-so.o -ltcl$(TCL_VERSION)

clean: txtclean
	rm -f $(SHLIBS) $(SHLIBS_OBJ) $(LIB) $(SHLIB)
	-rm testdtcl

testdtcl: testdtcl.c
	$(CC) -g -o testdtcl -O3 testdtcl.c -ltcl$(TCL_VERSION) -DDEBUG_SCRIPT_DIR=\"$(DEBUG_SCRIPT_DIR)\"

txtclean:
	-rm readme.txt INSTALL.txt dtcl-tcl.txt use.txt

txt: readme.txt INSTALL.txt dtcl-tcl.txt use.txt TODO.txt readme.hpux.txt

readme.hpux.html: readme.hpux.txt
	lynx -dump readme.hpux.html > readme.hpux.txt

readme.txt: readme.html
	lynx  -dump readme.html > readme.txt

INSTALL.txt: INSTALL.html
	lynx  -dump INSTALL.html > INSTALL.txt

dtcl-tcl.txt: dtcl-tcl.html
	lynx  -dump dtcl-tcl.html > dtcl-tcl.txt

use.txt: use.html
	lynx  -dump use.html > use.txt

TODO.txt: TODO.html
	lynx -dump TODO.html > TODO.txt

readme.hpux.txt: readme.hpux.html
	lynx -dump readme.hpux.html > readme.hpux.txt

# Need to be running under X for this to work!
code2html: font-lock-stuff.el
	if [ -n "$$DISPLAY" ] ; then emacs -r -l font-lock-stuff.el -f flscreate --kill ; fi

code2htmlclean:
	emacs -r -l font-lock-stuff.el -f flsclean -kill