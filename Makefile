# $Id$

# Changed to use the Tcl variables from tclConfig.sh

# You may have to change these if 'builddtcl.sh' and 'findconfig.tcl'
# don't work.

TCL_LIB=$(TCL_LIB_FLAG)
OPTIM=$(TCL_CFLAGS_OPTIMIZE)
CC=$(TCL_CC)
CFLAGS_SHLIB=$(TCL_SHLIB_CFLAGS) -DSHARED_MODULE
LDFLAGS_SHLIB=-Bshareable

DEBUG=-g
CFLAGS=-Wall $(OPTIM) $(EXTRA_CFLAGS)
# You must change the following line unless you have the Debian apache-dev package
INCLUDES=-I/usr/include/apache-1.3/
INCDIR=$(SRCDIR)/include
STATICLIB=mod_dtcl.a
SHLIB=mod_dtcl.so

all: builddtcl_test lib shlib

static: lib
lib: $(STATICLIB)

.c.a:
	$(CC) $(DEBUG) -c $(INCLUDES) $(CFLAGS) -DDTCL_VERSION=\"`cat VERSION`\" $<
	ar cr $(STATICLIB) $*.o

shared: shlib
shlib: $(SHLIB)

.SUFFIXES: .so .a

.c.so:
	$(CC) $(DEBUG) -c $(INCLUDES) $(CFLAGS) $(CFLAGS_SHLIB) -DDTCL_VERSION=\"`cat VERSION`\" $< && mv $*.o $*-so.o
	$(LD) $(LDFLAGS_SHLIB) -o $@ $*-so.o $(TCL_LIB)

clean: 
	-rm -f $(STATICLIB) $(SHLIB) *.o *~

version: 
	./cvsversion.tcl

dist: clean version
	(cd .. ; tar -czvf mod_dtcl-`cat mod_dtcl/VERSION`.tar.gz mod_dtcl/ ; )

install: lib
	-mkdir $(APACHE)src/modules/mod_dtcl/
	cp $(STATICLIB) $(APACHE)src/modules/mod_dtcl/
	cp Makefile.dummy $(APACHE)src/modules/mod_dtcl/Makefile


# This forces mod_dtcl to be built with the shell script, so please
# comment it out if you need to.

.SILENT: builddtcl_test
builddtcl_test:
	if [ "$(BUILDDTCL)" != "YES" ] ; then echo "You should use builddtcl.sh to build mod_dtcl"; exit 1 ; fi