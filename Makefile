# $Id$

# Changed to use the Tcl variables from tclConfig.sh

# You may have to change these if 'builddtcl.sh' and 'findconfig.tcl'
# don't work.

# You must change the following line unless you have the Debian
# apache-dev package

INC=$(INCLUDES) -I$(TCL_PREFIX)/include

STATICLIB=mod_dtcl.a
SHLIB=mod_dtcl$(TCL_SHLIB_SUFFIX)

APREQ_OBJECTS=apache_cookie.o apache_multipart_buffer.o apache_request.o
OBJECTS=mod_dtcl.o tcl_commands.o $(APREQ_OBJECTS)

# The following TCL_* variables are all exported from builddtcl.sh

COMPILE=$(TCL_CC) $(TCL_CFLAGS_DEBUG) $(TCL_CFLAGS_OPTIMIZE) $(TCL_CFLAGS_WARNING) $(TCL_SHLIB_CFLAGS) -c $(INC) $(CFLAGS) $(TCL_EXTRA_CFLAGS) $(EXTRA_FLAGS) $<

all: builddtcl_test shared

static: $(OBJECTS) docs/documentation.txt
	$(TCL_STLIB_LD) $(STATICLIB) $(OBJECTS) 

shared: $(OBJECTS) docs/documentation.txt
	$(TCL_SHLIB_LD) -o $(SHLIB) $(OBJECTS) $(TCL_LIB_SPEC) $(TCL_LIBS)

# I don't have too many C files, so it's just clearer to do things by
# hand

apache_cookie.o: apache_cookie.c apache_cookie.h
	$(COMPILE)
apache_multipart_buffer.o: apache_multipart_buffer.c apache_multipart_buffer.h
	$(COMPILE)
apache_request.o: apache_request.c apache_request.h
	$(COMPILE)
mod_dtcl.o: mod_dtcl.c mod_dtcl.h tcl_commands.h apache_request.h
	$(COMPILE) -DDTCL_VERSION=`cat VERSION`
tcl_commands.o: tcl_commands.c tcl_commands.h mod_dtcl.h
	$(COMPILE)

clean: 
	-rm -f $(STATICLIB) $(SHLIB) *.o *~ docs/documentation.txt

version: 
	./cvsversion.tcl

docs/documentation.txt:
	if test -x `which lynx` ; then 	lynx -dump ./docs/documentation.html > ./docs/documentation.txt ; else echo "You need lynx to create documentation.txt from documentation.html" ; fi

dist: clean docs/documentation.txt version
	(cd .. ; tar -czvf mod_dtcl-`cat mod_dtcl/VERSION`.tar.gz mod_dtcl/ ; )

install: static
	-mkdir $(APACHE)src/modules/mod_dtcl/
	cp $(STATICLIB) $(APACHE)src/modules/mod_dtcl/
	cp Makefile.dummy $(APACHE)src/modules/mod_dtcl/Makefile

# This forces mod_dtcl to be built with the shell script, so please
# comment it out if you need to.

.SILENT: builddtcl_test
builddtcl_test:
	if [ "$(BUILDDTCL)" != "YES" ] ; then echo "You should use builddtcl.sh to build mod_dtcl"; exit 1 ; fi