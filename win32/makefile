# 
# makefile for mod_dtcl and MingW32
# 
# 

#
# I use this as a pointer to a good temporary location. 
# The default works for most people
#
TEMP_LIBS = C:\\TEMP

#
# Set this to your TCL version
#
TCL_VERSION = 83

# 
# Set TCL_HOME to where you have installed Tcl
#
TCL_HOME = C:\\Progra~1\\Tcl
TCL_INC = $(TCL_HOME)\\include
TCL_LIB = $(TCL_HOME)\\lib

#
# Set this to where you have installed Apache - used for the install step.
#
APACHE_HOME = C:\\"Program Files\\Apache Group\\Apache"

#
# Set APACHE_SRC to where your APACHE sources live.
# NOTE: You must apply the diff to the os.h file as described in the
# readme, and this directory must contain built sources, e.g. object files
#
APACHE_SRC = ..\\apache

#
# Set APACHE_INC to where the APACHE source include files live. This default
# should be OK.
#
APACHE_INC = $(APACHE_SRC)\\src\\include

#
# Set APACHE_LIB and APACHE_DEF to where you'd like a MingW32 compatible
# APACHE library file and DLL DEF file put.  You normally only need these
# during a build, so a temporary location is OK
#
APACHE_LIB = $(TEMP_LIBS) 
APACHE_DEF = $(TEMP_LIBS)\\ApacheCore.def


#
# You shouldn't have to change anything below this
#
ROOT_DIR = ..\\

CC = gcc -O3 -fnative-struct -shared -mwindows -DSHARED_MODULE -DDTCL_VERSION="\"`cat $(ROOT_DIR)\\VERSION`\""

INCLUDES = -I$(TCL_INC) -I$(APACHE_INC)
LIBS = $(TCL_LIB)\\tcl$(TCL_VERSION).lib -L$(APACHE_LIB) -lapachecore 

APREQ_OBJECTS = apache_cookie.o apache_multipart_buffer.o apache_request.o
OBJECTS = tcl_commands.o $(APREQ_OBJECTS)

DLL_CFLAGS = -DEAPI=1

DLL_EXP_LIB = libmod_dtcl.a
DLL_EXP_DEF = mod_dtcl.def
DLL_DYNAMIC = ApacheModuleDtcl.dll 
DLL_SO	= mod_dtcl.so
DLL_OBJS = mod_dtcl.o $(OBJECTS) 

DLLWRAP_FLAGS = --def $(DLL_EXP_DEF) \
	--implib $(DLL_EXP_LIB) \
	--driver-name $(CC)

#
# By default we build a .dll file (Apache < 1.3.14)
#
all : apache_libs $(DLL_DYNAMIC)

dll_style: apache_libs $(DLL_DYNAMIC)

so_style:	apache_libs $(DLL_SO)

$(DLL_DYNAMIC):	$(DLL_OBJS) makefile
	$(CC) --dll --kill-at --disable-stdcall-fixup \
		-o $(DLL_DYNAMIC) $(DLL_OBJS) $(LIBS)

# 
# This does the same thing as the above, yet names the output file
# with a .so extension to match the "new" Apache style.
#
$(DLL_SO):	$(DLL_OBJS) makefile
	$(CC) --dll --kill-at --disable-stdcall-fixup \
		-o $(DLL_SO) $(DLL_OBJS) $(LIBS)

apache_cookie.o: $(ROOT_DIR)apache_cookie.c $(ROOT_DIR)apache_cookie.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
apache_multipart_buffer.o: $(ROOT_DIR)apache_multipart_buffer.c $(ROOT_DIR)apache_multipart_buffer.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
apache_request.o: $(ROOT_DIR)apache_request.c $(ROOT_DIR)apache_request.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
mod_dtcl.o: $(ROOT_DIR)mod_dtcl.c $(ROOT_DIR)mod_dtcl.h $(ROOT_DIR)tcl_commands.h $(ROOT_DIR)apache_request.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -o $@ $<
tcl_commands.o: $(ROOT_DIR)tcl_commands.c $(ROOT_DIR)tcl_commands.h $(ROOT_DIR)mod_dtcl.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<

clean:
	-@rm -f $(DLL_OBJS) $(DLL_DYNAMIC) $(DLL_SO) $(DLL_EXP_LIB)

install: $(DLL_DYNAMIC) $(DLL_EXP_LIB)
	echo Installing mod_dtcl...
	-cp $(DLL_DYNAMIC) $(APACHE_HOME)\\modules

apache_libs:
	-@mkdir $(TEMP_LIBS)
	-@rm $(APACHE_DEF)
	echo EXPORTS > $(APACHE_DEF)
	nm $(APACHE_SRC)\\src\\CoreR\\ApacheCore.exp |grep " U _" | sed "s/.* U _//" >> $(APACHE_DEF)
	sed -e "s/ap_log_error$$/ap_log_error@0/g" \
		-e "s/ap_log_rerror$$/ap_log_rerror@0/g" \
		-e "s/ap_table_do$$/ap_table_do@0/g" \
		$(APACHE_DEF) > $(APACHE_DEF).new
	mv $(APACHE_DEF).new $(APACHE_DEF)
	dlltool --def $(APACHE_DEF) --dllname ApacheCore.dll \
		--output-lib $(TEMP_LIBS)\libapachecore.a -k
	