# 
# makefile for mod_dtcl and MingW32
# 

# 
# Global settings
#
# Tweak these as needed to match your environment
# Most of these variables can be set from the shell or command line
# 

# 
# Command line options differ for different versions of gcc
#
#GCCVER = 2
#
GCCVER = 3

#
# Threaded flag - set this and mod_dtcl will link against a 
# threaded version of Tcl.  You MUST build a threaded version of Tcl for
# this to work - ActiveState's binary Tcl distribution does not include 
# threads!
#
# This overrides the THREADED_TCL flag in mod_dtcl.h !
#
#THREADED ?= YES
#
# 
THREADED ?= NO

#
# I use this as a pointer to a good temporary location. 
# The default works for most people.  You won't need any of the cruft
# we create while building.
#
TEMP_LIBS ?= C:/TEMP

#
# Set this to your TCL version
#
# TCL_VERSION ?= 83
TCL_VERSION ?= 84

# 
# Set TCL_HOME to where you have installed Tcl
#
TCL_HOME ?= C:/"Program Files/Tcl8.4"

#
# Set this to where you have installed Apache - used for the install step.
#
APACHE_HOME ?= C:/"Program Files/Apache Group/Apache"

#
# Set APACHE_SRC to where your APACHE sources live.
# NOTE: You must apply the diff to the os.h file as described in the
# readme, and this directory must contain built sources, e.g. object files
# If you use a binary install of Apache just set this to the same location
# as APACHE_HOME like this:
#APACHE_SRC ?= $(APACHE_HOME)
#
APACHE_SRC ?= ../../apache

#
# Set APACHE_INC to where the Apache source include files live. This default
# should be OK if you built Apache from source.  If you used a binary install
# of Apache, you probably want something like this assuming you set APACHE_SRC
# as suggested above:
#APACHE_INC ?= -I $(APACHE_SRC)/include
#
APACHE_INC ?= -I $(APACHE_SRC)/src/include -I $(APACHE_SRC)/src/os/win32


#
# You shouldn't have to change anything below this
#
ROOT_DIR = ../
OUTPUT_DIR = ./output
TCL_INC = -I $(TCL_HOME)/include
APACHE_LIB ?= $(TEMP_LIBS) 
APACHE_DEF ?= $(TEMP_LIBS)/ApacheCore.def

ifeq ($(GCCVER), 3)
NATIVESTRUCT ?= -mms-bitfields
else
NATIVESTRUCT ?= -fnative-struct
endif

ifeq ($(THREADED), YES)
TCL_LIB = $(TCL_HOME)/lib/tcl$(TCL_VERSION)t.lib
CFLAGS = $(NATIVESTRUCT) -shared -mwindows -DSHARED_MODULE -DDTCL_VERSION="\"`cat $(ROOT_DIR)/VERSION`\"" -DTHREADED_TCL=1
else
TCL_LIB = $(TCL_HOME)/lib/tcl$(TCL_VERSION).lib
CFLAGS = $(NATIVESTRUCT) -shared -mwindows -DSHARED_MODULE -DDTCL_VERSION="\"`cat $(ROOT_DIR)/VERSION`\""
endif


CC = gcc $(CFLAGS)
LIBS = $(TCL_LIB) -L$(APACHE_LIB) -lapachecore
INCLUDES = $(TCL_INC) $(APACHE_INC)

APREQ_OBJECTS = apache_cookie.o apache_multipart_buffer.o apache_request.o
OBJECTS = tcl_commands.o parser.o channel.o $(APREQ_OBJECTS)

DLL_CFLAGS = -DEAPI=1
DLL_DYNAMIC = ApacheModuleDtcl.dll 
DLL_SO	= mod_dtcl.so
DLL_OBJS = mod_dtcl.o $(OBJECTS) 

#
# By default we build a .so file (Apache > 1.3.14)
#
# "make so_style" gives you a mod_dtcl.so file
# "make dll_style" gives you a ApacheModuleDtcl.dll
# "make bin_style" gives you a mod_dtcl.so and assumes you used a binary install
# of Apache

all : so_style 

bin_style:  APACHE_EXP=$(APACHE_HOME)/libexec/ApacheCore.exp
bin_style:	DLL_BUILD=$(DLL_SO)	
bin_style:	apache_libs $(DLL_SO)

dll_style:	APACHE_EXP=$(APACHE_SRC)/CoreR/ApacheCore.exp 
dll_style:	DLL_BUILD=$(DLL_DYNAMIC)
dll_style:	apache_libs $(DLL_DYNAMIC)

so_style:	APACHE_EXP=$(APACHE_SRC)/src/Release/ApacheCore.exp
so_style:	DLL_BUILD=$(DLL_SO)	
so_style:	apache_libs $(DLL_SO)

$(DLL_DYNAMIC):	$(OUTPUT_DIR) $(DLL_OBJS) makefile 
	$(CC) --dll --kill-at --disable-stdcall-fixup \
	$(DLL_OBJS) $(LIBS) -o $(OUTPUT_DIR)/$(DLL_DYNAMIC)

# 
# This does the same thing as the above, yet names the output file
# with a .so extension to match the "new" Apache style.
#
$(DLL_SO):	$(OUTPUT_DIR) $(DLL_OBJS) makefile
	$(CC) --dll --kill-at --disable-stdcall-fixup \
	$(DLL_OBJS) $(LIBS) -o $(OUTPUT_DIR)/$(DLL_SO)

$(OUTPUT_DIR):
	-@mkdir $(OUTPUT_DIR)

apache_cookie.o: $(ROOT_DIR)apache_cookie.c $(ROOT_DIR)apache_cookie.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
apache_multipart_buffer.o: $(ROOT_DIR)apache_multipart_buffer.c $(ROOT_DIR)apache_multipart_buffer.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
apache_request.o: $(ROOT_DIR)apache_request.c $(ROOT_DIR)apache_request.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
mod_dtcl.o: $(ROOT_DIR)mod_dtcl.c $(ROOT_DIR)mod_dtcl.h $(ROOT_DIR)tcl_commands.h $(ROOT_DIR)apache_request.h $(ROOT_DIR)parser.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -o $@ $<
tcl_commands.o: $(ROOT_DIR)tcl_commands.c $(ROOT_DIR)tcl_commands.h $(ROOT_DIR)mod_dtcl.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
parser.o: $(ROOT_DIR)parser.c $(ROOT_DIR)mod_dtcl.h $(ROOT_DIR)parser.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<
channel.o: $(ROOT_DIR)channel.c $(ROOT_DIR)mod_dtcl.h $(ROOT_DIR)channel.h
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -D_AP_OS_IS_PATH_ABS_ -o $@ $<

clean:
	-@rm -f $(DLL_OBJS) $(DLL_DYNAMIC) $(DLL_SO) 
	-@rm -rf $(OUTPUT_DIR)

install: 
	@echo Installing mod_dtcl...
	-@cp $(OUTPUT_DIR)/* $(APACHE_HOME)/modules

apache_libs:
	-@mkdir $(TEMP_LIBS)
	-@rm $(APACHE_DEF)
	echo EXPORTS > $(APACHE_DEF)
	nm $(APACHE_EXP) |grep " U _" | sed "s/.* U _//" >> $(APACHE_DEF)
	dlltool --def $(APACHE_DEF) --dllname ApacheCore.dll \
		--output-lib $(TEMP_LIBS)/libapachecore.a -k
	

