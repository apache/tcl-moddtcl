# 
# makefile for mod_dtcl and MingW32
#
# 

CC = gcc -O3

# 
# Set TCL_HOME to where you have installed Tcl
#
TCL_HOME = c:\progra~1\tcl
TCL_INC = $(TCL_HOME)\include
TCL_LIB = $(TCL_HOME)\lib

#
# Set this to your TCL version
#
TCL_VERSION = 83

#
# Set this to where you have installed Apache 
#
APACHE_HOME = c:\progra~1\apache~1\apache
APACHE_INC = $(APACHE_HOME)\src\include
APACHE_LIB = $(APACHE_HOME)\src\lib

INCLUDES = -I$(TCL_INC) -I$(APACHE_INC)

LIBS = -L$(TCL_LIB) -ltcl$(TCL_VERSION) -L$(APACHE_LIB) -lapachecore

DLL_CFLAGS = -DEAPI=1

DLL_EXP_LIB = libmod_dtcl.a
DLL_EXP_DEF = mod_dtcl.def
DLL_DYNAMIC = ApacheModuleDtcl.dll
DLL_OBJS = mod_dtcl.o

DLLWRAP_FLAGS = --def $(DLL_EXP_DEF) \
	--implib $(DLL_EXP_LIB) \
	--driver-name $(CC)

all :	$(DLL_DYNAMIC) $(DLL_EXP_LIB)

$(DLL_DYNAMIC) $(DLL_EXP_LIB): $(DLL_OBJS) makefile
	dllwrap $(DLLWRAP_FLAGS) -o $@ $< $(LIBS)

%.o: %.c
	$(CC) -c $(DLL_CFLAGS) $(INCLUDES) -o $@ $<

clean:
	-rm -f $(DLL_OBJS) $(DLL_DYNAMIC) $(DLL_EXP_LIB)

install: $(DLL_DYNAMIC) $(DLL_EXP_LIB)
	echo Installing mod_dtcl...
	-cp $(DLL_DYNAMIC) $(APACHE_HOME)\modules
	

