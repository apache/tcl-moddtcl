#!/bin/sh
# $Id$

# Name of tclsh - on FreeBSD, this is probably tclsh8.2
TCLSH=tclsh  ######### CHANGEME ##########
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
TCLSH=`which $TCLSH`

if [ "$TCLSH" = "" ]
    then
    echo "No tclsh executable, please edit builddtcl.sh"
    exit 1
fi

TCLSHEXIST=`echo "puts helloworld" | $TCLSH`
if [ "$TCLSHEXIST" != "helloworld" ]
    then
    echo "Tclsh is not $TCLSH, please edit builddtcl.sh"
    exit 1
    else
    echo "Using $TCLSH as tclsh program"
fi

# Location of Apache source install (for static installs - you can
# comment this out for shared lib installs
export APACHE=$HOME/download/apache-1.3/  ######### CHANGEME ##########
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# APACHE=/usr/local/src/apache-1.3/
APACHE=/

if [ -d $APACHE ]
    then
    echo "Apache in $APACHE"
    else
    echo "Apache NOT in $Apache, please edit builddtcl.sh"
    exit 1
fi

# Location of Apache include files.
INC=/usr/include/apache-1.3/  ######### CHANGEME ##########
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# INC=$APACHE/src/include

if [ -f $INC/httpd.h ] 
    then
    echo "Apache includes in $INC"
    export INCLUDES="-I$INC -I$APACHE/src/os/unix/"
    else
    echo "Apache include files *not* in $INC, please edit builddtcl.sh"
    exit 1
fi

# find location of tclConfig.sh, source it, and export variables to
# make them available to 'make'

export CONFIG=`$TCLSH ./findconfig.tcl`
echo "Using tclConfig.sh: $CONFIG"
. $CONFIG

export TCL_CC
export TCL_CFLAGS_DEBUG 
export TCL_CFLAGS_OPTIMIZE 
export TCL_CFLAGS_WARNING 
export TCL_EXTRA_CFLAGS
export TCL_LIBS
export TCL_LIB_FLAG 
export TCL_LIB_SPEC
export TCL_SHLIB_CFLAGS
export TCL_SHLIB_LD
export TCL_SHLIB_SUFFIX
export TCL_STLIB_LD 

export BUILDDTCL="YES"
#export C_INCLUDE_PATH

# pass the first argument to make
make -e $1

