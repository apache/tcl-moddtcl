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
APACHE=$HOME/download/apache-1.3/  ######### CHANGEME ##########
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# APACHE=/usr/local/src/apache-1.3/
APACHE=/

export APACHE

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
    INCLUDES="-I$INC" ; export INCLUDES
    else
    echo "Apache include files *not* in $INC, please edit builddtcl.sh"
    exit 1
fi

# find location of tclConfig.sh, source it, and export variables to
# make them available to 'make'

CONFIG=`$TCLSH ./findconfig.tcl` ; export CONFIG
echo "Using tclConfig.sh: $CONFIG"
. $CONFIG

TCL_CC ; export TCL_CC
TCL_CFLAGS_DEBUG  ; export TCL_CFLAGS_DEBUG 
TCL_CFLAGS_OPTIMIZE  ; export TCL_CFLAGS_OPTIMIZE 
TCL_CFLAGS_WARNING  ; export TCL_CFLAGS_WARNING 
TCL_EXTRA_CFLAGS ; export TCL_EXTRA_CFLAGS
TCL_LIBS ; export TCL_LIBS
TCL_LIB_FLAG  ; export TCL_LIB_FLAG 
TCL_LIB_SPEC ; export TCL_LIB_SPEC
TCL_PREFIX ; export TCL_PREFIX
TCL_SHLIB_CFLAGS ; export TCL_SHLIB_CFLAGS
TCL_SHLIB_LD ; export TCL_SHLIB_LD
TCL_SHLIB_SUFFIX ; export TCL_SHLIB_SUFFIX
TCL_STLIB_LD  ; export TCL_STLIB_LD 
TCL_SRC_DIR ; export TCL_SRC_DIR

BUILDDTCL="YES" ; export BUILDDTCL
#export C_INCLUDE_PATH

# pass the first argument to make
make -e $1

