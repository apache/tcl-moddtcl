#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# This is an attempt to duplicate the dtcl parser in pure Tcl.  It is
# not currently complete.

# $Id$

set buffer ""

proc dtcl_info { } {
}

proc buffered { x } {
}

proc headers { args } {    
}

proc include { filename } {
    set fl [ open $filename ]
    fconfigure $fl -translation binary
    puts -nonewline [ read $fl ]
    close $fl
}

proc parse { filename } {
    main $filename 0
}

proc hflush { } {
}

proc no_body { } {
}

proc hgetvars { } {
    array set ENVS {x y}
    array set VARS {a b}
}

proc buffer_add { x } {
    puts -nonewline "$x"
}

proc hputs { x } {
    puts -nonewline "$x"
}

proc accumulate { x } {
    global buffer
    append buffer $x
}

proc main { filename toplevel } {
    global buffer
    set fl [ open $filename ]

    if { $toplevel != 1 } {
	accumulate "namespace eval request \{\n"
	accumulate "buffer_add \"\n"
    } else {
	accumulate "hputs \"\n"
    }
    set inside 0
    while { 1 } {
	if { [ eof $fl ] } { break }
	set char [ read $fl 1 ]
	if { $inside == 0 } { 
	    if { $char == "<" } { 
		set char2 [ read $fl 1 ]
		if { $char2 == "?" } {
		    set inside 1
		    accumulate "\"\n"
		} else {
		    set char2 [ string map {\$ \\\$ \" \\\" [ \\\[ ] \\\] \\ \\\\} $char2 ]
		    accumulate "<$char2"
		}
	    } else {
		set char [ string map {\$ \\\$ \" \\\" [ \\\[ ] \\\] \\ \\\\} $char ]
		accumulate "$char"
	    }
	} else {
	    if { $char == "?" } { 
		set char2 [ read $fl 1 ]	    
		if { $char2 == ">" } {
		    accumulate "\nhputs \"\n"
		    set inside 0
		} else {
		    accumulate "+$char2"
		}	    
	    } else {
		accumulate "$char"		
	    }
	}
    }
    if { $inside == 0 } {
	accumulate "\""
    }
    if { $toplevel != 1 } {
	accumulate "\n\}\nnamespace delete request\n"
    }
#    puts "$buffer"
    catch { eval "$buffer" } err
    if { $err != "" } { 
	puts $err
	puts "------------"
	puts "$buffer" 
    }
}

main [ lindex $argv 0 ] 1
