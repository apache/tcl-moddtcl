# $Id$
# takes a list of lists and transforms it:

#|heading1| |heading2| |heading3|
#|data1|    |data2|    |data3|
#|data4|    |data5|    |data6|

# becomes

#|heading1| |data1| |data4|
#|heading2| |data2| |data5|
#|heading3| |data3| |data6|

proc tabletransform { lol } { 
    set transformed_list [ list ]
    set sz [ llength [ lindex $lol 1 ] ]
    for {set i 0} {$i < 3} {incr i} {
	lappend transformed_list [ list ]
    }
    foreach l1 $lol {
	set i 0
	foreach l2 $l1 {
	    set ll [ concat [ lindex $transformed_list $i ] [list $l2 ] ]
	    set transformed_list [ lreplace $transformed_list $i $i $ll ]
	    incr i
	}
    }
    return $transformed_list
}
