#!/bin/sh

# $Id$ 

#This script transforms the old <+ +> mod_dtcl tags into the new <? ?>
#tags.

#Run it in your server root directory.

for fn in `find . -name "*.ttml"` ;     
    do 
    echo -n "Editing $fn "
    sed -e 's/<+/<?/g' -e 's/+>/?>/g' $fn > $fn.new; 
    echo "... done"
    mv $fn.new $fn ; 
done

