#!/bin/sh

fullname="certcheck.c"
option="-lssl -lcrypto"
name=`echo $fullname | cut -d. -f1`

gcc -o $name $fullname $option
echo ========================
./$name ./sample_input.csv
