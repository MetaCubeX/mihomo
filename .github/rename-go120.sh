#!/bin/bash

FILENAMES=$(ls)
for FILENAME in $FILENAMES
do
    if [[ ! ($FILENAME =~ ".exe" || $FILENAME =~ ".sh")]];then
        mv $FILENAME ${FILENAME}-go120
    elif [[ $FILENAME =~ ".exe" ]];then
        mv $FILENAME ${FILENAME%.*}-go120.exe
    else echo "skip $FILENAME"
    fi
done