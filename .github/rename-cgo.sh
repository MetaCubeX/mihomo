#!/bin/bash

FILENAMES=$(ls)
for FILENAME in $FILENAMES
do
    if [[ $FILENAME =~ "darwin-10.16-arm64" ]];then
        echo "rename darwin-10.16-arm64 $FILENAME"
        mv $FILENAME clash.meta-darwin-arm64-cgo-${VERSION}-${ShortSHA}
    elif [[ $FILENAME =~ "darwin-10.16-amd64" ]];then
        echo "rename darwin-10.16-amd64 $FILENAME"
        mv $FILENAME clash.meta-darwin-amd64-cgo-${VERSION}-${ShortSHA}
    elif [[ $FILENAME =~ "windows-4.0-386" ]];then
        echo "rename windows 386 $FILENAME"
        mv $FILENAME clash.meta-windows-386-cgo-${VERSION}-${ShortSHA}.exe
    elif [[ $FILENAME =~ "windows-4.0-amd64" ]];then
        echo "rename windows amd64 $FILENAME"
        mv $FILENAME clash.meta-windows-amd64-cgo-${VERSION}-${ShortSHA}.exe
    elif [[ $FILENAME =~ "linux" ]];then
        echo "rename linux $FILENAME"
        mv $FILENAME $FILENAME-cgo-${VERSION}-${ShortSHA}
    elif [[ $FILENAME =~ "android" ]];then
        echo "rename android $FILENAME"
        mv $FILENAME $FILENAME-cgo-${VERSION}-${ShortSHA}
    else echo "skip $FILENAME"
    fi
done

FILENAMES=$(ls)
for FILENAME in $FILENAMES
do
    if [[ ! ($FILENAME =~ ".exe" || $FILENAME =~ ".sh")]];then
        gzip -S ".gz" $FILENAME
    elif [[ $FILENAME =~ ".exe" ]];then
        zip -m $FILENAME.zip $FILENAME
    else echo "skip $FILENAME"
    fi
done