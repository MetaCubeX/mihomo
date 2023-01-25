#!/bin/sh
os="clash.meta-linux-"
arch=`uname -m`
case $arch in 
    "x86_64")
        arch="amd64-compatible"
        ;;
    "x86")
        arch="386-cgo"
        ;;
    "aarch64")
        arch="arm64"
        ;;
    "armv7l")
        arch="armv7"
        ;;
    "riscv64")
        arch="riscv64-cgo"
        ;;
    *)
        echo "Unknown architecture"
        exit 1
        ;;        
esac
file_name="$os$arch"
echo $file_name