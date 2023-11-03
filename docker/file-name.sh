#!/bin/sh
os="mihomo-linux-"
case $TARGETPLATFORM in
    "linux/amd64")
        arch="amd64-compatible"
        ;;
    "linux/386")
        arch="386"
        ;;
    "linux/arm64")
        arch="arm64"
        ;;
    "linux/arm/v7")
        arch="armv7"
        ;;
    "riscv64")
        arch="riscv64"
        ;;
    *)
        echo "Unknown architecture"
        exit 1
        ;;        
esac
file_name="$os$arch-$(cat bin/version.txt)"
echo $file_name