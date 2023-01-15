#!/bin/bash

BRANCH=$(git branch --show-current)
if [ "$BRANCH" = "Alpha" ];then
  VERSION=alpha-$(git rev-parse --short HEAD)
elif [ "$BRANCH" = "Beta" ]; then
  VERSION=beta-$(git rev-parse --short HEAD)
elif [ "$BRANCH" = "" ]; then
  VERSION=$(git describe --tags)
else
  VERSION=$(git rev-parse --short HEAD)
fi

CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
Ldflags="-X 'github.com/Dreamacro/clash/constant.Version=${VERSION}' -X 'github.com/Dreamacro/clash/constant.BuildTime=${BUILDTIME}' -w -s -buildid="

CGO_ENABLED=1 go build -tags with_gvisor,with_lwip -trimpath -ldflags "${Ldflags}" -o bin/clash.meta-android-arm64