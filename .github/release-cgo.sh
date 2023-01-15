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

xgoTarget=windows/*,linux/*,darwin-10.16/*
xgoTags=with_gvisor,with_lwip
Ldflags="-X 'github.com/Dreamacro/clash/constant.Version=${VERSION}' -X 'github.com/Dreamacro/clash/constant.BuildTime=${BUILDTIME}' -w -s -buildid="

xgo  --branch ${BRANCH} --out=${BINDIR}/${NAME} --targets="${xgoTarget}" --tags="${xgoTags}" -ldflags="${Ldflags}" github.com/${REPO}