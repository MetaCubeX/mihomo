FROM golang:alpine as builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache make git && \
    mkdir /clash-config && \
    wget -O /clash-config/Country.mmdb https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb && \
    wget -O /clash-config/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat && \
    wget -O /clash-config/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

WORKDIR /clash-src
COPY . /clash-src
RUN go mod download
RUN /bin/ash -c 'set -ex && \
    if [ "$TARGETARCH" == "amd64" ]; then \
       GOOS=$TARGETOS GOARCH=$TARGETARCH GOAMD64=v1 make docker && \
       mv ./bin/Clash.Meta-docker ./bin/clash-amd64v1 && \
       GOOS=$TARGETOS GOARCH=$TARGETARCH GOAMD64=v2 make docker && \
       mv ./bin/Clash.Meta-docker ./bin/clash-amd64v2 && \
       GOOS=$TARGETOS GOARCH=$TARGETARCH GOAMD64=v3 make docker && \
       mv ./bin/Clash.Meta-docker ./bin/clash-amd64v3 && \
       ln -s clash-amd64v3 ./bin/clash-amd64v4 && \
       mv check_amd64.sh ./bin/ && \
       printf "#!/bin/sh\\nsh ./check_amd64.sh\\nexec ./clash-amd64v\$? \$@" > ./bin/clash && \
       chmod +x ./bin/check_amd64.sh ./bin/clash; \
    else \
       GOOS=$TARGETOS GOARCH=$TARGETARCH make docker && \
       mv ./bin/Clash.Meta-docker ./bin/clash; \
    fi'
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/MetaCubeX/Clash.Meta"

RUN apk add --no-cache ca-certificates tzdata

VOLUME ["/root/.config/clash/"]
EXPOSE 7890/tcp

COPY --from=builder /clash-config/ /root/.config/clash/
COPY --from=builder /clash-src/bin/ /
ENTRYPOINT [ "/clash" ]