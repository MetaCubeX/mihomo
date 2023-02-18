FROM alpine:latest as builder

RUN apk add --no-cache gzip && \
    mkdir /clash-config && \
    wget -O /clash-config/Country.mmdb https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb && \
    wget -O /clash-config/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat && \
    wget -O /clash-config/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

COPY docker/file-name.sh /clash/file-name.sh
WORKDIR /clash
COPY bin/ bin/
RUN FILE_NAME=`sh file-name.sh` && echo $FILE_NAME && \
    FILE_NAME=`ls bin/ | egrep "$FILE_NAME.*"|awk NR==1` && \
    mv bin/$FILE_NAME clash.gz && gzip -d clash.gz && echo "$FILE_NAME" > /clash-config/test
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/MetaCubeX/Clash.Meta"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/clash/"]

COPY --from=builder /clash-config/ /root/.config/clash/
COPY --from=builder /clash/clash /clash
RUN chmod +x /clash
ENTRYPOINT [ "/clash" ]
