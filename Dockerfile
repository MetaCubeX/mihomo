FROM alpine:latest as builder
ARG TARGETPLATFORM
RUN echo "I'm building for $TARGETPLATFORM"

RUN apk add --no-cache gzip && \
    mkdir /mihomo-config && \
    wget -O /mihomo-config/geoip.metadb https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb && \
    wget -O /mihomo-config/geosite.dat https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat && \
    wget -O /mihomo-config/geoip.dat https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat

COPY docker/file-name.sh /mihomo/file-name.sh
WORKDIR /mihomo
COPY bin/ bin/
RUN FILE_NAME=`sh file-name.sh` && echo $FILE_NAME && \
    FILE_NAME=`ls bin/ | egrep "$FILE_NAME.gz"|awk NR==1` && echo $FILE_NAME && \
    mv bin/$FILE_NAME mihomo.gz && gzip -d mihomo.gz && chmod +x mihomo && echo "$FILE_NAME" > /mihomo-config/test
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/MetaCubeX/mihomo"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/mihomo/"]

COPY --from=builder /mihomo-config/ /root/.config/mihomo/
COPY --from=builder /mihomo/mihomo /mihomo
ENTRYPOINT [ "/mihomo" ]
