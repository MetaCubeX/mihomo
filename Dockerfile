FROM golang:latest as builder
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz -O /tmp/GeoLite2-Country.tar.gz && \
    tar zxvf /tmp/GeoLite2-Country.tar.gz -C /tmp && \
    cp /tmp/GeoLite2-Country_*/GeoLite2-Country.mmdb /Country.mmdb
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
    mkdir -p /go/src/github.com/Dreamacro/clash
WORKDIR /go/src/github.com/Dreamacro/clash
COPY . /go/src/github.com/Dreamacro/clash
RUN dep ensure && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-w -s' -o /clash && \
    chmod +x /clash

FROM alpine:latest
RUN apk --no-cache add ca-certificates && \
    mkdir -p /root/.config/clash
COPY --from=builder /clash .
COPY --from=builder /Country.mmdb /root/.config/clash/
EXPOSE 7890 7891
ENTRYPOINT ["/clash"]
