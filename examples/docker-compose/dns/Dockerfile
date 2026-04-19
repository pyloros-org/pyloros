FROM alpine:3.21
RUN apk add --no-cache dnsmasq
ENTRYPOINT ["dnsmasq", "-k", "--no-resolv"]
