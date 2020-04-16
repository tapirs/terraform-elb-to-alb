FROM golang:1.14-alpine

RUN apk add -U --no-cache ca-certificates

ARG ZSCALER_CERT

RUN echo "$ZSCALER_CERT" > /usr/local/share/ca-certificates/zscaler.crt

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN update-ca-certificates --verbose

RUN apk add -U --no-cache git

ENV GO111MODULE=on
