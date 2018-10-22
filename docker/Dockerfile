# Build the go binary
FROM golang:1.11-stretch as build

COPY ./src/. /lecert/src/

WORKDIR /lecert

ENV GOPATH /lecert

RUN go build playground/lecert

# Build a slim image with only the binary
FROM debian:stretch-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils apt-transport-https curl ca-certificates

# Even if you dont manually map a volume, docker will create an
# anonymouse volume with the certs.
VOLUME /certs
WORKDIR /lecert

COPY --from=build /lecert/lecert .
COPY docker/entrypoint.sh /

CMD /entrypoint.sh
