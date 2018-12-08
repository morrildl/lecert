# `lecert`: letsencrypt.org via Cloudflare DNS

This is a simple client for users of Cloudflare DNS, that implements the ACME DNS01 challenge
protocol using [letsencrypt.org](letsencrypt.org) as the CA, written in Go. The directory
`./playground/lecert` contains that code, and the directory `./docker` can construct a Docker
image for conveniently running it, for those who swing that way.

It also includes a related dynamc-DNS client to Cloudflare DNS, as `./playground/ddns`.

Special thanks to Playground Global, LLC for open-sourcing this software. See the `LICENSE` file
for details.

# Usage

Fetch the source:

    git clone --recursive https://github.com/morrildl/lecert

Build the binary:

    GOPATH=`pwd` go build src/playground/lecert/cmd/lecert.go

Create a config file using `./etc/config-example.json` as a starting point; enter your Cloudflare
account ID, etc.

Run the binary:

    ./lecert -config ./my-config.json

Usage is very similar for `ddns`. See `./docker/README.md` for details on the Docker container.