# Let's Encrypt Cert Generator

### Update git submodules
```
$ git submodule init
$ git submodule sync
```

### Setup environment variables.
Create a file `docker/.env` with contents
```
export FQDN=""
export ACCOUNT_EMAIL=""
export CLOUDFLARE_EMAIL=""
export CLOUDFLARE_SECRET=""
export CLOUDFLARE_ZONE_ID=""
```

### Load environment variables
```
$ source docker/.env
```

### Build docker image
```
$ cd docker
$ docker-compose build
```

### Start docker container
```
$ cd docker
$ docker-compose up -d
```

### Getting a copy of the certs.
* Spin up a container just to mount up the volume
```
$ docker run --rm -it --name certs -v ssl_certs:/certs debian:stretch-slim /bin/bash
root@e94cec4c9352:/# ls /certs
account.json  account.key  talent.playground.global.crt talent.playground.global.key
```

* In another terminal, copy the files out.
```
$ mkdir /tmp/erase
$ cd /tmp/erase
/tmp/erase $ docker cp certs:/certs/. .
/tmp/erase $ ls
account.json                    account.key                     talent.playground.global.crt    talent.playground.global.key
```
