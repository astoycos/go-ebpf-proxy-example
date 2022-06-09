#!/bin/sh
set -xe

echo ${1}
if ! $(command -v bpf2go >/dev/null 2>&1)
 then go install github.com/cilium/ebpf/cmd/bpf2go@master
fi
go generate ./
go build
sudo ${1} kill server || true && sudo $1 rm server || true
sudo ${1} run --name server -d -p 8080:80 nginx
serverIP=$(sudo ${1} inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)
sudo ./go-ebpf-proxy-example 169.1.1.1 ${serverIP}