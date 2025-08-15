#!/bin/bash -e

# Run from delve
set -x

#go install github.com/go-delve/delve/cmd/dlv
go build github.com/go-delve/delve/cmd/dlv/conftamer_main
pushd ../prometheus
#go build -gcflags="all=-N -l" ./cmd/prometheus/

dlv --check-go-version=false --headless --api-version=2 --accept-multiclient --listen localhost:4040 \
  exec ./prometheus -- --config.file=conftamer/self_scrape.yml
popd


# Rest is manual for now
# 0. Wait for dlv to start listening
# 1. Start client (will continue target):
# ./conftamer_main --config=prometheus_scan/client_config.yaml
