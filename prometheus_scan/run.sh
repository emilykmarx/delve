#!/bin/bash -e

# Run from delve
set -x

set +e
pkill dlv
set -e
go install github.com/go-delve/delve/cmd/dlv
go build github.com/go-delve/delve/cmd/dlv/conftamer_main
pushd ../prometheus
go build -gcflags="all=-N -l" ./cmd/prometheus/

dlv --headless --api-version=2 --accept-multiclient --listen localhost:4040 \
  exec ./prometheus -- --config.file=../delve/prometheus_scan/self_scrape.yaml
popd


# Rest is manual for now
# 0. Wait for dlv to start listening
# 1. Start client (will continue target):
# ./conftamer_main --config=prometheus_scan/client_config.yaml
