#!/bin/bash -e

# Script to scan caddy (TODO make this usable for arbitrary target)
# Run from delve
set -x

go install github.com/go-delve/delve/cmd/dlv
go build github.com/go-delve/delve/cmd/dlv/conftamer_main
pushd ../caddy/cmd/caddy
go build -gcflags="all=-N -l"

dlv --headless --api-version=2 --accept-multiclient --listen localhost:4040 \
 exec ./caddy -- run
popd


# Rest is manual for now
# 1. Start client (will continue caddy):
# ./conftamer_main --config=caddy_scan/client_config.yaml
# 2. Wait for caddy to say it's serving the admin endpoint (takes a second)
# 3. Load config:
# curl localhost:2019/load \
 #       -H "Content-Type: application/json" \
 #       -d @caddy.json
# 4. Ctrl-C the curl to avoid follow-on request to API endpoint (haven't invesitaged what it is)
