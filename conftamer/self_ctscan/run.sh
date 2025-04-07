#!/bin/bash -e

# Script to allow manually CT-scanning dlv itself
set -x

# Run from delve root (assumes some absolute paths)
DIR=/home/emily/projects/config_tracing/delve/conftamer/self_ctscan
SCANNEE_DIR=$DIR/scannee

# 1. Set up configs: each dlv points to its target's
# Target => own config
# $SCANNEE_DIR/dlv/target_config.txt: param1\nparam2

# CT-scannee (child) dlv => target's config
# $SCANNEE_DIR/dlv/config.yml:
# target-config-files: ["$SCANNEE_DIR/dlv/target_config.txt"]

# CT-scanner (parent) dlv => CT-scannee's config
# ~/.config/dlv/config.yml:
# target-config-files: ["$SCANNEE_DIR/dlv/config.yml"]

# 2. Build and install dlv and client
go build -gcflags="all=-N -l" github.com/go-delve/delve/cmd/dlv
go install github.com/go-delve/delve/cmd/dlv
go build github.com/go-delve/delve/cmd/dlv/conftamer_main

# 3. Build target
/home/emily/projects/wtf_project/go1.20.1/bin/go build -gcflags="all=-N -l"  ./_fixtures/conftamer/load_config_param.go

# 4. Run built dlv with installed dlv. Point all 3 processes to their configs

# TODO use FollowExec (likely needs a fix due to my changes to dlv) -
# until then, set a watchpoint manually on CT-scannee's config (since it's read in before we attach)

# 4a. Launch CT-scannee.
# Scannee will read in its config (LoadConfig()), and create target process (Launch()).
# Target will not yet read its config (since it's not running)
config=$SCANNEE_DIR/dlv/target_config.txt XDG_CONFIG_HOME=$SCANNEE_DIR \
 ./dlv exec --headless --api-version=2 --accept-multiclient --listen localhost:4040 ./load_config_param

## Rest is manual for now

# 4b. Launch CT-scanner and attach to CT-scannee
# dlv attach --headless --api-version=2 --accept-multiclient --listen localhost:4041 $(pgrep dlv)

# 4c. Set initial watchpoint for scannee - for now, with dlv connect (should update client to allow setting initial wp immediately)
# dlv connect localhost:4041
# goroutine 1 frame 2 watch -rw -sw -nomove conf.TargetConfigFiles

# 4c. Launch parent client - will continue child dlv (needed because attach stops the process?)
# ./conftamer_main --config=$DIR/parent_client_config.yaml

# 4d. Launch child client - will continue target => target reads its config, hitting watchpoint
# ./conftamer_main --config=$DIR/child_client_config.yaml

# Parent client catches watchpoint hit in proc.(*Breakpoint).taintedSyscallEntry (takes ~40 sec)
# Keep continuing in parent until child hits syscall entry bp =>
# child client sets watchpoint on read buf and continues
