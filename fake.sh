#!/bin/bash -e
go install github.com/go-delve/delve/cmd/dlv

# new go
echo 'FAILURE CASE'
go build -gcflags="all=-N -l"  ./_fixtures/conftamer/fake_xv.go
dlv exec --allow-non-terminal-interactive=true --init=init.txt ./fake_xv

# old go
echo 'SUCCESS CASE'
/home/emily/projects/wtf_project/go1.20.1/bin/go build -gcflags="all=-N -l"  ./_fixtures/conftamer/fake_xv.go
dlv exec --allow-non-terminal-interactive=true --init=init.txt ./fake_xv
