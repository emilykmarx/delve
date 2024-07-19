#!/usr/bin/env python3

import subprocess

p = subprocess.run("grep 'func Test' cmd/dlv/client_test.go | cut -d '(' -f1 | cut -d ' ' -f2", shell=True, check=True, text=True, capture_output=True)
regex = '^(' + p.stdout.strip().replace('\n', '|') + ')'
test = f'go test -v -timeout 30s -run \'{regex}\' github.com/go-delve/delve/cmd/dlv -count=1'
print(f'To run client tests: {test}')
