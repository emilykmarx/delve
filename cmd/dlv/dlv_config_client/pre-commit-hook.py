#!/usr/bin/env python3

import subprocess

grep = subprocess.run("grep 'func Test' cmd/dlv/client_test.go | cut -d '(' -f1 | cut -d ' ' -f2", shell=True, check=True, text=True, capture_output=True)
regex = '^(' + grep.stdout.strip().replace('\n', '|') + ')'
test_cmd = f'go test -v -timeout 30s -run \'{regex}\' github.com/go-delve/delve/cmd/dlv -count=1 -failfast'
print(f'Running client tests: {test_cmd}')

try:
  subprocess.run(test_cmd, shell=True, check=True, text=True, capture_output=True)
except subprocess.CalledProcessError as e:
  print('TESTS FAILED, ABORTING COMMIT')
  print(e.stdout)
  print(e.stderr)
  exit(1)
