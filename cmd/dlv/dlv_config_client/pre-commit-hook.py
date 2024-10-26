#!/usr/bin/env python3

import subprocess

subprocess.check_output('go install github.com/go-delve/delve/cmd/dlv', shell=True, text=True)
subprocess.check_output('go build github.com/go-delve/delve/cmd/dlv/dlv_config_client', shell=True, text=True)

# TODO fix client tests to use native backend
for i, test in enumerate(['watchpoint']):
  if i == 0:
    test_path = "pkg/proc"
    grep_arg = f"'func TestWatchpoints' {test_path}/proc_test.go"
  else:
    test_path = "cmd/dlv"
    grep_arg = f"'func Test' {test_path}/client_test.go"

  grep = subprocess.run(f"grep {grep_arg} | cut -d '(' -f1 | cut -d ' ' -f2", shell=True, check=True, text=True, capture_output=True)
  regex = '^(' + grep.stdout.strip().replace('\n', '|') + ')'
  test_cmd = f'go test -v -timeout 30s -run \'{regex}\' github.com/go-delve/delve/{test_path} -count=1 -failfast'

  print(f'Running {test} tests: {test_cmd}')

  try:
    p = subprocess.run(test_cmd, shell=True, check=True, text=True, capture_output=True)
    print(p.stdout)
    print(p.stderr)
  except subprocess.CalledProcessError as e:
    print(f'{test} TESTS FAILED, ABORTING COMMIT')
    print(e.stdout)
    print(e.stderr)
    exit(1)
