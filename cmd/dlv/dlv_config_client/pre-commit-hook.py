#!/usr/bin/env python3

import subprocess

subprocess.check_output('go install github.com/go-delve/delve/cmd/dlv', shell=True, text=True)
subprocess.check_output('go build github.com/go-delve/delve/cmd/dlv/dlv_config_client', shell=True, text=True)

'''
Running all the tests with a single regex command causes the second wp test to fail due to bad siginfo:
signo:11 errno:0 code:1 _:0 addr:0 (and rest zeroed) - code should be 2, addr non-zero.
No idea why, but running in loop fixes. Some state leftover between tests?
'''
for i, test in enumerate(['watchpoint', 'client']):
  if i == 0:
    test_path = "pkg/proc"
    grep_arg = f"'func TestWatchpoints' {test_path}/proc_test.go"
  else:
    test_path = "cmd/dlv"
    grep_arg = f"'func Test' {test_path}/client_test.go"

  grep = subprocess.run(f"grep {grep_arg} | cut -d '(' -f1 | cut -d ' ' -f2", shell=True, check=True, text=True, capture_output=True)
  tests = grep.stdout.splitlines()


  for test in tests:
    test_cmd = f'go test -v -timeout 30s -run {test} github.com/go-delve/delve/{test_path} -count=1 -failfast'
    print(test_cmd)
    try:
      p = subprocess.run(test_cmd, shell=True, check=True, text=True, capture_output=True)
      print(p.stdout)
      print(p.stderr)
    except subprocess.CalledProcessError as e:
      print(f'{test} TESTS FAILED, ABORTING COMMIT')
      print(e.stdout)
      print(e.stderr)
      exit(1)
