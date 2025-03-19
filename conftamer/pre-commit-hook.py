#!/usr/bin/env python3

import subprocess
import sys
from collections import namedtuple


subprocess.check_output('go install github.com/go-delve/delve/cmd/dlv', shell=True, text=True)
subprocess.check_output('go build github.com/go-delve/delve/cmd/dlv/conftamer_main', shell=True, text=True)

'''
Running all the tests with a single regex command causes the second wp test to fail due to bad siginfo:
signo:11 errno:0 code:1 _:0 addr:0 (and rest zeroed) - code should be 2, addr non-zero.
No idea why, but running in loop fixes. Some state leftover between tests? Pretty sure they're not running in parallel.
'''

'''
After editing this: remember to copy it to .git/hooks
'''

'''
Optional argument to run only watchpoint or client tests
'''

nargs = len(sys.argv)
TestGroup = namedtuple('TestGroup', ['test_path', 'grep_arg'])
test_path = "pkg/proc"
watchpoint_tests = TestGroup(test_path,  f"'func TestWatchpoints' {test_path}/proc_test.go")
test_path = "cmd/dlv"
client_tests = TestGroup(test_path, f"'func Test' {test_path}/conftamer_test.go")

test_groups = {
'watchpoint': watchpoint_tests,
'client': client_tests
}

if nargs > 1:
  arg = sys.argv[1]
  if arg == 'watchpoint':
    print('Only running watchpoint tests')
    test_groups.pop('client')
  elif arg == 'client':
    print('Only running client tests')
    test_groups.pop('watchpoint')
  else:
    print(f'Unknown arg {arg}')
    exit(1)

for test_name, test_group in test_groups.items():
  grep = subprocess.run(f"grep {test_group.grep_arg} | cut -d '(' -f1 | cut -d ' ' -f2", shell=True, check=True, text=True, capture_output=True)
  tests = grep.stdout.splitlines()
  print(f'{test_name} tests: {tests}')

  for test in tests:
    test_cmd = f'go test -v -timeout 30s -run {test} github.com/go-delve/delve/{test_group.test_path} -count=1 -failfast'
    print(test_cmd)
    try:
      p = subprocess.run(test_cmd, shell=True, check=True, text=True, capture_output=True)
      print(p.stdout)
      print(p.stderr)
    except subprocess.CalledProcessError as e:
      print(f'{test} FAILED, ABORTING COMMIT')
      print(e.stdout)
      print(e.stderr)
      exit(1)

# TODO should periodically run all dlv tests (my tests don't check things like nexting)
