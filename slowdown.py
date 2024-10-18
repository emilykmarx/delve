#!/usr/bin/env python3

import subprocess
import time
import matplotlib.pyplot as plt
import scipy
import numpy
import statistics
import argparse

runtime_s_all = []
segv_tot_all = []
segv_trapth_all = []
trap_tot_all = []
trap_trapth_all = []

def run(no_watchpoints):
  server_cmd = 'dlv exec --headless --api-version=2 --accept-multiclient --listen=:4040 ./sw_wp_no_prints'
  client_cmd = './dlv_config_client -initial_bp_file=./_fixtures/dlv_config_client/sw_wp_no_prints.go -initial_bp_line=12'
  if not no_watchpoints:
    client_cmd += ' -initial_watchexpr=x'

  server = subprocess.Popen(server_cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  time.sleep(0.3) # wait for server to start
  client_out = subprocess.check_output(client_cmd, shell=True, text=True)
  server_out, server_err = server.communicate()
  if server.returncode != 0:
    print('SERVER FAILED')
    print(server_out)
    print(server_err)
    exit(1)

  print(server_out)
  print(client_out)

  for line in server_out.splitlines():
    tokens = line.split()
    if 'RUNTIME' in line:
      runtime_s_all.append(numpy.float64(tokens[1]))
    elif 'SEGV' in line:
      segv_tot_all.append(numpy.float64(tokens[1]))
      segv_trapth_all.append(numpy.float64(tokens[-1]))
    elif 'TRAP' in line:
      trap_tot_all.append(numpy.float64(tokens[1]))
      trap_trapth_all.append(numpy.float64(tokens[-1]))

# Plot slowdown vs signals
def plot_slowdown(baseline_runtime):
  fig, (ax1, ax2) = plt.subplots(1, 2)
  fig.set_figwidth(15)

  runtime_s = numpy.array(runtime_s_all)
  slowdown = runtime_s/baseline_runtime
  segv_tot = numpy.array(segv_tot_all)
  segv_trapth = numpy.array(segv_trapth_all)
  trap_tot = numpy.array(trap_tot_all)
  trap_trapth = numpy.array(trap_trapth_all)

  for i, x in enumerate([segv_tot, segv_trapth, trap_tot, trap_trapth]):
    color = 'c' if i % 2 == 0 else 'm'
    ax = ax1 if i < 2 else ax2
    ax.scatter(x, slowdown, color=color)
    ax.set(xlabel='Count')
    slope, intercept, r, p, stderr = scipy.stats.linregress(x, slowdown)
    line = f'y={slope:.2f}x + {intercept:.2f}, R={r:.2f}, p={p:.2f}'

    label = 'Total' if i % 2 == 0 else 'Trapthread'
    label += f': {line}'
    ax.plot(x, intercept + slope * x, label=label, color=color)

  for ax in [ax1, ax2]:
    ax.grid(True)
    ax.set(ylabel='Slowdown (ratio)')
    box = ax.get_position()
    ax.set_position([box.x0, box.y0 + box.height * 0.1,
                 box.width, box.height * 0.9])
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1))

  ax1.set_title('Segfaults')
  ax2.set_title('Spurious Traps')

  plt.show()
  fig.savefig('slowdown.png')


# Get average runtime (as baseline for slowdown)
def plot_runtime():
  runtime_avg = statistics.fmean(runtime_s_all)
  runtime_stdev = statistics.stdev(runtime_s_all)
  dummy_x_len = 5.0
  dummy_x = numpy.linspace(0, dummy_x_len, num=len(runtime_s_all))
  plt.scatter(dummy_x, runtime_s_all)
  plt.errorbar(dummy_x_len/2, runtime_avg, yerr=2*runtime_stdev, linestyle='')

  plt.xlabel('Fake')
  plt.ylabel('Runtime (s)')
  plt.title(f'Baseline runtime: avg {runtime_avg:.2f}s, stdev {runtime_stdev:.2f}s')
  plt.savefig('baseline.png')
  plt.show()


  # TODO Check what r and p mean exactly, and think abt what intercept and slope mean
  # More minor: Consider fitting a different curve, better stats to check if sample is representative
def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--runs", type=int, help="Number of times to run program")
  parser.add_argument("--no-watchpoints", action="store_true", help="Whether to run without watchpoints")
  parser.add_argument("--baseline-runtime", type=float, help="Baseline runtime (s)", required=False)
  args = parser.parse_args()

  for i in range(args.runs):
    run(args.no_watchpoints)

  if args.no_watchpoints:
    plot_runtime()
  else:
    plot_slowdown(args.baseline_runtime)


if __name__=="__main__":
    main()
