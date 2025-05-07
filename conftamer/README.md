# CT-Scan

A Delve client that implements taint tracking for configuration.

It relies on several changes to the server side of Delve, including:
* A software implementation of watchpoints
* Support for watching new types
* Other stuff

It also relies on changes to the go allocator - see below.

## Usage
Tests: See [the pre-commit hook](pre-commit-hook.py) for tests of the client and of the server changes.

Only supports linux/amd64 and Delve's native backend.

### Setup to run the tests
If running on a clean machine, install basic packages:
```
sudo apt-get update
sudo apt-get install build-essential git
```

If haven't already, install Go; we are assuming version 1.21:
```
wget https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

Prepare the project-specific dependencies. When building Go, some of the tests in `all.bash` will fail since the implementation is modified in the fork.

In delve's parent directory:
```
git clone https://github.com/emilykmarx/go-set.git
git clone https://github.com/emilykmarx/graph.git
git clone https://github.com/emilykmarx/go.git

cd go/src
./all.bash
```

Set `CT_TARGET_GO` to the path of the previously cloned fork of Go:
```
export CT_TARGET_GO=<path to the Go fork>
```

Run the tests for watchpoint and client:
```
cd delve
python3 conftamer/pre-commit-hook.py client
python3 conftamer/pre-commit-hook.py watchpoint
```

### Building the target
* Include `syscall.Syscall6()` - will be used to get a `syscall` instruction and to set breakpoints on syscall entry/exit.
* Build with `-gcflags="all=-N -l"` - this will minimize optimizations
  * But, compiler may still circumvent taint tracking by using registers -
    `runtime.KeepAlive()` can help.
* Build with a [go allocator](https://github.com/emilykmarx/go) that supports moving tainted objects.
* Import `net/http/pprof` (with `_` if needed)
* If target does not already run an HTTP server, start one.
  * If server does not use the DefaultServeMux, register the pprof handlers (see pprof docs).
* Pointer arithmetic using `unsafe` is not fully supported (the allocator cannot update the resulting pointers).

### Configuration
Pass the config file with `--config=<file.yaml>`.

For parameters, see `Config` in [config.go](config.go).

## Supported Go constructs
### Propagation
* Function/method calls (arguments, receiver, return value)
* Assignment
* Range
* `if()`

See the [client tests](../client_test.go) for examples.

Implemented in [taint.go](taint.go).

### Watchpoints
* String: Watch characters
* Slice: Watch backing array
* Array: Watch elements
* Struct: Watch fields
* Any other type with size <= 8 bytes

For types that can contain reference elements (slice, array, and struct above), watch the backing array of the reference.

See the [client tests](../cmd/dlv/conftamer_test.go) for examples of non-trivial types.

Type-specific support implemented in [breakpoints.go](../pkg/proc/breakpoints.go).

## Input
The target application, including its code and configuration.

Supports configuration load via file or API endpoint.

## Output
### Behavior map
The main output is a "behavior map", which can be used to understand the target's configuration.

Currently only supported behaviors are network message send and receive using the `write` and `read` syscalls, respectively. (For testing convenience, TCP only for now.)

Key: Offset in the buffer passed to `write` or `read`. For network messages, this is the offset in the application-layer protocol portion of the message (assuming a single write/read call per message).

Value: Items directly (i.e. via memory accesses within the module) tainting the offset.

### Event log
Also outputs a log of all important events, useful for testing and debugging.
See `Event` in [event_log.go](event_log.go).

## Limitations
### False negatives
* If one thread is in a syscall that would fault on a user arg while another thread
  would access tainted memory, we will miss the latter access.
* If access to tainted data occurs while data is enregistered, we will miss the access.
* See comments in mallocgc.
### False positives
* Target GC does not tell delve when watched memory is freed => if a tainted heap object is freed and its memory reused, and then the watchpoint hits, we will incorrectly copy the freed object's tainting values.
### Other
* When stack is moved, delve records its old addresses and client moves any corresponding memory-parameter map entries => if watchpoint is on stack and stack is moved and old stack memory is reused before the client updates its entries, this may be messy (need to think through it).
