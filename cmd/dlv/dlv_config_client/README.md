# ConfLens

A Delve client that implements taint tracking for configuration.

It relies on several changes to the server side of Delve, including:
* A software implementation of watchpoints
* Support for watching new types
* Other stuff

## Usage
Tests: See [the pre-commit hook](pre-commit-hook.py) for tests of the client and of the server changes.

Performance: [This script](slowdown.py) gathers some rough slowdown statistics.

Use in a real program (in progress): See [Xenon](https://github.com/emilykmarx/xenon)

Only supports linux/amd64 and Delve's native backend; currently only tested with go 1.22.4.

### Building the target
* Include `syscall.Syscall6()`, e.g. via `import "_ syscall"`
* Build with `-gcflags="all=-N -l"` - this will minimize optimizations
  * But, compiler may still circumvent taint tracking by using registers -
    `runtime.KeepAlive()` can help.


## Supported Go constructs
### Propagation
* Function/method calls (arguments, receiver, return value)
* Assignment
* Range
* Index (string, array, slice)
* Select (struct)

Data-flow propagation only.

See the [client tests](../client_test.go) for examples.

Implemented in [taint.go](taint.go).

### Watchpoints
* String: Watch characters
* Slice: Watch backing array (or if elements are slices/strings, their backing arrays)
* Array: Watch elements (or if elements are slices/strings, their backing arrays)
* Any other type with size <= 8 bytes

See the [client tests](../client_test.go) for examples of non-trivial types.

Type-specific support implemented in [breakpoints.go](../../../pkg/proc/breakpoints.go).

Watchexprs match the name of the expr passed by the client,
except for types containing reference elements (e.g. slice of strings) -
for these, a watchpoint is created for each element with an indexed watchexpr
(e.g. `s[0]` for slice of strings, or `s[0][0]` for slice of slice of strings).

## Limitations
* If one thread is in a syscall that would fault on a user arg while another thread
  would access tainted memory, we will miss the latter access.
