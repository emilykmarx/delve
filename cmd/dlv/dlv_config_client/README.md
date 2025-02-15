# ConfLens

A Delve client that implements taint tracking for configuration.

It relies on several changes to the server side of Delve, including:
* A software implementation of watchpoints
* Support for watching new types
* Other stuff

It also relies on changes to the go allocator - see below.

## Usage
Tests: See [the pre-commit hook](pre-commit-hook.py) for tests of the client and of the server changes.

Performance: [This script](slowdown.py) gathers some rough slowdown statistics.

Use in a real program (in progress): See [Xenon](https://github.com/emilykmarx/xenon)

Only supports linux/amd64 and Delve's native backend.

### Building the target
* Include `syscall.Syscall6()`, e.g. via `import "_ syscall"`
* Build with `-gcflags="all=-N -l"` - this will minimize optimizations
  * But, compiler may still circumvent taint tracking by using registers -
    `runtime.KeepAlive()` can help.
* Build with a [go allocator](https://github.com/emilykmarx/go) that supports moving tainted objects.
* Import `net/http/pprof` (with `_` if needed)
* If target does not already run an HTTP server, start one.
  * If server does not use the DefaultServeMux, register the pprof handlers (see pprof docs).
* Pointer arithmetic using `unsafe` is not supported (the allocator cannot update the resulting pointers).


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

## Output
Produces a "behavior map" for the target.

Currently only supported behavior is message send using the `write` syscall (e.g. network messages, file writes).

Key: Offset in the buffer passed to `write`. E.g. for network messages, this is the offset in the application-layer protocol portion of the message.

Value: Items directly (i.e. via memory accesses within the module) tainting the offset, currently just the sending module's configuration parameters.

## Limitations
* If one thread is in a syscall that would fault on a user arg while another thread
  would access tainted memory, we will miss the latter access.
