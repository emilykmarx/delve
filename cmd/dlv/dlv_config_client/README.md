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
See the [client tests](../client_test.go) for examples, and [taint.go](taint.go) for implementation.
### Propagation
* Function calls
* Assignment
* Range

Data-flow propagation only.

### Watchpoints
(Where `s` is a variable of the given type)
* String => Set on s and s[0]
* Slice => If has [x:y] syntax, remove that. If that expression is now an array, handle as array. Else set on s
* Array => Set on s[0]
* Struct member
* Any other type with size <= 8 bytes
