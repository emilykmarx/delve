=== RUN   TestAllocatorHTTP
    conftamer_test.go:867: Starting server: /tmp/TestAllocatorHTTP2441922092/002/dlv.exe debug --headless --api-version=2 --accept-multiclient --listen localhost:4040 ../../_fixtures/conftamer/allocator_http.go
API server listening at: 127.0.0.1:4040
    conftamer_test.go:889: Starting client with timeout 10s: /tmp/TestAllocatorHTTP2441922092/001/client.exe -config=test_module_client_config.yml
Continue
2025/05/09 17:21:49.578250 exec.go:72: Starting CT-Scan

copystack gp=0xc0000061a0 [0xc00006e000 0xc00006e3e8 0xc00006e800] -> [0xc000085000 0xc000085be8 0xc000086000]/4096
did memmove
copystack gp=0xc0000061a0 [0xc000085000 0xc000085988 0xc000086000] -> [0xc0000b0000 0xc0000b1988 0xc0000b2000]/8192
did memmove
copystack gp=0xc0000061a0 [0xc0000b0000 0xc0000b0570 0xc0000b2000] -> [0xc000264000 0xc000266570 0xc000268000]/16384
did memmove
copystack gp=0xc000226680 [0xc00006a000 0xc00006a378 0xc00006a800] -> [0xc000080000 0xc000080b78 0xc000081000]/4096
did memmove
copystack gp=0xc000226680 [0xc000080000 0xc000080578 0xc000081000] -> [0xc0000ac000 0xc0000ad578 0xc0000ae000]/8192
did memmove
copystack gp=0xc000102680 [0xc00006a000 0xc00006a410 0xc00006a800] -> [0xc000080000 0xc000080c10 0xc000081000]/4096
did memmove
copystack gp=0xc000102680 [0xc000080000 0xc0000803d0 0xc000081000] -> [0xc0000ae000 0xc0000af3d0 0xc0000b0000]/8192
did memmove
copystack gp=0xc000102680 [0xc0000ae000 0xc0000ae500 0xc0000b0000] -> [0xc000260000 0xc000262500 0xc000264000]/16384
did memmove

# Eval before first move
# Stack is 0xc000264000:0xc000268000,dlv evals ptr to in that range
ZZEM file /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go line 28: hit pending wp breakpoint
watchexprs: {items:map[*ptr:{}]}, watchargs: {items:map[]}, cmds: []
op: *evalop.PushIdent
op: *evalop.PointerDeref
# xev.Addr: &ptr
xev Addr in evalPointerDeref: 0xc000267ef0
# rv.Addr: ptr
rv Addr in evalPointerDeref: 0xc0001201d8
wp set for 0xc0001201d8 (sz 0x8) - not on stack
op: *evalop.PushIdent
op: *evalop.PointerDeref
xev Addr in evalPointerDeref: 0xc000267ef0
rv Addr in evalPointerDeref: 0xc0001201d8
ZZEM Set watchpoint on *ptr
Continue
goroutine at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:28, stack 0xc000264000:0xc000268000
ZZEM setting pending wp: {0xc00134e140 *ptr 3}
op: *evalop.PushIdent
op: *evalop.PointerDeref
xev Addr in evalPointerDeref: 0xc000267ef0
rv Addr in evalPointerDeref: 0xc0001201d8
enter monitorMoveObject
enter MoveObject
copystack gp=0xc000102680 [0xc00006a000 0xc00006a798 0xc00006a800] -> [0xc000080000 0xc000080f98 0xc000081000]/4096
did memmove
copystack gp=0xc000102680 [0xc000080000 0xc000080390 0xc000081000] -> [0xc0000ae000 0xc0000af390 0xc0000b0000]/8192
did memmove
copystack gp=0xc000102680 [0xc0000ae000 0xc0000ae3a0 0xc0000b0000] -> [0xc000260000 0xc0002623a0 0xc000264000]/16384
did memmove
copystack gp=0xc000102820 [0xc00006a000 0xc00006a3a0 0xc00006a800] -> [0xc000186000 0xc000186ba0 0xc000187000]/4096
did memmove
MoveObject, addr  0xc0001201d8
old obj block=0xc0001201d0 s.base()=0xc000120000 s.limit=0xc000122000 s.spanclass=9 s.elemsize=16 s.state=mSpanInUse
 *(old obj block+0) = 0x36393034
 *(old obj block+8) = 0x4 <==

# copystack during first move, before scanblock finds the ptr => update ptr after copystack moves it
# 0xc000264000:0xc000268000 => 0xc0000ae000:0xc0000b0000
copystack gp=0xc0000061a0 [0xc000264000 0xc000267e60 0xc000268000] -> [0xc0000ae000 0xc0000afe60 0xc0000b0000]/8192
did memmove
putOldPtr from  scanblock : block  0xc0001201d0 off:  0x8 , addr of ptr 0xc0000afef0
b:  0xc0000afef0  i:  0x0  n:  0x80
# Copied stack
stk:  0xc0000ae000 : 0xc0000b0000
putOldPtr from  scanblock : block  0xc0001201d0 off:  0x8 , addr of ptr 0xc0002630d8
b:  0xc0002630d8  i:  0x0  n:  0x8
# Whose stack is this? This is the ptr the 2nd move finds
# Was copied above...
stk:  0xc000260000 : 0xc000264000
copystack gp=0xc00018c820 [0xc000194000 0xc000194368 0xc000194800] -> [0xc000182000 0xc000182b68 0xc000183000]/4096
did memmove
updating ptr from 0xc0001201d8 to 0xc0002a0008 ; addr 0xc0000afef0 , off 0x8
pointer block, before update in updateOldPtrs=0xc0000afef0 s.base()=0xc0000ac000 s.limit=0xc0000b4000 s.spanclass=0 s.elemsize=8192 s.state=mSpanManual
 *(pointer block, before update in updateOldPtrs+0) = 0xc0001201d8 <==

pointer block, after update=0xc0000afef0 s.base()=0xc0000ac000 s.limit=0xc0000b4000 s.spanclass=0 s.elemsize=8192 s.state=mSpanManual
 *(pointer block, after update+0) = 0xc0002a0008 <==

updating ptr from 0xc0001201d8 to 0xc0002a0008 ; addr 0xc0002630d8 , off 0x8
pointer block, before update in updateOldPtrs=0xc0002630d8 s.base()=0xc000260000 s.limit=0xc000268000 s.spanclass=0 s.elemsize=16384 s.state=mSpanManual
 *(pointer block, before update in updateOldPtrs+0) = 0xc0001201d8 <==
pointer block, after update=0xc0002630d8 s.base()=0xc000260000 s.limit=0xc000268000 s.spanclass=0 s.elemsize=16384 s.state=mSpanManual
 *(pointer block, after update+0) = 0xc0002a0008 <==

new obj block=0xc0002a0000 s.base()=0xc0002a0000 s.limit=0xc0002a2000 s.spanclass=11 s.elemsize=16 s.state=mSpanInUse
 *(new obj block+0) = 0x36393034
 *(new obj block+8) = 0x4 <==
allocator response body: New address: 0xc0002a0008

exit MoveObject
sent stop() to thread 1797922
donech; exit monitorMoveObject
about to stop()
about to set wp after successful MoveObject
wp set for 0xc0002a0008 (sz 0x8) - not on stack
ZZEM setting pending wp: {0xc00134e140 *ptr 3}
op: *evalop.PushIdent
op: *evalop.PointerDeref

# Second move
# Dlv evals &ptr to pre-copystack addr => mem there didn't get updated
# What should we do?
xev Addr in evalPointerDeref: 0xc000267ef0
rv Addr in evalPointerDeref: 0xc0001201d8
enter monitorMoveObject
enter MoveObject
MoveObject, addr  0xc0001201d8
old obj block=0xc0001201d0 s.base()=0xc000120000 s.limit=0xc000122000 s.spanclass=9 s.elemsize=16 s.state=mSpanInUse
copystack gp=0xc000102820 [0xc000071000 0xc0000713a0 0xc000071800] -> [0xc000189000 0xc000189ba0 0xc00018a000]/4096
did memmove
 *(old obj block+0) = 0x36393034
 *(old obj block+8) = 0x4 <==

# Stack moves again
copystack gp=0xc0000061a0 [0xc0000ae000 0xc0000afe60 0xc0000b0000] -> [0xc000183000 0xc000183e60 0xc000184000]/4096
did memmove
putOldPtr from  scanblock : block  0xc0001201d0 off:  0x8 , addr of ptr 0xc0002630d8
b:  0xc0002630d8  i:  0x0  n:  0x8
stk:  0xc000260000 : 0xc000264000
updating ptr from 0xc0001201d8 to 0xc0002a0018 ; addr 0xc0002630d8 , off 0x8
pointer block, before update in updateOldPtrs=0xc0002630d8 s.base()=0xc000260000 s.limit=0xc000268000 s.spanclass=0 s.elemsize=16384 s.state=mSpanManual
 *(pointer block, before update in updateOldPtrs+0) = 0xc0001201d8 <==
 ...

pointer block, after update=0xc0002630d8 s.base()=0xc000260000 s.limit=0xc000268000 s.spanclass=0 s.elemsize=16384 s.state=mSpanManual
 *(pointer block, after update+0) = 0xc0002a0018 <==
 ...

new obj block=0xc0002a0010 s.base()=0xc0002a0000 s.limit=0xc0002a2000 s.spanclass=11 s.elemsize=16 s.state=mSpanInUse
 *(new obj block+0) = 0x36393034
 *(new obj block+8) = 0x4 <==
allocator response body: New address: 0xc0002a0018

exit MoveObject
sent stop() to thread 1797920
donech; exit monitorMoveObject
about to stop()
about to set wp after successful MoveObject
wp set for 0xc0002a0018 (sz 0x8) - not on stack
target about to access

# Hit *ptr => eval *ptr
# Evals to after most recent copystack, which copied the val that got updated in 1st move - so evals to obj's new addr
ZZEM hit watchpoint on *ptr at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30
start propagateTaint - AssignStmt lhs x
ZZEM eval *ptr
op: *evalop.PushIdent
op: *evalop.PointerDeref

xev Addr in evalPointerDeref: 0xc000183ef0
rv Addr in evalPointerDeref: 0xc0002a0008
watch region 0xc0002a0008:8, xv 0xc0002a0008:8
isTainted return {new_expr:<nil> new_argno:<nil> old_region:[0xc00031d040] set_now:false set_location:<nil> cmds:[] body_start:0 body_end:0}
finish propagateTaint - AssignStmt lhs x
propagateTaint return [{new_expr:0xc00027eea0 new_argno:<nil> old_region:[0xc00031d040] set_now:false set_location:<nil> cmds:[{cmd:next stack_len:3 lineno:30}] body_start:0 body_end:0}]
pendingWatchpoint about to record: watchexprs: {items:map[x:{}]}, watchargs: {items:map[]}, cmds: [{cmd:next stack_len:3 lineno:30}]
ZZEM propagated taint for watchpoint hit on *ptr
Next
goroutine at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30, stack 0xc000183000:0xc000184000
cmd was {cmd:next stack_len:3 lineno:30}; thread line now 30, stacklen now 3
ZZEM interrupted at line 30, not at right line yet => next again
ZZEM hit watchpoint on *ptr at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30
start propagateTaint - AssignStmt lhs x
ZZEM eval *ptr
op: *evalop.PushIdent
op: *evalop.PointerDeref
xev Addr in evalPointerDeref: 0xc000183ef0
rv Addr in evalPointerDeref: 0xc0002a0008
watch region 0xc0002a0008:8, xv 0xc0002a0008:8
isTainted return {new_expr:<nil> new_argno:<nil> old_region:[0xc0002a72b0] set_now:false set_location:<nil> cmds:[] body_start:0 body_end:0}
finish propagateTaint - AssignStmt lhs x
propagateTaint return [{new_expr:0xc0002ec3d0 new_argno:<nil> old_region:[0xc0002a72b0] set_now:false set_location:<nil> cmds:[{cmd:next stack_len:3 lineno:30}] body_start:0 body_end:0}]
pendingWatchpoint about to record: watchexprs: {items:map[x:{}]}, watchargs: {items:map[]}, cmds: [{cmd:next stack_len:3 lineno:30}]
ZZEM propagated taint for watchpoint hit on *ptr
Next
goroutine at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30, stack 0xc000183000:0xc000184000
cmd was {cmd:next stack_len:3 lineno:30}; thread line now 31, stacklen now 3
cmd {cmd:next stack_len:3 lineno:30} done - at line 31
ZZEM finished sequence - at line 31; pending wp:
watchexprs: {items:map[x:{}]}, watchargs: {items:map[]}, cmds: [{cmd:next stack_len:3 lineno:30}]
ZZEM not in branch body - set cmd pending wp
wp set for 0xc000183ee8 - on stack
ZZEM Set watchpoint on x
Continue
goroutine at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:31, stack 0xc000183000:0xc000184000
IGNORING PRINT: fmt.Println("target exit; %v", x)
Continue
2025/05/09 17:21:52.021557 hits.go:549: Not propagating taint for watchpoint hit at 0x804754
goroutine at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:31, stack 0xc000183000:0xc000184000
target exit; %v 4
Watchpoint on x went out of scope - current goroutine at /home/emily/projects/wtf_project/go1.20.1/src/runtime/proc.go:260 (0x442e93)
Continue
goroutine at /home/emily/projects/wtf_project/go1.20.1/src/runtime/proc.go:260, stack 0xc000183000:0xc000184000
Target exited with status 0
2025/05/09 17:21:54.640732 exec.go:173: Finished CT-Scan
    conftamer_test.go:946: failed assertion at conftamer_test.go:946: expected vs actual:
        Watchpoint set,0x0,0x8,*ptr,,,2025-05-09 17:21:54.642737363 -0700 PDT m=+10.321397570,,

        Watchpoint set,0xc0001201d8,0x8,*ptr,,,2025-05-09 17:21:54.642785693 -0700 PDT m=+10.321445888,,

        diff   conftamer.Event{
          	... // 1 ignored and 3 identical fields
          	Behavior:     nil,
          	TaintingVals: nil,
        - 	Line:         27,
        + 	Line:         28,
          }
         (expected event 0 wrong)
--- FAIL: TestAllocatorHTTP (10.32s)
FAIL
FAIL	github.com/go-delve/delve/cmd/dlv	10.328s
FAIL
