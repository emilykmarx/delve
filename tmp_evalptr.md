=== RUN   TestAllocatorHTTP
    conftamer_test.go:867: Starting server: /tmp/TestAllocatorHTTP2425475171/002/dlv.exe debug --headless --api-version=2 --accept-multiclient --listen localhost:4040 ../../_fixtures/conftamer/allocator_http.go
API server listening at: 127.0.0.1:4040
    conftamer_test.go:889: Starting client with timeout 10s: /tmp/TestAllocatorHTTP2425475171/001/client.exe -config=test_module_client_config.yml
Continue
2025/05/07 17:55:45.121369 exec.go:72: Starting CT-Scan

ZZEM file /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go line 27: hit pending wp breakpoint
watchexprs: {items:map[*ptr:{}]}, watchargs: {items:map[]}, cmds: []
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr
xev before load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
xev after load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:824635417016 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635417016 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
wp set for 0xc00019e1b8 (sz 0x8) - not on stack
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr
xev before load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
xev after load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:824635417016 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635417016 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
ZZEM Set watchpoint on *ptr
Continue

# Eval before first move
ZZEM setting pending wp: {0xc0020b0500 *ptr 3}
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr
xev before load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
xev after load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:824635417016 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635417016 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
enter monitorMoveObject
enter MoveObject
MoveObject, addr  0xc00019e1b8
old obj block=0xc00019e1b0 s.base()=0xc00019e000 s.limit=0xc0001a0000 s.spanclass=9 s.elemsize=16 s.state=mSpanInUse
 *(old obj block+0) = 0x36393034
 *(old obj block+8) = 0x4 <==
old addr: 0xc00019e1b8
putOldPtr from  scanblock : block  0xc00019e1b0 off:  0x8 , addr of ptr 0xc000295ed0
putOldPtr from  scanblock : block  0xc00019e1b0 off:  0x8 , addr of ptr 0xc0002070d8
updating ptr from 0xc00019e1b8 to 0xc000212008 ; addr 0xc000295ed0 , off 0x8
updating ptr from 0xc00019e1b8 to 0xc000212008 ; addr 0xc0002070d8 , off 0x8
new obj block=0xc000212000 s.base()=0xc000212000 s.limit=0xc000214000 s.spanclass=11 s.elemsize=16 s.state=mSpanInUse
 *(new obj block+0) = 0x36393034
 *(new obj block+8) = 0x4 <==
allocator response body: New address: 0xc000212008

exit MoveObject
sent stop() to thread 1360800
donech; exit monitorMoveObject
about to stop()
about to set wp after successful MoveObject
wp set for 0xc000212008 (sz 0x8) - not on stack

# Eval before second move
ZZEM setting pending wp: {0xc0020b0500 *ptr 3}
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr
# Addr: 0xc000161ed0 - doesn't appear elsewhere???
xev before load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}

# Load reads the memory at Addr
# after load: Value is 0xc00019e1b8, so is Child Addr - this is the old addr
xev after load: {Addr:824635170512 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:824635417016 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635417016 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc001066d00 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
enter monitorMoveObject
enter MoveObject
MoveObject, addr  0xc00019e1b8
old obj block=0xc00019e1b0 s.base()=0xc00019e000 s.limit=0xc0001a0000 s.spanclass=9 s.elemsize=16 s.state=mSpanInUse
 *(old obj block+0) = 0x36393034
 *(old obj block+8) = 0x4 <==
putOldPtr from  scanblock : block  0xc00019e1b0 off:  0x8 , addr of ptr 0xc0002070d8
updating ptr from 0xc00019e1b8 to 0xc000212018 ; addr 0xc0002070d8 , off 0x8
new obj block=0xc000212010 s.base()=0xc000212000 s.limit=0xc000214000 s.spanclass=11 s.elemsize=16 s.state=mSpanInUse
 *(new obj block+0) = 0x36393034
 *(new obj block+8) = 0x4 <==
allocator response body: New address: 0xc000212018

exit MoveObject
sent stop() to thread 1360772
donech; exit monitorMoveObject
about to stop()
about to set wp after successful MoveObject
wp set for 0xc000212018 (sz 0x8) - not on stack
target about to access
ZZEM hit watchpoint on *ptr at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30
start propagateTaint - AssignStmt lhs x
ZZEM eval *ptr
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr
xev before load: {Addr:824636468944 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
xev after load: {Addr:824636468944 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:824635891720 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635891720 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
watch region 0xc000212008:8, xv 0xc000212008:8
isTainted return {new_expr:<nil> new_argno:<nil> old_region:[0xc0002b8ea0] set_now:false set_location:<nil> cmds:[] body_start:0 body_end:0}
finish propagateTaint - AssignStmt lhs x
propagateTaint return [{new_expr:0xc000390160 new_argno:<nil> old_region:[0xc0002b8ea0] set_now:false set_location:<nil> cmds:[{cmd:next stack_len:3 lineno:30}] body_start:0 body_end:0}]
pendingWatchpoint about to record: watchexprs: {items:map[x:{}]}, watchargs: {items:map[]}, cmds: [{cmd:next stack_len:3 lineno:30}]
ZZEM propagated taint for watchpoint hit on *ptr
Next
cmd was {cmd:next stack_len:3 lineno:30}; thread line now 30, stacklen now 3
ZZEM interrupted at line 30, not at right line yet => next again
ZZEM hit watchpoint on *ptr at /home/emily/projects/config_tracing/delve/_fixtures/conftamer/allocator_http.go:30
start propagateTaint - AssignStmt lhs x
ZZEM eval *ptr
op: *evalop.PushIdent
op: *evalop.PointerDeref
deref, X: ptr

# Eval to set wp after both moves
# Addr is 0xc00029eed0 which also doesn't appear elsewhere???
# Value/child is 0xc000212008, which is location of obj after first move
xev before load: {Addr:824636468944 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
xev after load: {Addr:824636468944 OnlyAddr:false Name:ptr DwarfType:*int RealType:*int Kind:ptr Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:824635891720 FloatSpecial:0 reg:<nil> Len:1 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[{Addr:824635891720 OnlyAddr:false Name: DwarfType:int RealType:int Kind:int Watchsz:0 mem:0xc005e99400 bi:0xc0001bb7c0 Value:<nil> FloatSpecial:0 reg:<nil> Len:0 Cap:0 Flags:0 Base:0 stride:0 fieldType:<nil> closureAddr:0 mapSkip:0 Children:[] loaded:false Unreadable:<nil> LocationExpr: DeclLine:0}] loaded:false Unreadable:<nil> LocationExpr:[block] DW_OP_fbreg -0xb0  DeclLine:26}
watch region 0xc000212018:8, xv 0xc000212008:8
isTainted return nil
finish propagateTaint - AssignStmt lhs x
propagateTaint return []
ZZEM propagated taint for watchpoint hit on *ptr
Next
cmd was {cmd:next stack_len:3 lineno:30}; thread line now 31, stacklen now 3
cmd {cmd:next stack_len:3 lineno:30} done - at line 31
ZZEM finished sequence - at line 31; pending wp:
watchexprs: {items:map[x:{}]}, watchargs: {items:map[]}, cmds: [{cmd:next stack_len:3 lineno:30}]
ZZEM not in branch body - set cmd pending wp
wp set for 0xc00029eec8 - on stack
ZZEM Set watchpoint on x
Continue
IGNORING PRINT: fmt.Println("target exit; %v", x)
Continue
2025/05/07 17:55:47.628682 hits.go:549: Not propagating taint for watchpoint hit at 0x804682
target exit; %v 4
Watchpoint on x went out of scope - current goroutine at /home/emily/projects/wtf_project/go1.20.1/src/runtime/proc.go:260 (0x442cf3)
Continue
2025/05/07 17:55:50.783521 exec.go:173: Finished CT-Scan
Target exited with status 0
--- PASS: TestAllocatorHTTP (7.50s)
PASS
ok  	github.com/go-delve/delve/cmd/dlv	7.510s
