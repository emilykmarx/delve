FAILURE CASE
Type 'help' for list of commands.
Breakpoint 1 set at 0x4655d3 for main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:6
> [Breakpoint 1] main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:6 (hits goroutine(1):1 total:1) (PC: 0x4655d3)
[33m  [34m   1:	[0mpackage[0m main
[33m  [34m   2:	[0m
[33m  [34m   3:	[0m[0mimport[0m [32m"runtime"[0m
[33m  [34m   4:	[0m
[33m  [34m   5:	[0m[0mfunc[0m sortByRFC6724withSrcs(addrs int) {
[33m=>[34m   6:	[0m[90m	[0mif[0m addrs == [0m0[0m { [95m// addrs gets an addr only after executing first instr in line (with go 1.22.4 - ok w/ go 1.20.1)[0m
[33m  [34m   7:	[0m[90m	[0m[90m	[0mpanic([32m"internal error"[0m)
[33m  [34m   8:	[0m[90m	[0m}
[33m  [34m   9:	[0m}
[33m  [34m  10:	[0m
[33m  [34m  11:	[0m[0mfunc[0m main() {
init.txt:3: command not available
extractVarInfoFromEntry; entry: {Entry:0xc000d802a0 typ:0xc0007a7300 Tag:FormalParameter Offset:4533 Ranges:[] Children:[]}
entry.Entry: &{Offset:4533 Tag:FormalParameter Children:false Field:[{Attr:Name Val:addrs Class:ClassString} {Attr:VarParam Val:false Class:ClassFlag} {Attr:DeclLine Val:5 Class:ClassConstant} {Attr:Type Val:7268 Class:ClassReference} {Attr:Location Val:3516 Class:ClassLocListPtr}]}
contains pc: false
attr: Location
a: 0xdbc
a not ok, returning loclistEntry at off 0xdbc
instructions: 0x50
opcode 0x50
ctxt has one piece, it's a reg: {Size:0 Kind:1 Val:0 Bytes:[]}
stack: []
(*int)(0xbeef000000000000)
init.txt:5: command not available
> main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:9 (PC: 0x4655da)
[33m  [34m   4:	[0m
[33m  [34m   5:	[0m[0mfunc[0m sortByRFC6724withSrcs(addrs int) {
[33m  [34m   6:	[0m[90m	[0mif[0m addrs == [0m0[0m { [95m// addrs gets an addr only after executing first instr in line (with go 1.22.4 - ok w/ go 1.20.1)[0m
[33m  [34m   7:	[0m[90m	[0m[90m	[0mpanic([32m"internal error"[0m)
[33m  [34m   8:	[0m[90m	[0m}
[33m=>[34m   9:	[0m}
[33m  [34m  10:	[0m
[33m  [34m  11:	[0m[0mfunc[0m main() {
[33m  [34m  12:	[0m[90m	[0ma := [0m5[0m
[33m  [34m  13:	[0m[90m	[0mruntime.KeepAlive(a)
[33m  [34m  14:	[0m[90m	[0msortByRFC6724withSrcs(a)
init.txt:7: command not available
extractVarInfoFromEntry; entry: {Entry:0xc000d802a0 typ:0xc0007a7300 Tag:FormalParameter Offset:4533 Ranges:[] Children:[]}
entry.Entry: &{Offset:4533 Tag:FormalParameter Children:false Field:[{Attr:Name Val:addrs Class:ClassString} {Attr:VarParam Val:false Class:ClassFlag} {Attr:DeclLine Val:5 Class:ClassConstant} {Attr:Type Val:7268 Class:ClassReference} {Attr:Location Val:3516 Class:ClassLocListPtr}]}
contains pc: false
attr: Location
a: 0xdbc
a not ok, returning loclistEntry at off 0xdbc
instructions: 0x9c
opcode 0x9c
(*int)(0xc00006e750)
SUCCESS CASE
Type 'help' for list of commands.
Breakpoint 1 set at 0x461339 for main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:6
> [Breakpoint 1] main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:6 (hits goroutine(1):1 total:1) (PC: 0x461339)
[33m  [34m   1:	[0mpackage[0m main
[33m  [34m   2:	[0m
[33m  [34m   3:	[0m[0mimport[0m [32m"runtime"[0m
[33m  [34m   4:	[0m
[33m  [34m   5:	[0m[0mfunc[0m sortByRFC6724withSrcs(addrs int) {
[33m=>[34m   6:	[0m[90m	[0mif[0m addrs == [0m0[0m { [95m// addrs gets an addr only after executing first instr in line (with go 1.22.4 - ok w/ go 1.20.1)[0m
[33m  [34m   7:	[0m[90m	[0m[90m	[0mpanic([32m"internal error"[0m)
[33m  [34m   8:	[0m[90m	[0m}
[33m  [34m   9:	[0m}
[33m  [34m  10:	[0m
[33m  [34m  11:	[0m[0mfunc[0m main() {
init.txt:3: command not available
extractVarInfoFromEntry; entry: {Entry:0xc0010502a0 typ:0xc000549000 Tag:FormalParameter Offset:95853 Ranges:[] Children:[]}
entry.Entry: &{Offset:95853 Tag:FormalParameter Children:false Field:[{Attr:Name Val:addrs Class:ClassString} {Attr:VarParam Val:false Class:ClassFlag} {Attr:DeclLine Val:5 Class:ClassConstant} {Attr:Type Val:4252 Class:ClassReference} {Attr:Location Val:6222 Class:ClassLocListPtr}]}
contains pc: false
attr: Location
a: 0x184e
a not ok, returning loclistEntry at off 0x184e
instructions: 0x9c
opcode 0x9c
(*int)(0xc000068758)
init.txt:5: command not available
> main.sortByRFC6724withSrcs() ./_fixtures/conftamer/fake_xv.go:9 (PC: 0x461342)
[33m  [34m   4:	[0m
[33m  [34m   5:	[0m[0mfunc[0m sortByRFC6724withSrcs(addrs int) {
[33m  [34m   6:	[0m[90m	[0mif[0m addrs == [0m0[0m { [95m// addrs gets an addr only after executing first instr in line (with go 1.22.4 - ok w/ go 1.20.1)[0m
[33m  [34m   7:	[0m[90m	[0m[90m	[0mpanic([32m"internal error"[0m)
[33m  [34m   8:	[0m[90m	[0m}
[33m=>[34m   9:	[0m}
[33m  [34m  10:	[0m
[33m  [34m  11:	[0m[0mfunc[0m main() {
[33m  [34m  12:	[0m[90m	[0ma := [0m5[0m
[33m  [34m  13:	[0m[90m	[0mruntime.KeepAlive(a)
[33m  [34m  14:	[0m[90m	[0msortByRFC6724withSrcs(a)
init.txt:7: command not available
extractVarInfoFromEntry; entry: {Entry:0xc0010502a0 typ:0xc000549000 Tag:FormalParameter Offset:95853 Ranges:[] Children:[]}
entry.Entry: &{Offset:95853 Tag:FormalParameter Children:false Field:[{Attr:Name Val:addrs Class:ClassString} {Attr:VarParam Val:false Class:ClassFlag} {Attr:DeclLine Val:5 Class:ClassConstant} {Attr:Type Val:4252 Class:ClassReference} {Attr:Location Val:6222 Class:ClassLocListPtr}]}
contains pc: false
attr: Location
a: 0x184e
a not ok, returning loclistEntry at off 0x184e
instructions: 0x9c
opcode 0x9c
(*int)(0xc000068758)
