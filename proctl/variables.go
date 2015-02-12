package proctl

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"unsafe"

	"github.com/chendesheng/delve/dwarf/op"
	"github.com/chendesheng/delve/dwarf/reader"
)

type Variable struct {
	Name  string
	Value string
	Type  string
}

type M struct {
	procid   uint64
	spinning uint8
	blocked  uint8
	curg     uintptr
}

const ptrsize uintptr = unsafe.Sizeof(int(1))

// Parses and returns select info on the internal M
// data structures used by the Go scheduler.
func (dbp *DebuggedProcess) AllM() ([]*M, error) {
	reader := dbp.Dwarf.Reader()

	allmaddr, err := parseAllMPtr(dbp, reader)
	if err != nil {
		return nil, err
	}
	mptr, err := dbp.readMemory(uintptr(allmaddr), int(ptrsize))
	if err != nil {
		return nil, err
	}
	m := binary.LittleEndian.Uint64(mptr)
	if m == 0 {
		return nil, fmt.Errorf("allm contains no M pointers")
	}

	// parse addresses
	procidInstructions, err := instructionsFor("procid", dbp, reader, true)
	if err != nil {
		return nil, err
	}
	spinningInstructions, err := instructionsFor("spinning", dbp, reader, true)
	if err != nil {
		return nil, err
	}
	alllinkInstructions, err := instructionsFor("alllink", dbp, reader, true)
	if err != nil {
		return nil, err
	}
	blockedInstructions, err := instructionsFor("blocked", dbp, reader, true)
	if err != nil {
		return nil, err
	}
	curgInstructions, err := instructionsFor("curg", dbp, reader, true)
	if err != nil {
		return nil, err
	}

	var allm []*M
	for {
		// curg
		curgAddr, err := executeMemberStackProgram(mptr, curgInstructions)
		if err != nil {
			return nil, err
		}
		curgBytes, err := dbp.readMemory(uintptr(curgAddr), int(ptrsize))
		if err != nil {
			return nil, fmt.Errorf("could not read curg %#v %s", curgAddr, err)
		}
		curg := binary.LittleEndian.Uint64(curgBytes)

		// procid
		procidAddr, err := executeMemberStackProgram(mptr, procidInstructions)
		if err != nil {
			return nil, err
		}
		procidBytes, err := dbp.readMemory(uintptr(procidAddr), int(ptrsize))
		if err != nil {
			return nil, fmt.Errorf("could not read procid %#v %s", procidAddr, err)
		}
		procid := binary.LittleEndian.Uint64(procidBytes)

		// spinning
		spinningAddr, err := executeMemberStackProgram(mptr, spinningInstructions)
		if err != nil {
			return nil, err
		}
		spinBytes, err := dbp.readMemory(uintptr(spinningAddr), 1)
		if err != nil {
			return nil, fmt.Errorf("could not read spinning %#v %s", spinningAddr, err)
		}

		// blocked
		blockedAddr, err := executeMemberStackProgram(mptr, blockedInstructions)
		if err != nil {
			return nil, err
		}
		blockBytes, err := dbp.readMemory(uintptr(blockedAddr), 1)
		if err != nil {
			return nil, fmt.Errorf("could not read blocked %#v %s", blockedAddr, err)
		}

		allm = append(allm, &M{
			procid:   procid,
			blocked:  blockBytes[0],
			spinning: spinBytes[0],
			curg:     uintptr(curg),
		})

		// Follow the linked list
		alllinkAddr, err := executeMemberStackProgram(mptr, alllinkInstructions)
		if err != nil {
			return nil, err
		}
		mptr, err = dbp.readMemory(uintptr(alllinkAddr), int(ptrsize))
		if err != nil {
			return nil, fmt.Errorf("could not read alllink %#v %s", alllinkAddr, err)
		}
		m = binary.LittleEndian.Uint64(mptr)

		if m == 0 {
			break
		}
	}

	return allm, nil
}

func instructionsFor(name string, dbp *DebuggedProcess, reader *dwarf.Reader, member bool) ([]byte, error) {
	reader.Seek(0)
	entry, err := findDwarfEntry(name, reader, member)
	if err != nil {
		return nil, err
	}
	return instructionsForEntry(entry)
}

func instructionsForEntry(entry *dwarf.Entry) ([]byte, error) {
	if entry.Tag == dwarf.TagMember {
		instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
		if !ok {
			return nil, fmt.Errorf("member data has no data member location attribute")
		}
		// clone slice to prevent stomping on the dwarf data
		return append([]byte{}, instructions...), nil
	}

	// non-member
	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return nil, fmt.Errorf("entry has no location attribute")
	}

	// clone slice to prevent stomping on the dwarf data
	return append([]byte{}, instructions...), nil
}

func executeMemberStackProgram(base, instructions []byte) (uint64, error) {
	parentInstructions := append([]byte{op.DW_OP_addr}, base...)
	addr, err := op.ExecuteStackProgram(0, append(parentInstructions, instructions...))
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

func parseAllMPtr(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("runtime.allm", reader, false)
	if err != nil {
		return 0, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

type G struct {
	id      int
	stacklo uint64
	stackhi uint64
}

func (dbp *DebuggedProcess) allG() ([]*G, error) {
	reader := dbp.Dwarf.Reader()

	allglen, err := allglenval(dbp, reader)
	if err != nil {
		return nil, err
	}
	log.Print("allglen:", allglen)

	if dbp.allgaddr == 0 {
		reader.Seek(0)
		allgentryaddr, err := addressFor(dbp, "runtime.allg", reader)
		if err != nil {
			return nil, err
		}

		faddr, err := dbp.readMemory(uintptr(allgentryaddr), int(ptrsize))
		if err != nil {
			return nil, err
		}

		dbp.allgaddr = binary.LittleEndian.Uint64(faddr)
	}
	log.Print("allgaddr:", dbp.allgaddr)

	allgptrbytes, err := dbp.readMemory(uintptr(dbp.allgaddr), int(allglen*uint64(ptrsize)))
	if err != nil {
		return nil, err
	}
	log.Print("allgptrbytes:", allgptrbytes)

	allg := make([]*G, allglen)
	for i := uint64(0); i < allglen; i++ {
		gaddr := binary.LittleEndian.Uint64(allgptrbytes[i*8 : i*8+8])
		gbytes, err := dbp.readMemory(uintptr(gaddr), 136)
		if err != nil {
			return nil, err
		}

		gid := binary.LittleEndian.Uint64(gbytes[128 : 128+8])
		lo := binary.LittleEndian.Uint64(gbytes[:8])
		hi := binary.LittleEndian.Uint64(gbytes[8 : 8+8])
		log.Printf("allg: gid: %#v, lo: %#v, hi: %#v\n", gid, lo, hi)

		allg[i] = &G{int(gid), lo, hi}
	}

	return allg, nil
}

//Find goroutine id by compare SP with G struct's stack field (stack.lo <= SP <= stack.hi)
//FIXME: It's hacky, need better way to find thread's goroutine. I've already tried and failed: 1)read tls 2)use procid field (not work on OSX)
func (dbp *DebuggedProcess) getGoroutineId(tid int) (int, error) {
	regs, err := registers(tid)
	if err != nil {
		return 0, err
	}

	sp := regs.SP()
	reader := dbp.Dwarf.Reader()

	allglen, err := allglenval(dbp, reader)
	if err != nil {
		return 0, err
	}

	if dbp.allgaddr == 0 {
		reader.Seek(0)
		allgentryaddr, err := addressFor(dbp, "runtime.allg", reader)
		if err != nil {
			return 0, err
		}

		faddr, err := dbp.readMemory(uintptr(allgentryaddr), int(ptrsize))
		if err != nil {
			return 0, err
		}

		dbp.allgaddr = binary.LittleEndian.Uint64(faddr)
	}

	allgptrbytes, err := dbp.readMemory(uintptr(dbp.allgaddr), int(allglen*uint64(ptrsize)))
	if err != nil {
		return 0, err
	}

	for i := uint64(0); i < allglen; i++ {
		gaddr := binary.LittleEndian.Uint64(allgptrbytes[i*8 : i*8+8])
		gbytes, err := dbp.readMemory(uintptr(gaddr), 136)
		if err != nil {
			return 0, err
		}

		gid := binary.LittleEndian.Uint64(gbytes[128 : 128+8])
		lo := binary.LittleEndian.Uint64(gbytes[:8])
		hi := binary.LittleEndian.Uint64(gbytes[8 : 8+8])

		log.Printf("sp %#v, gid: %#v, lo: %#v, hi: %#v", sp, gid, lo, hi)
		if lo <= sp && sp <= hi {
			return int(gid), nil
		}

		if err != nil {
			return 0, err
		}
	}

	//return 0, fmt.Errorf("Can't find goroutine by sp: %#v", sp)
	return 0, nil
}

func (dbp *DebuggedProcess) allGoroutineIds() ([]int, error) {
	reader := dbp.Dwarf.Reader()

	allglen, err := allglenval(dbp, reader)
	if err != nil {
		return nil, err
	}

	allgaddr, err := dbp.getAllgaddr(reader)
	if err != nil {
		return nil, err
	}

	allgptrbytes, err := dbp.readMemory(uintptr(allgaddr), int(allglen*uint64(ptrsize)))
	if err != nil {
		return nil, err
	}

	gids := make([]int, allglen)
	for i := uint64(0); i < allglen; i++ {
		gaddr := binary.LittleEndian.Uint64(allgptrbytes[i*8 : i*8+8])
		gbytes, err := dbp.readMemory(uintptr(gaddr+128), 8)
		if err != nil {
			return nil, err
		}

		gid := binary.LittleEndian.Uint64(gbytes)
		gids = append(gids, int(gid))
	}

	return gids, nil
}

func (dbp *DebuggedProcess) getAllgaddr(reader *dwarf.Reader) (uint64, error) {
	if dbp.allgaddr == 0 {
		reader.Seek(0)
		allgentryaddr, err := addressFor(dbp, "runtime.allg", reader)
		if err != nil {
			return 0, err
		}

		faddr, err := dbp.readMemory(uintptr(allgentryaddr), int(ptrsize))
		if err != nil {
			return 0, err
		}

		dbp.allgaddr = binary.LittleEndian.Uint64(faddr)
	}

	return dbp.allgaddr, nil
}

func (dbp *DebuggedProcess) PrintGoroutinesInfo() error {
	reader := dbp.Dwarf.Reader()

	allglen, err := allglenval(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	allgentryaddr, err := addressFor(dbp, "runtime.allg", reader)
	if err != nil {
		return err
	}
	fmt.Printf("[%d goroutines]\n", allglen)
	faddr, err := dbp.readMemory(uintptr(allgentryaddr), int(ptrsize))
	allg := binary.LittleEndian.Uint64(faddr)

	for i := uint64(0); i < allglen; i++ {
		err = printGoroutineInfo(dbp, allg+(i*uint64(ptrsize)), reader)
		if err != nil {
			return err
		}
	}

	return nil
}

func printGoroutineInfo(dbp *DebuggedProcess, addr uint64, reader *dwarf.Reader) error {
	gaddrbytes, err := dbp.readMemory(uintptr(addr), int(ptrsize))
	if err != nil {
		return fmt.Errorf("error derefing *G %s", err)
	}
	initialInstructions := append([]byte{op.DW_OP_addr}, gaddrbytes...)

	reader.Seek(0)
	goidaddr, err := offsetFor("goid", reader, initialInstructions)
	if err != nil {
		return err
	}

	reader.Seek(0)
	schedaddr, err := offsetFor("sched", reader, initialInstructions)
	if err != nil {
		return err
	}

	goidbytes, err := dbp.readMemory(uintptr(goidaddr), int(ptrsize))
	if err != nil {
		return fmt.Errorf("error reading goid %s", err)
	}

	stacklobytes, err := dbp.readMemory(uintptr(addr), int(ptrsize))
	if err != nil {
		return fmt.Errorf("error reading stack %s", err)
	}
	stacklo := binary.LittleEndian.Uint64(stacklobytes)

	stackhibytes, err := dbp.readMemory(uintptr(addr+uint64(ptrsize)), int(ptrsize))
	if err != nil {
		return fmt.Errorf("error reading stack %s", err)
	}
	stackhi := binary.LittleEndian.Uint64(stackhibytes)

	schedbytes, err := dbp.readMemory(uintptr(schedaddr+uint64(ptrsize)), int(ptrsize))
	if err != nil {
		return fmt.Errorf("error reading sched %s", err)
	}
	gopc := binary.LittleEndian.Uint64(schedbytes)
	f, l, fn := dbp.GoSymTable.PCToLine(gopc)
	fname := ""
	if fn != nil {
		fname = fn.Name
	}
	fmt.Printf("Goroutine %d - %s:%d %s\tstack:[%#v-%#v)\n", binary.LittleEndian.Uint64(goidbytes), f, l, fname, stacklo, stackhi)
	return nil
}

func allglenval(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	if dbp.allglenaddr == 0 {
		entry, err := findDwarfEntry("runtime.allglen", reader, false)
		if err != nil {
			return 0, err
		}

		instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
		if !ok {
			return 0, fmt.Errorf("type assertion failed")
		}
		addr, err := op.ExecuteStackProgram(0, instructions)
		if err != nil {
			return 0, err
		}
		dbp.allglenaddr = uint64(addr)
	}
	val, err := dbp.readMemory(uintptr(dbp.allglenaddr), 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(val), nil
}

func addressFor(dbp *DebuggedProcess, name string, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry(name, reader, false)
	if err != nil {
		return 0, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

func offsetFor(name string, reader *dwarf.Reader, parentinstr []byte) (uint64, error) {
	entry, err := findDwarfEntry(name, reader, true)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	offset, err := op.ExecuteStackProgram(0, append(parentinstr, instructions...))
	if err != nil {
		return 0, err
	}

	return uint64(offset), nil
}

// Returns the value of the named symbol.
func (g *Goroutine) EvalSymbol(name string) (*Variable, error) {
	pc, err := g.pc()
	if err != nil {
		return nil, err
	}

	reader := g.dbp.DwarfReader()

	_, err = reader.SeekToFunction(pc)
	if err != nil {
		return nil, err
	}

	varName := name
	memberName := ""
	if strings.Contains(name, ".") {
		idx := strings.Index(name, ".")
		varName = name[:idx]
		memberName = name[idx+1:]
	}

	for entry, err := reader.NextScopeVariable(); entry != nil; entry, err = reader.NextScopeVariable() {
		if err != nil {
			return nil, err
		}

		n, ok := entry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}

		if n == varName {
			if len(memberName) == 0 {
				return g.extractVariableFromEntry(entry)
			}
			return g.evaluateStructMember(entry, reader, memberName)
		}
	}

	return nil, fmt.Errorf("could not find symbol value for %s", name)
}

func findDwarfEntry(name string, reader *dwarf.Reader, member bool) (*dwarf.Entry, error) {
	depth := 1
	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return nil, err
		}

		if entry.Children {
			depth++
		}

		if entry.Tag == 0 {
			depth--
			if depth <= 0 {
				return nil, fmt.Errorf("could not find symbol value for %s", name)
			}
		}

		if member {
			if entry.Tag != dwarf.TagMember {
				continue
			}
		} else {
			if entry.Tag != dwarf.TagVariable && entry.Tag != dwarf.TagFormalParameter && entry.Tag != dwarf.TagStructType {
				continue
			}
		}

		n, ok := entry.Val(dwarf.AttrName).(string)
		if !ok || n != name {
			continue
		}
		return entry, nil
	}
	return nil, fmt.Errorf("could not find symbol value for %s", name)
}

func (g *Goroutine) evaluateStructMember(parentEntry *dwarf.Entry, reader *reader.Reader, memberName string) (*Variable, error) {
	parentAddr, err := g.extractVariableDataAddress(parentEntry, reader)
	if err != nil {
		return nil, err
	}

	// Get parent variable name
	parentName, ok := parentEntry.Val(dwarf.AttrName).(string)
	if !ok {
		return nil, fmt.Errorf("unable to retrive variable name")
	}

	// Seek reader to the type information so members can be iterated
	_, err = reader.SeekToType(parentEntry, true, true)
	if err != nil {
		return nil, err
	}

	// Iterate to find member by name
	for memberEntry, err := reader.NextMemberVariable(); memberEntry != nil; memberEntry, err = reader.NextMemberVariable() {
		if err != nil {
			return nil, err
		}

		name, ok := memberEntry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}

		if name == memberName {
			// Nil ptr, wait until here to throw a nil pointer error to prioritize no such member error
			if parentAddr == 0 {
				return nil, fmt.Errorf("%s is nil", parentName)
			}

			memberInstr, err := instructionsForEntry(memberEntry)
			if err != nil {
				return nil, err
			}

			offset, ok := memberEntry.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok {
				return nil, fmt.Errorf("type assertion failed")
			}

			data := g.dbp.Dwarf
			t, err := data.Type(offset)
			if err != nil {
				return nil, err
			}

			baseAddr := make([]byte, 8)
			binary.LittleEndian.PutUint64(baseAddr, uint64(parentAddr))

			parentInstructions := append([]byte{op.DW_OP_addr}, baseAddr...)
			val, err := g.extractValue(append(parentInstructions, memberInstr...), 0, t)
			if err != nil {
				return nil, err
			}
			return &Variable{Name: strings.Join([]string{parentName, memberName}, "."), Type: t.String(), Value: val}, nil
		}
	}

	return nil, fmt.Errorf("%s has no member %s", parentName, memberName)
}

// Extracts the name, type, and value of a variable from a dwarf entry
func (g *Goroutine) extractVariableFromEntry(entry *dwarf.Entry) (*Variable, error) {
	if entry == nil {
		return nil, fmt.Errorf("invalid entry")
	}

	if entry.Tag != dwarf.TagFormalParameter && entry.Tag != dwarf.TagVariable {
		return nil, fmt.Errorf("invalid entry tag, only supports FormalParameter and Variable, got %s", entry.Tag.String())
	}

	n, ok := entry.Val(dwarf.AttrName).(string)
	if !ok {
		return nil, fmt.Errorf("type assertion failed")
	}

	offset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, fmt.Errorf("type assertion failed")
	}

	data := g.dbp.Dwarf
	t, err := data.Type(offset)
	if err != nil {
		return nil, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return nil, fmt.Errorf("type assertion failed")
	}

	val, err := g.extractValue(instructions, 0, t)
	if err != nil {
		return nil, err
	}

	return &Variable{Name: n, Type: t.String(), Value: val}, nil
}

// Execute the stack program taking into account the current stack frame
func (g *Goroutine) executeStackProgram(instructions []byte) (int64, error) {
	regs, err := registers(g.tid)
	if err != nil {
		return 0, err
	}

	fde, err := g.dbp.FrameEntries.FDEForPC(regs.PC())
	if err != nil {
		return 0, err
	}

	fctx := fde.EstablishFrame(regs.PC())
	cfa := fctx.CFAOffset() + int64(regs.SP())
	address, err := op.ExecuteStackProgram(cfa, instructions)
	if err != nil {
		return 0, err
	}
	return address, nil
}

// Extracts the address of a variable, dereferencing any pointers
func (g *Goroutine) extractVariableDataAddress(entry *dwarf.Entry, reader *reader.Reader) (int64, error) {
	instructions, err := instructionsForEntry(entry)
	if err != nil {
		return 0, err
	}

	address, err := g.executeStackProgram(instructions)
	if err != nil {
		return 0, err
	}

	// Dereference pointers to get down the concrete type
	for typeEntry, err := reader.SeekToType(entry, true, false); typeEntry != nil; typeEntry, err = reader.SeekToType(typeEntry, true, false) {
		if err != nil {
			return 0, err
		}

		if typeEntry.Tag != dwarf.TagPointerType {
			break
		}

		ptraddress := uintptr(address)

		ptr, err := g.dbp.readMemory(ptraddress, int(ptrsize))
		if err != nil {
			return 0, err
		}
		address = int64(binary.LittleEndian.Uint64(ptr))
	}

	return address, nil
}

// Extracts the value from the instructions given in the DW_AT_location entry.
// We execute the stack program described in the DW_OP_* instruction stream, and
// then grab the value from the other processes memory.
func (g *Goroutine) extractValue(instructions []byte, addr int64, typ interface{}) (string, error) {
	var err error

	if addr == 0 {
		addr, err = g.executeStackProgram(instructions)
		if err != nil {
			return "", err
		}
	}

	// If we have a user defined type, find the
	// underlying concrete type and use that.
	if tt, ok := typ.(*dwarf.TypedefType); ok {
		typ = tt.Type
	}

	ptraddress := uintptr(addr)
	switch t := typ.(type) {
	case *dwarf.PtrType:
		ptr, err := g.dbp.readMemory(ptraddress, int(ptrsize))
		if err != nil {
			return "", err
		}

		intaddr := int64(binary.LittleEndian.Uint64(ptr))
		if intaddr == 0 {
			return fmt.Sprintf("%s nil", t.String()), nil
		}

		val, err := g.extractValue(nil, intaddr, t.Type)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("*%s", val), nil
	case *dwarf.StructType:
		switch t.StructName {
		case "string":
			return g.readString(ptraddress)
		case "[]int":
			return g.readIntSlice(ptraddress, t)
		default:
			// Recursively call extractValue to grab
			// the value of all the members of the struct.
			fields := make([]string, 0, len(t.Field))
			for _, field := range t.Field {
				val, err := g.extractValue(nil, field.ByteOffset+addr, field.Type)
				if err != nil {
					return "", err
				}

				fields = append(fields, fmt.Sprintf("%s: %s", field.Name, val))
			}
			retstr := fmt.Sprintf("%s {%s}", t.StructName, strings.Join(fields, ", "))
			return retstr, nil
		}
	case *dwarf.ArrayType:
		return g.readIntArray(ptraddress, t)
	case *dwarf.IntType:
		return g.readInt(ptraddress, t.ByteSize)
	case *dwarf.FloatType:
		return g.readFloat(ptraddress, t.ByteSize)
	}

	return "", fmt.Errorf("could not find value for type %s", typ)
}

func (g *Goroutine) readString(addr uintptr) (string, error) {
	// string data structure is always two ptrs in size. Addr, followed by len
	// http://research.swtch.com/godata

	// read len
	val, err := g.dbp.readMemory(addr+ptrsize, int(ptrsize))
	if err != nil {
		return "", err
	}
	strlen := uintptr(binary.LittleEndian.Uint64(val))

	// read addr
	val, err = g.dbp.readMemory(addr, int(ptrsize))
	if err != nil {
		return "", err
	}
	addr = uintptr(binary.LittleEndian.Uint64(val))

	val, err = g.dbp.readMemory(addr, int(strlen))
	if err != nil {
		return "", err
	}

	return *(*string)(unsafe.Pointer(&val)), nil
}

func (g *Goroutine) readIntSlice(addr uintptr, t *dwarf.StructType) (string, error) {
	val, err := g.dbp.readMemory(addr, 24)
	if err != nil {
		return "", err
	}

	a := binary.LittleEndian.Uint64(val[:8])
	l := binary.LittleEndian.Uint64(val[8:16])
	c := binary.LittleEndian.Uint64(val[16:24])

	val, err = g.dbp.readMemory(uintptr(a), int(uint64(ptrsize)*l))
	if err != nil {
		return "", err
	}

	switch t.StructName {
	case "[]int":
		members := *(*[]int)(unsafe.Pointer(&val))
		setSliceLength(unsafe.Pointer(&members), int(l))
		return fmt.Sprintf("len: %d cap: %d %d", l, c, members), nil
	}
	return "", fmt.Errorf("Could not read slice")
}

func (g *Goroutine) readIntArray(addr uintptr, t *dwarf.ArrayType) (string, error) {
	val, err := g.dbp.readMemory(addr, int(t.ByteSize))
	if err != nil {
		return "", err
	}

	switch t.Type.Size() {
	case 4:
		members := *(*[]uint32)(unsafe.Pointer(&val))
		setSliceLength(unsafe.Pointer(&members), int(t.Count))
		return fmt.Sprintf("%s %d", t, members), nil
	case 8:
		members := *(*[]uint64)(unsafe.Pointer(&val))
		setSliceLength(unsafe.Pointer(&members), int(t.Count))
		return fmt.Sprintf("%s %d", t, members), nil
	}
	return "", fmt.Errorf("Could not read array")
}

func (g *Goroutine) readInt(addr uintptr, size int64) (string, error) {
	var n int

	val, err := g.dbp.readMemory(addr, int(size))
	if err != nil {
		return "", err
	}

	switch size {
	case 1:
		n = int(val[0])
	case 2:
		n = int(binary.LittleEndian.Uint16(val))
	case 4:
		n = int(binary.LittleEndian.Uint32(val))
	case 8:
		n = int(binary.LittleEndian.Uint64(val))
	}

	return strconv.Itoa(n), nil
}

func (g *Goroutine) readFloat(addr uintptr, size int64) (string, error) {
	val, err := g.dbp.readMemory(addr, int(size))
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(val)

	switch size {
	case 4:
		n := float32(0)
		binary.Read(buf, binary.LittleEndian, &n)
		return strconv.FormatFloat(float64(n), 'f', -1, int(size)*8), nil
	case 8:
		n := float64(0)
		binary.Read(buf, binary.LittleEndian, &n)
		return strconv.FormatFloat(n, 'f', -1, int(size)*8), nil
	}

	return "", fmt.Errorf("could not read float")
}

// Fetches all variables of a specific type in the current function scope
func (g *Goroutine) variablesByTag(tag dwarf.Tag) ([]*Variable, error) {
	pc, err := g.pc()
	if err != nil {
		return nil, err
	}

	reader := g.dbp.DwarfReader()

	_, err = reader.SeekToFunction(pc)
	if err != nil {
		return nil, err
	}

	vars := make([]*Variable, 0)

	for entry, err := reader.NextScopeVariable(); entry != nil; entry, err = reader.NextScopeVariable() {
		if err != nil {
			return nil, err
		}

		if entry.Tag == tag {
			val, err := g.extractVariableFromEntry(entry)
			if err != nil {
				return nil, err
			}

			vars = append(vars, val)
		}
	}

	return vars, nil
}

// LocalVariables returns all local variables from the current function scope
func (dbp *DebuggedProcess) LocalVariables() ([]*Variable, error) {
	return dbp.currentGoroutine.variablesByTag(dwarf.TagVariable)
}

func (dbp *DebuggedProcess) PrintRegs() {
	regs, err := registers(dbp.currentGoroutine.tid)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%#v", regs)
}

// FunctionArguments returns the name, value, and type of all current function arguments
func (dbp *DebuggedProcess) FunctionArguments() ([]*Variable, error) {
	return dbp.currentGoroutine.variablesByTag(dwarf.TagFormalParameter)
}

// Sets the length of a slice.
func setSliceLength(ptr unsafe.Pointer, l int) {
	lptr := (*int)(unsafe.Pointer(uintptr(ptr) + ptrsize))
	*lptr = l
}
