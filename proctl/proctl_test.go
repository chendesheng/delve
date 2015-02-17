package proctl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func withTestProcess(name string, t *testing.T, fn func(p *DebuggedProcess)) {
	runtime.LockOSThread()
	base := filepath.Base(name)
	if err := exec.Command("go", "build", "-gcflags=-N -l", "-o", base, name+".go").Run(); err != nil {
		t.Fatalf("Could not compile %s due to %s", name, err)
	}
	defer os.Remove("./" + base)

	p, err := Launch([]string{"./" + base})
	if err != nil {
		t.Fatal("Launch():", err)
	}

	p.Listen(func() {
		fn(p)
	})
}

func getRegisters(p *DebuggedProcess, t *testing.T) Registers {
	regs, err := p.Registers()
	if err != nil {
		t.Fatal("Registers():", err)
	}

	return regs
}

func assertNoError(err error, t *testing.T, s string) {
	if err != nil {
		t.Fatal(s, ":", err)
	}
}

func currentPC(p *DebuggedProcess, t *testing.T) uint64 {
	pc, err := p.currentGoroutine.pc()
	if err != nil {
		t.Fatal(err)
	}

	return pc
}

func currentLineNumber(p *DebuggedProcess, t *testing.T) (string, int) {
	pc := currentPC(p, t)
	f, l, _ := p.GoSymTable.PCToLine(pc)

	return f, l
}

func TestStep(t *testing.T) {
	withTestProcess("../_fixtures/testprog", t, func(p *DebuggedProcess) {
		if p.currentGoroutine.id == 0 {
			helloworldfunc := p.GoSymTable.LookupFunc("main.helloworld")
			helloworldaddr := helloworldfunc.Entry

			_, err := p.Break(helloworldaddr)
			assertNoError(err, t, "Break()")
			assertNoError(p.Continue(), t, "Continue()")
			return
		}

		regs := getRegisters(p, t)
		rip := regs.PC()

		err := p.Step()
		assertNoError(err, t, "Step()")

		regs = getRegisters(p, t)
		if rip >= regs.PC() {
			t.Errorf("Expected %#v to be greater than %#v", regs.PC(), rip)
		}

		go func() {
			time.Sleep(100 * time.Millisecond)
			if err := p.Process.Kill(); err != nil {
				log.Fatal(err)
			}
		}()

		p.ClearByLocation("main.helloworld")
		p.Continue()
	})
}

func TestStepProcess(t *testing.T) {
	files := []string{"../_fixtures/testprog", "../_fixtures/testprog"}
	lines := []int{18, 10}
	steptimes := []int{1, 2}
	linesafter := []int{8, 19}

	for i := 0; i < len(files); i++ {
		withTestProcess(files[i], t, func(p *DebuggedProcess) {
			fp, err := filepath.Abs(files[i] + ".go")
			if err != nil {
				t.Fatal(err)
			}

			pc, _, _ := p.GoSymTable.LineToPC(fp, lines[i])
			fmt.Printf("line %d pc:0x%x\n", lines[i], pc)

			if p.currentGoroutine.id == 0 {
				if _, err := p.Break(pc); err != nil {
					t.Fatal(err)
				}

				if err := p.Continue(); err != nil {
					t.Fatal(err)
				}
			}

			for j := 0; j < steptimes[i]; j++ {
				pc, err = p.CurrentPC()
				if err != nil {
					t.Fatal(err)
				}

				fmt.Printf("pc:0x%x\n", pc)
				if err := p.Step(); err != nil {
					t.Fatal(err)
				}
			}

			pc, err = p.CurrentPC()
			if err != nil {
				t.Fatal(err)
			}

			_, l, _ := p.GoSymTable.PCToLine(pc)
			if linesafter[i] != l {
				t.Fatalf("Cases %d: Expect current pc in line %d but %d", i, linesafter[i], l)
			}

			go func() {
				if err := p.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			}()

			p.Continue()
		})
	}
}

func TestContinue(t *testing.T) {
	withTestProcess("../_fixtures/continuetestprog", t, func(p *DebuggedProcess) {
		err := p.Continue()
		if err != nil {
			t.Error(err)
		}

		state, err := p.Process.Wait()
		if err != nil {
			t.Error(err)
		}

		if !state.Exited() {
			t.Fatal("Process did not exit successfully:", state)
		}

	})
}

func TestBreakpoint(t *testing.T) {
	breakpc := uint64(0)
	withTestProcess("../_fixtures/testprog", t, func(p *DebuggedProcess) {
		sleepytimefunc := p.GoSymTable.LookupFunc("main.helloworld")
		sleepyaddr := sleepytimefunc.Entry

		if p.currentGoroutine.id == 0 {
			bp, err := p.Break(sleepyaddr)
			assertNoError(err, t, "Break()")

			breakpc = bp.Addr
			err = p.Continue()
			assertNoError(err, t, "Continue()")

		}

		pc, err := p.CurrentPC()
		if err != nil {
			t.Fatal(err)
		}

		if pc != breakpc && pc-1 != breakpc { //if use HWBreakpoints pc == breakpc, if use 0xcc pc-1==breakpc
			f, l, _ := p.GoSymTable.PCToLine(pc)
			t.Fatalf("Break not respected:\nPC:%#v %s:%d\nFN:%#v \n", pc, f, l, breakpc)
		}

		err = p.Step()
		assertNoError(err, t, "Step()")

		pc, err = p.CurrentPC()
		if err != nil {
			t.Fatal(err)
		}

		if pc == breakpc {
			t.Fatalf("Step not respected:\nPC:%d\nFN:%d\n", pc, breakpc)
		}

		go func() {
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}()

		p.ClearByLocation("main.helloworld")
		p.Continue()
	})
}

func TestBreakpointInSeperateGoRoutine(t *testing.T) {
	withTestProcess("../_fixtures/testthreads", t, func(p *DebuggedProcess) {
		fn := p.GoSymTable.LookupFunc("main.anotherthread")
		if fn == nil {
			t.Fatal("No fn exists")
		}

		if p.currentGoroutine.id == 0 {
			_, err := p.Break(fn.Entry)
			if err != nil {
				t.Fatal(err)
			}

			err = p.Continue()
			if err != nil {
				t.Fatal(err)
			}
			return
		}

		pc, err := p.CurrentPC()
		if err != nil {
			t.Fatal(err)
		}

		f, l, _ := p.GoSymTable.PCToLine(pc)
		if f != "testthreads.go" && l != 8 {
			t.Fatal("Program did not hit breakpoint")
		}

		p.Process.Kill()
		os.Remove("./testthreads")
		os.Exit(0)
	})
}

func TestBreakpointWithNonExistantFunction(t *testing.T) {
	withTestProcess("../_fixtures/testprog", t, func(p *DebuggedProcess) {
		_, err := p.Break(0)
		if err == nil {
			t.Fatal("Should not be able to break at non existant function")
		}
	})
}

func TestClearBreakpoint(t *testing.T) {
	withTestProcess("../_fixtures/testprog", t, func(p *DebuggedProcess) {
		fn := p.GoSymTable.LookupFunc("main.sleepytime")

		bp, err := p.Break(fn.Entry)
		assertNoError(err, t, "Break()")

		bp, err = p.Clear(fn.Entry)
		assertNoError(err, t, "Clear()")

		data, err := p.readMemory(uintptr(bp.Addr), 1)
		if err != nil {
			t.Fatal(err)
		}

		int3 := []byte{0xcc}
		if bytes.Equal(data, int3) {
			t.Fatalf("Breakpoint was not cleared data: %#v, int3: %#v", data, int3)
		}

		if len(p.Breakpoints) != 0 {
			t.Fatal("Breakpoint not removed internally")
		}

		go func() {
			time.Sleep(100 * time.Millisecond)
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}()

		p.Continue()

	})
}

func TestNext(t *testing.T) {
	var (
		err            error
		executablePath = "../_fixtures/testnextprog"
	)

	testcases := []struct {
		begin, end int
	}{
		{19, 20},
		{20, 23},
		{23, 24},
		{24, 26},
		{26, 31},
		{31, 23},
		{23, 24},
		{24, 26},
		{26, 31},
		{31, 23},
		{23, 24},
		{24, 26},
		{26, 27},
		{27, 34},
		{34, 35},
		{35, 41},
		{41, 40},
		{40, 19},
	}
	fp, err := filepath.Abs("../_fixtures/testnextprog.go")
	if err != nil {
		t.Fatal(err)
	}

	withTestProcess(executablePath, t, func(p *DebuggedProcess) {
		pc, _, _ := p.GoSymTable.LineToPC(fp, testcases[0].begin)
		_, err := p.Break(pc)
		fmt.Printf("pc:%#v\n", pc)
		if err == nil {
			assertNoError(p.Continue(), t, "Continue()")
		}

		for _, tc := range testcases {
			f, ln := currentLineNumber(p, t)
			if ln != tc.begin {
				t.Fatalf("Program not stopped at correct spot expected %d was %s:%d", tc.begin, f, ln)
			}

			assertNoError(p.Next(), t, "Next() returned an error")

			f, ln = currentLineNumber(p, t)
			if ln != tc.end {
				t.Fatalf("Program did not continue to correct next location expected %d was %s:%d", tc.end, f, ln)
			}
		}

		p.Clear(pc)
		if len(p.Breakpoints) != 0 {
			t.Fatal("Not all breakpoints were cleaned up", len(p.Breakpoints))
		}

		go func() {
			os.Exit(0)
		}()

		p.Continue()
	})
}

func TestFindReturnAddress(t *testing.T) {
	var testfile, _ = filepath.Abs("../_fixtures/testnextprog")

	withTestProcess(testfile, t, func(p *DebuggedProcess) {
		var (
			fdes = p.FrameEntries
			gsd  = p.GoSymTable
		)

		testsourcefile := testfile + ".go"
		start, _, err := gsd.LineToPC(testsourcefile, 24)

		if p.currentGoroutine.id == 0 {
			if err != nil {
				t.Fatal(err)
			}

			_, err = p.Break(start)
			if err != nil {
				t.Fatal(err)
			}

			err = p.Continue()
			if err != nil {
				t.Fatal(err)
			}
			return
		}

		regs, err := p.Registers()
		if err != nil {
			t.Fatal(err)
		}

		fde, err := fdes.FDEForPC(start)
		if err != nil {
			t.Fatal(err)
		}

		ret := fde.ReturnAddressOffset(start)
		if err != nil {
			t.Fatal(err)
		}

		addr := uint64(int64(regs.SP()) + ret)
		data, _ := p.readMemory(uintptr(addr), 8)
		addr = binary.LittleEndian.Uint64(data)

		f, l, fn := gsd.PCToLine(addr)
		log.Println(f, ":", l, " ", fn.Name)

		if l != 41 {
			t.Fatalf("return address not found correctly, expected line 41 got %d", l)
		}

		if fn.Name != "main.main" {
			t.Fatalf("return function not found correctly, expected main.main got %s", fn.Name)
		}

		go func() {
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}()

		p.Continue()
	})
}

func TestNext2(t *testing.T) {
	var testfile, _ = filepath.Abs("../_fixtures/testprog")

	withTestProcess(testfile, t, func(p *DebuggedProcess) {
		if p.currentGoroutine.id == 0 {
			start, _, err := p.GoSymTable.LineToPC(testfile+".go", 16)
			if err != nil {
				t.Fatal(err)
			}

			_, err = p.Break(start)
			if err != nil {
				t.Fatal(err)
			}
			p.Continue()
			return
		}

		if err := p.Next(); err != nil {
			t.Fatal(err)
		}

		_, cl := currentLineNumber(p, t)
		if cl != 18 {
			t.Fatalf("Expect pc at line %d but %d", 18, cl)
		}

		go func() {
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}()

		p.Continue()
	})
}

func TestNext3(t *testing.T) {
	var testfile, _ = filepath.Abs("../_fixtures/testprog")

	withTestProcess(testfile, t, func(p *DebuggedProcess) {
		if p.currentGoroutine.id == 0 {
			start, _, err := p.GoSymTable.LineToPC(testfile+".go", 9)
			if err != nil {
				t.Fatal(err)
			}

			_, err = p.Break(start)
			if err != nil {
				t.Fatal(err)
			}
			p.Continue()
			return
		}

		nextCheckLinenext(p, t, 10)
		nextCheckLinenext(p, t, 19)

		go func() {
			if err := p.Process.Kill(); err != nil {
				t.Fatal(err)
			}
		}()

		p.Continue()
	})
}

func nextCheckLinenext(p *DebuggedProcess, t *testing.T, expectedline int) {
	_, cl := next(p, t)
	if cl != expectedline {
		t.Fatalf("Expect pc at line %d but %d", expectedline, cl)
	}
}

func next(p *DebuggedProcess, t *testing.T) (string, int) {
	if err := p.Next(); err != nil {
		t.Fatal(err)
	}

	return currentLineNumber(p, t)
}

func TestConcurrent(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	var testfile, _ = filepath.Abs("../_fixtures/concurrentprog")

	withTestProcess(testfile, t, func(p *DebuggedProcess) {
		start, _, err := p.GoSymTable.LineToPC(testfile+".go", 12)
		if err != nil {
			t.Fatal(err)
		}

		p.Break(start)

		p.Continue()
		p.Continue()
		p.Continue()
	})
}

func TestConcurrent2(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	var testfile, _ = filepath.Abs("../_fixtures/concurrentprog")

	withTestProcess(testfile, t, func(p *DebuggedProcess) {
		start, _, err := p.GoSymTable.LineToPC(testfile+".go", 11)
		if err != nil {
			t.Fatal(err)
		}

		p.Break(start)

		p.Continue()
		p.Continue()
		p.Continue()
	})
}
