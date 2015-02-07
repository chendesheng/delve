package cli

import (
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chendesheng/delve/command"
	"github.com/chendesheng/delve/goreadline"
	"github.com/chendesheng/delve/proctl"
)

const historyFile string = ".dbg_history"

func Run(run bool, pid int, args []string) {
	go func() {
		log.Print(http.ListenAndServe(":6061", nil))
	}()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var (
		dbp *proctl.DebuggedProcess
		err error
	)

	switch {
	case run:
		const debugname = "debug"
		cmd := exec.Command("go", "build", "-o", debugname, "-gcflags", "-N -l")
		err := cmd.Run()
		if err != nil {
			die(1, "Could not compile program:", err)
		}
		defer os.Remove(debugname)

		dbp, err = proctl.Launch(append([]string{"./" + debugname}, args...))
		if err != nil {
			die(1, "Could not launch program:", err)
		}
	case pid != 0:
		dbp, err = proctl.Attach(pid)
		if err != nil {
			die(1, "Could not attach to process:", err)
		}
	default:
		dbp, err = proctl.Launch(args)
		if err != nil {
			die(1, "Could not launch program:", err)
		}
	}

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT)
	go func() {
		for _ = range ch {
			if dbp.Running() {
				dbp.RequestManualStop()
			}
		}
	}()

	cmds := command.DebugCommands()
	goreadline.LoadHistoryFromFile(historyFile)
	fmt.Println("Type 'help' for list of commands.")

	dbp.Listen(func() {
		for {
			if err := command.PrintContext(dbp); err != nil {
				fmt.Print("Print context faild: ", err.Error())
			}

			cmdstr, err := promptForInput()
			if err != nil {
				if err == io.EOF {
					handleExit(dbp, 0)
				}
				die(1, "Prompt for input failed.\n")
			}

			cmdstr, args := parseCommand(cmdstr)

			if cmdstr == "exit" {
				handleExit(dbp, 0)
			}

			cmd := cmds.Find(cmdstr)
			err = cmd(dbp, args...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Command failed: %s\n", err)
			}
		}
	})
}

func handleExit(dbp *proctl.DebuggedProcess, status int) {
	errno := goreadline.WriteHistoryToFile(historyFile)
	if errno != 0 {
		fmt.Println("readline:", errno)
	}

	prompt := "Would you like to kill the process? [y/n]"
	answerp := goreadline.ReadLine(&prompt)
	if answerp == nil {
		die(2, io.EOF)
	}
	answer := strings.TrimSuffix(*answerp, "\n")

	for pc := range dbp.Breakpoints {
		if _, err := dbp.Clear(pc); err != nil {
			fmt.Printf("Can't clear breakpoint @%x: %s\n", pc, err)
		}
	}

	fmt.Println("Detaching from process...")
	dbp.Detach()

	if answer == "y" {
		fmt.Println("Killing process", dbp.Process.Pid)

		err := dbp.Process.Kill()
		if err != nil {
			fmt.Println("Could not kill process", err)
		}
	}

	die(status, "Hope I was of service hunting your bug!")
}

func die(status int, args ...interface{}) {
	fmt.Fprint(os.Stderr, args)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(status)
}

func parseCommand(cmdstr string) (string, []string) {
	vals := strings.Split(cmdstr, " ")
	return vals[0], vals[1:]
}

func promptForInput() (string, error) {
	prompt := "(dlv) "
	linep := goreadline.ReadLine(&prompt)
	if linep == nil {
		return "", io.EOF
	}
	line := strings.TrimSuffix(*linep, "\n")
	if line != "" {
		goreadline.AddHistory(line)
	}

	return line, nil
}
