package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/derekparker/delve/client/cli"
)

const version string = "0.3.0.beta"

func main() {
	var (
		pid    int
		run    bool
		printv bool
	)

	flag.IntVar(&pid, "pid", 0, "Pid of running process to attach to.")
	flag.BoolVar(&run, "run", false, "Compile program and begin debug session.")
	flag.BoolVar(&printv, "v", false, "Print version number and exit.")
	flag.Parse()

	if flag.NFlag() == 0 && len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	if printv {
		fmt.Printf("Delve version: %s\n", version)
		os.Exit(0)
	}

	cli.Run(run, pid, flag.Args())
}
