package goreadline

//#include <readline/readline.h>
//#include <readline/history.h>
import "C"
import (
	"os"
	"os/signal"
	"syscall"
)

func init() {
	C.rl_catch_sigwinch = 0
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGWINCH)
	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGWINCH:
				Resize()
			default:

			}
		}
	}()
}

func Resize() {
	C.rl_resize_terminal()
}
