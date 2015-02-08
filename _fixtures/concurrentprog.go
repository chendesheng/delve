package main

import (
	"sync"
)

func main() {
	w := sync.WaitGroup{}
	w.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			w.Done()
		}()
	}
	w.Wait()
}
