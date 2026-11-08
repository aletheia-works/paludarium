// Goroutines over channels, a mutex, a timer and a signal sent to itself.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

func main() {
	results := make(chan int)
	var wg sync.WaitGroup
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			results <- n * n
		}(i)
	}
	go func() { wg.Wait(); close(results) }()
	var squares []int
	for r := range results {
		squares = append(squares, r)
	}
	sort.Ints(squares)
	fmt.Println("squares", squares)

	var mu sync.Mutex
	total := 0
	var group sync.WaitGroup
	for i := 0; i < 100; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			mu.Lock()
			total++
			mu.Unlock()
		}()
	}
	group.Wait()
	fmt.Println("total", total)

	select {
	case <-time.After(20 * time.Millisecond):
		fmt.Println("timer fired")
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	fmt.Println("signal", <-signals)
}
