package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
)

func main() {
	// Start a goroutine with an HTTP server for runtime profiling
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Enable CPU profiling
	f, err := os.Create("cpu.prof")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	// Test different prime lengths
	for _, bits := range []int{512, 1024, 2048} {
		fmt.Printf("Testing with prime length: %d bits\n", bits)
		zk13 := NewZK13("shared secret", bits) // Adjust NewZK13 to accept prime length as an argument
		r, P := zk13.Prover()
		isValid := zk13.Verifier(r, P)
		fmt.Printf("Verification with %d bits prime: %v\n", bits, isValid)
	}

	// Memory profiling
	mf, err := os.Create("mem.prof")
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer mf.Close()
	runtime.GC() // get up-to-date statistics
	if err := pprof.WriteHeapProfile(mf); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}
}
