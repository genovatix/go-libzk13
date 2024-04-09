package main

import (
	"fmt"
	"github.com/twingdev/go-libzk13/zkp"
	"log"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
)

func main() {
	runtime.GOMAXPROCS(7)
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

	// Run tests
	err = runTests()
	if err != nil {
		log.Fatalf("Error running tests: %v", err)
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

func runTests() error {
	// Test different prime lengths
	for _, bits := range []int{512, 1024, 2048, 2048 + 32} {
		fmt.Printf("Testing with prime length: %d bits\n", bits)
		zk13 := zkp.NewZK13("shared secret", bits) // Adjust NewZK13 to accept prime length as an argument
		nonce := zk13.GenerateNonce()              // Generate a nonce for replay attack protection
		proof, err := zk13.Prover(nonce)
		if err != nil {
			return fmt.Errorf("error generating proof: %v", err)
		}
		isValid := zk13.Verifier(proof)
		fmt.Printf("Verification with %d bits prime: %v\n", bits, isValid)
	}

	// Run timing attack test
	zk13 := zkp.NewZK13("shared secret", 2048) // Use a fixed prime length for timing attack test
	nonce := zk13.GenerateNonce()              // Generate a nonce for replay attack protection
	proof, err := zk13.Prover(nonce)
	if err != nil {
		return fmt.Errorf("error generating proof: %v", err)
	}
	isValid := zk13.Verifier(proof)
	if !isValid {
		return fmt.Errorf("proof should be valid")
	}

	// Modify the proof and verify that it is invalid
	proof.R.Add(proof.R, big.NewInt(1))
	isValid = zk13.Verifier(proof)
	if isValid {
		return fmt.Errorf("proof should be invalid")
	}

	// Modify the nonce and verify that the proof is invalid
	proof.Nonce.Add(proof.Nonce, big.NewInt(1))
	isValid = zk13.Verifier(proof)
	if isValid {
		return fmt.Errorf("proof should be invalid")
	}

	// Run replay attack test
	zk13 = zkp.NewZK13("shared secret", 2048) // Use a fixed prime length for replay attack test
	nonce = zk13.GenerateNonce()              // Generate a nonce for replay attack protection
	proof, err = zk13.Prover(nonce)
	if err != nil {
		return fmt.Errorf("error generating proof: %v", err)
	}
	isValid = zk13.Verifier(proof)
	if !isValid {
		return fmt.Errorf("proof should be valid")
	}

	// Use the same nonce to generate another proof
	proof2, err := zk13.Prover(nonce)
	if err != nil {
		return fmt.Errorf("error generating proof: %v", err)
	}
	isValid = zk13.Verifier(proof2)
	if isValid {
		return fmt.Errorf("proof should be invalid")
	}

	return nil
}
