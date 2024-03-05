package main

import (
	"math/big"
	"testing"
)

func BenchmarkCalculateR(b *testing.B) {
	g := big.NewInt(7)
	k, _ := randBigInt(big.NewInt(100))
	p := big.NewInt(2741)

	for i := 0; i < b.N; i++ {
		calculateR(g, k, p)
	}
}

func BenchmarkCalculateP(b *testing.B) {
	g := big.NewInt(7)
	Hs := big.NewInt(88) // Simulating the hash result for benchmarking
	k, _ := randBigInt(big.NewInt(100))
	p := big.NewInt(2741)
	F := calculateF(Hs, k, p)

	for i := 0; i < b.N; i++ {
		calculateP(g, F, p)
	}
}

func BenchmarkVerify(b *testing.B) {
	g := big.NewInt(7)
	k, _ := randBigInt(big.NewInt(100))
	p := big.NewInt(2741)
	Hs := big.NewInt(88) // Simulating the hash result for benchmarking
	r := calculateR(g, k, p)
	F := calculateF(Hs, k, p)
	P := calculateP(g, F, p)

	for i := 0; i < b.N; i++ {
		verify(r, Hs, P, p)
	}
}
