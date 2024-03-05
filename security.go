package main

import "math/big"

func validatePrime(p, g *big.Int) bool {
	// Example: ensure p is prime. In practice, more comprehensive checks are needed.
	return p.ProbablyPrime(20) && g.Cmp(big.NewInt(1)) > 0 && g.Cmp(p) < 0
}
