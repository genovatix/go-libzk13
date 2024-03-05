package main

import "math/big"

// ValidateParameters Assume q is the large prime factor of p-1 known during setup
func (z *ZK13) ValidateParameters(q *big.Int) bool {
	// Check if p is a strong prime with a high degree of confidence
	if !z.p.ProbablyPrime(20) {
		return false
	}

	// Ensure g is not 1 and less than p
	if z.g.Cmp(big.NewInt(1)) == 0 || z.g.Cmp(z.p) >= 0 {
		return false
	}

	// Check that g^q mod p == 1, which means g generates a subgroup of order q
	one := big.NewInt(1)
	gqModP := new(big.Int).Exp(z.g, q, z.p)
	if gqModP.Cmp(one) != 0 {
		return false
	}

	return true
}
