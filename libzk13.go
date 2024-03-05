package main

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/zeebo/blake3"
)

const PrimeLength = 2048 // Ensure this is suitable for your security needs
const GENERATOR = 7
const PubKeyRange = 2044 // Size of k, ensure the range is suitable

type ZK13 struct {
	p, g, Hs *big.Int
}

// NewZK13 initializes the ZK13 structure with a prime number, generator, and hashed secret.
// It addresses the correct handling of byte slices and ensures that parameters are securely generated.
func NewZK13(secretBagage string, bits int) *ZK13 {
	var p *big.Int
	var err error
	z := &ZK13{}
	p, err = GenerateLargePrime(bits)

	if err != nil {
		panic(fmt.Sprintf("Failed to generate a large prime: %v", err))
	}
	g := big.NewInt(GENERATOR)
	z.g = g
	z.p = p
	if !z.ValidateParameters(big.NewInt(224)) {
		z.p = nil
		p, err = GenerateLargePrime(bits)
		z.p = p
	}
	hash := blake3.Sum512([]byte(secretBagage))
	Hs := new(big.Int).SetBytes(hash[:])

	z.Hs = Hs
	return z
}

func (z *ZK13) Prover() (*big.Int, *big.Int) {
	k, _ := rand.Int(rand.Reader, z.p) // Prover's random secret
	r := new(big.Int).Exp(z.g, k, z.p) // r = g^k mod p
	F := new(big.Int).Mul(z.Hs, k)     // F = Hs*k (simplified, not modulo p-1 for this example)
	P := new(big.Int).Exp(z.g, F, z.p) // P = g^F mod p
	return r, P
}

// Verifier checks if the provided proof (r, P) is valid  Verifier checks the proof using constant-time comparison
func (z *ZK13) Verifier(r, P *big.Int) bool {

	V := new(big.Int).Exp(r, z.Hs, z.p)
	// Convert V and P to byte slices for comparison
	VBytes := V.Bytes()
	PBytes := P.Bytes()

	// Use subtle.ConstantTimeCompare to prevent timing attacks
	return subtle.ConstantTimeCompare(VBytes, PBytes) == 1
}

func GenerateLargePrime(bit int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bit)
	if err != nil {
		return nil, err
	}
	return prime, nil
}

// calculateR calculates r = g^k mod p.
func (z *ZK13) calculateR(k *big.Int) *big.Int {
	return new(big.Int).Exp(z.g, k, z.p)
}

// calculateF calculates F = Hs*k mod (p-1).
func (z *ZK13) calculateF(k *big.Int) *big.Int {
	pMinusOne := new(big.Int).Sub(z.p, big.NewInt(1))
	return new(big.Int).Mod(new(big.Int).Mul(z.Hs, k), pMinusOne)
}

// calculateP calculates P = g^F mod p.
func (z *ZK13) calculateP(F *big.Int) *big.Int {
	return new(big.Int).Exp(z.g, F, z.p)
}

// Verify checks if the given P matches r^Hs mod p, validating the proof.
func Verify(r, Hs, P, p *big.Int) bool {
	V := new(big.Int).Exp(r, Hs, p)
	return V.Cmp(P) == 0
}

// randBigInt generates a random big integer within a specified range.
func randBigInt(max *big.Int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// setupZK13Verifier simulates the verifier setup for demonstration purposes.
// In practice, the verifier should only need to verify the proof against known parameters, not generate them.
func SetupZK13Verifier(z *ZK13) *Verifier {
	v := &Verifier{}
	k, _ := randBigInt(big.NewInt(PubKeyRange)) // Better error handling should be added
	v.k = k
	v.r = z.calculateR(k)
	v.F = z.calculateF(k)
	v.P = z.calculateP(v.F)
	return v
}

type Verifier struct {
	k, r, F, P *big.Int
}
