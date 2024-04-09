package main

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/zeebo/blake3"
	"math/big"
)

const PubKeyRange = 2044 // Size of k, ensure the range is suitable

type ZK13 struct {
	p, g, q, Hs *big.Int
}

// NewZK13 initializes the ZK13 structure with a prime number, generator, and hashed secret.
// It addresses the correct handling of byte slices and ensures that parameters are securely generated.
func NewZK13(secretBaggage string, bits int) *ZK13 {
	var p *big.Int
	var err error
	z := &ZK13{}
	p, err = GenerateLargePrime(bits)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a large prime: %v", err))
	}
	q, err := GenerateLargePrime(bits / 2)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a large prime: %v", err))
	}
	g, err := GenerateGenerator(p, q)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate a generator: %v", err))
	}
	z.q = q
	z.g = g
	z.p = p
	if !z.ValidateParameters(big.NewInt(224)) {
		z.p = nil
		p, err = GenerateLargePrime(bits)
		z.p = p
	}
	hash := blake3.Sum512([]byte(secretBaggage))
	Hs := new(big.Int).SetBytes(hash[:])
	z.Hs = Hs
	spew.Dump(z)
	return z
}

type Proof struct {
	R, P, Nonce *big.Int
}

func (z *ZK13) Prover(nonce *big.Int) (*Proof, error) {
	k, err := rand.Int(rand.Reader, z.p) // Prover's random secret
	if err != nil {
		return nil, err
	}
	r := new(big.Int).Exp(z.g, k, z.p) // r = g^k mod p
	F := new(big.Int).Mul(z.Hs, k)     // F = Hs*k
	pMinusOne := new(big.Int).Sub(z.p, big.NewInt(1))
	F.Mod(F, pMinusOne)                // F = Hs*k mod (p-1)
	P := new(big.Int).Exp(z.g, F, z.p) // P = g^F mod p
	proof := &Proof{
		R:     r,
		P:     P,
		Nonce: nonce,
	}
	spew.Dump(proof)
	return proof, nil
}

// Verifier checks if the provided proof (r, P, nonce) is valid  Verifier checks the proof using constant-time comparison
func (z *ZK13) Verifier(proof *Proof) bool {
	V := new(big.Int).Exp(proof.R, z.Hs, z.p)
	// Convert V and P to byte slices for comparison
	VBytes := V.Bytes()
	PBytes := proof.P.Bytes()
	// Use subtle.ConstantTimeCompare to prevent timing attacks
	if subtle.ConstantTimeCompare(VBytes, PBytes) != 1 {
		return false
	}
	// Check that the nonce is valid
	if proof.Nonce.Cmp(big.NewInt(0)) <= 0 {
		return false
	}
	return true
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

func (z *ZK13) GenerateNonce() *big.Int {
	b, _ := randBigInt(z.p)
	return b
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

// SetupZK13Verifier simulates the verifier setup for demonstration purposes.
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

// GenerateGenerator generates a generator of the form g = h^((p-1)/q) where
// h is a random element in the field and q is a large prime factor of p-1.
func GenerateGenerator(p, q *big.Int) (*big.Int, error) {
	// Generate a random element h in the field
	h, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}
	// Ensure that h is not a multiple of q
	for h.Mod(h, q).Cmp(big.NewInt(0)) == 0 {
		h, err = rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
	}
	// Compute g = h^((p-1)/q)
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	pMinusOneOverQ := new(big.Int).Div(pMinusOne, q)
	g := new(big.Int).Exp(h, pMinusOneOverQ, p)
	return g, nil
}
