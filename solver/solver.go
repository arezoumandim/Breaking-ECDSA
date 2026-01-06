package solver

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"breaking-ecdsa/generator"
)

// Solver solver for recovering private key from signatures with affine nonces
type Solver struct {
	curve elliptic.Curve
}

// NewSolver create a new solver
func NewSolver(curve elliptic.Curve) *Solver {
	return &Solver{
		curve: curve,
	}
}

// RecoverPrivateKey recover private key from two signatures with affine nonces
// Based on paper: "Breaking ECDSA with Two Affinely Related Nonces"
// Formula: k2 = a*k1 + b
//
// Recovery equation:
// numerator = (a * s2 * z1 - s1 * z2 + b * s1 * s2) mod n
// denominator = (r2 * s1 - a * r1 * s2) mod n
// private_key = (numerator * denominator^-1) mod n
func (s *Solver) RecoverPrivateKey(
	sig1, sig2 generator.SignatureData,
	a, b *big.Int,
) (*big.Int, error) {
	n := s.curve.Params().N

	// calculate numerator: (a * s2 * z1 - s1 * z2 + b * s1 * s2) mod n
	// first part: a * s2 * z1
	as2 := new(big.Int).Mul(a, sig2.S)
	as2z1 := new(big.Int).Mul(as2, sig1.Z)
	as2z1.Mod(as2z1, n)

	// second part: s1 * z2
	s1z2 := new(big.Int).Mul(sig1.S, sig2.Z)
	s1z2.Mod(s1z2, n)

	// third part: b * s1 * s2
	bs1s2 := new(big.Int).Mul(b, sig1.S)
	bs1s2.Mul(bs1s2, sig2.S)
	bs1s2.Mod(bs1s2, n)

	// numerator = a*s2*z1 - s1*z2 + b*s1*s2
	numerator := new(big.Int).Sub(as2z1, s1z2)
	numerator.Add(numerator, bs1s2)
	numerator.Mod(numerator, n)

	// calculate denominator: (r2 * s1 - a * r1 * s2) mod n
	// first part: r2 * s1
	r2s1 := new(big.Int).Mul(sig2.R, sig1.S)
	r2s1.Mod(r2s1, n)

	// second part: a * r1 * s2
	ar1 := new(big.Int).Mul(a, sig1.R)
	ar1s2 := new(big.Int).Mul(ar1, sig2.S)
	ar1s2.Mod(ar1s2, n)

	// denominator = r2*s1 - a*r1*s2
	denominator := new(big.Int).Sub(r2s1, ar1s2)
	denominator.Mod(denominator, n)

	// check that denominator is invertible
	if denominator.Sign() == 0 {
		return nil, fmt.Errorf("denominator is zero - cannot recover private key")
	}

	// calculate inverse of denominator
	denominatorInv := new(big.Int).ModInverse(denominator, n)
	if denominatorInv == nil {
		return nil, fmt.Errorf("cannot calculate inverse of denominator")
	}

	// calculate private key: numerator * denominator^-1 mod n
	privateKey := new(big.Int).Mul(numerator, denominatorInv)
	privateKey.Mod(privateKey, n)

	return privateKey, nil
}

// Solve recover private key from generated data
func (s *Solver) Solve(data *generator.GeneratedData) (*big.Int, error) {
	return s.RecoverPrivateKey(
		data.Signature1,
		data.Signature2,
		data.Config.AffineRelationship.A,
		data.Config.AffineRelationship.B,
	)
}

// VerifyPrivateKey verify recovered private key
func (s *Solver) VerifyPrivateKey(
	recoveredKey *big.Int,
	originalKey *big.Int,
) bool {
	return recoveredKey.Cmp(originalKey) == 0
}
