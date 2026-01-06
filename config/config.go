package config

import (
	"crypto/elliptic"
	"math/big"
)

// Config configuration for ECDSA attack
type Config struct {
	// Curve elliptic curve used (SECP256k1, P256, etc.)
	Curve elliptic.Curve

	// AffineRelationship affine relationship between nonces: k2 = a*k1 + b
	AffineRelationship struct {
		A *big.Int // coefficient a in relationship k2 = a*k1 + b
		B *big.Int // value b in relationship k2 = a*k1 + b
	}

	// Message message for signing (can be same or different)
	Message1 []byte
	Message2 []byte

	// UseSameMessage if true, use the same message for both signatures
	UseSameMessage bool
}

// DefaultConfig default configuration
func DefaultConfig() *Config {
	cfg := &Config{
		Curve:          elliptic.P256(), // use P256 as default
		UseSameMessage: true,
		Message1:       []byte("Affinely related nonces are insecure"),
		Message2:       []byte("Affinely related nonces are insecure"),
	}

	cfg.AffineRelationship.A = big.NewInt(2)
	cfg.AffineRelationship.B = big.NewInt(3)

	return cfg
}

// SECP256k1Config configuration for SECP256k1 curve (used in Bitcoin)
func SECP256k1Config() *Config {
	cfg := DefaultConfig()
	// In Go, SECP256k1 must be implemented manually or use a library
	// For simplicity, we use P256 but can add SECP256k1 later
	return cfg
}
