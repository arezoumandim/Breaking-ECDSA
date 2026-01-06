package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"slippage/config"
)

// SignatureData signature data including r, s, z (message hash)
type SignatureData struct {
	R *big.Int // r component
	S *big.Int // s component
	Z *big.Int // hash of message (z)
}

// KeyPair private and public key pair
type KeyPair struct {
	PrivateKey *big.Int
	PublicKey  *ecdsa.PublicKey
}

// GeneratedData generated data including keys and signatures
type GeneratedData struct {
	KeyPair     KeyPair
	Signature1  SignatureData
	Signature2  SignatureData
	K1          *big.Int // first nonce
	K2          *big.Int // second nonce (with affine relationship)
	Config      *config.Config
}

// GenerateKeyPair generate ECDSA key pair
func GenerateKeyPair(curve elliptic.Curve) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey.D,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// HashMessage hash the message
func HashMessage(message []byte, curve elliptic.Curve) *big.Int {
	hash := sha256.Sum256(message)
	z := new(big.Int).SetBytes(hash[:])
	n := curve.Params().N
	z.Mod(z, n)
	return z
}

// SignWithNonce sign with specified nonce
func SignWithNonce(curve elliptic.Curve, privateKey *big.Int, message []byte, k *big.Int) (*SignatureData, error) {
	// calculate z (message hash)
	z := HashMessage(message, curve)

	// calculate r = (k * G).x mod n
	// use ScalarBaseMult to calculate k*G (more efficient than ScalarMult)
	n := curve.Params().N
	kBytes := k.Bytes()
	// ensure kBytes is large enough
	if len(kBytes) < (n.BitLen()+7)/8 {
		padded := make([]byte, (n.BitLen()+7)/8)
		copy(padded[len(padded)-len(kBytes):], kBytes)
		kBytes = padded
	}
	kGx, _ := curve.ScalarBaseMult(kBytes)
	r := new(big.Int).Mod(kGx, n)
	
	// check that r is not zero (in ECDSA r must not be zero)
	if r.Sign() == 0 {
		return nil, ErrInvalidNonce
	}

	// calculate s = k^-1 * (z + r * d) mod n
	// where d is the private key
	kInv := new(big.Int).ModInverse(k, n)
	if kInv == nil {
		return nil, ErrInvalidNonce
	}

	// s = k^-1 * (z + r * d) mod n
	rd := new(big.Int).Mul(r, privateKey)
	zPlusRd := new(big.Int).Add(z, rd)
	s := new(big.Int).Mul(kInv, zPlusRd)
	s.Mod(s, n)

	return &SignatureData{
		R: r,
		S: s,
		Z: z,
	}, nil
}

// GenerateSampleData generate sample data with affine nonces
func GenerateSampleData(cfg *config.Config) (*GeneratedData, error) {
	// generate key
	keyPair, err := GenerateKeyPair(cfg.Curve)
	if err != nil {
		return nil, err
	}

	// generate first nonce (k1)
	n := cfg.Curve.Params().N
	k1, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, err
	}

	// generate second nonce with affine relationship: k2 = a*k1 + b
	k2 := new(big.Int).Mul(cfg.AffineRelationship.A, k1)
	k2.Add(k2, cfg.AffineRelationship.B)
	k2.Mod(k2, n)

	// determine messages
	message1 := cfg.Message1
	message2 := cfg.Message2
	if cfg.UseSameMessage {
		message2 = message1
	}

	// generate first signature
	sig1, err := SignWithNonce(cfg.Curve, keyPair.PrivateKey, message1, k1)
	if err != nil {
		return nil, err
	}

	// generate second signature
	sig2, err := SignWithNonce(cfg.Curve, keyPair.PrivateKey, message2, k2)
	if err != nil {
		return nil, err
	}

	return &GeneratedData{
		KeyPair:    *keyPair,
		Signature1: *sig1,
		Signature2: *sig2,
		K1:         k1,
		K2:         k2,
		Config:     cfg,
	}, nil
}

// ErrInvalidNonce invalid nonce error
var ErrInvalidNonce = &Error{Message: "invalid nonce"}

// Error custom error
type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

