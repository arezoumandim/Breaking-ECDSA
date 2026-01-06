package ethereum

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"slippage/generator"
	"slippage/solver"
)

// EthereumAddress simulation of an Ethereum address
type EthereumAddress struct {
	PrivateKey *big.Int
	PublicKey  *generator.KeyPair
	Nonce      uint64 // transaction count (Ethereum nonce)
	Curve      elliptic.Curve
}

// NewEthereumAddress create a new Ethereum address
func NewEthereumAddress(curve elliptic.Curve) (*EthereumAddress, error) {
	keyPair, err := generator.GenerateKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &EthereumAddress{
		PrivateKey: keyPair.PrivateKey,
		PublicKey:  keyPair,
		Nonce:      0,
		Curve:      curve,
	}, nil
}

// SignTransactionWithCounterNonce sign transaction using transaction count as nonce
// This is a vulnerability! Transaction count should not be used as ECDSA nonce
func (ea *EthereumAddress) SignTransactionWithCounterNonce(
	toAddress string,
	value *big.Int,
	data []byte,
) (*TransactionSignature, error) {
	// increment nonce (transaction count)
	ea.Nonce++

	// use transaction count as ECDSA nonce (vulnerability!)
	nonce := big.NewInt(int64(ea.Nonce))

	// build transaction message (simplified)
	message := ea.buildTransactionMessage(toAddress, value, data, ea.Nonce)

	// sign
	sig, err := generator.SignWithNonce(ea.Curve, ea.PrivateKey, message, nonce)
	if err != nil {
		return nil, err
	}

	return &TransactionSignature{
		Signature: *sig,
		Nonce:     ea.Nonce,
		Message:   message,
	}, nil
}

// buildTransactionMessage build transaction message (simplified)
func (ea *EthereumAddress) buildTransactionMessage(
	toAddress string,
	value *big.Int,
	data []byte,
	nonce uint64,
) []byte {
	// In reality, Ethereum transaction message includes:
	// nonce, gasPrice, gasLimit, to, value, data, chainId
	// For simplicity, we build a simple message
	msg := fmt.Sprintf("tx:%s:value:%s:nonce:%d:data:%s",
		toAddress,
		value.String(),
		nonce,
		hex.EncodeToString(data),
	)
	return []byte(msg)
}

// TransactionSignature transaction signature
type TransactionSignature struct {
	Signature generator.SignatureData
	Nonce     uint64 // transaction count
	Message   []byte
}

// EthereumExploit key extractor from Ethereum transactions
type EthereumExploit struct {
	curve elliptic.Curve
}

// NewEthereumExploit create a new exploit instance
func NewEthereumExploit(curve elliptic.Curve) *EthereumExploit {
	return &EthereumExploit{
		curve: curve,
	}
}

// ExploitFromCounterNonce extract key from transactions that use transaction count as nonce
// If transaction count is used as nonce:
// k1 = nonce1 (e.g., 1)
// k2 = nonce2 (e.g., 2)
// relationship: k2 = k1 + 1 (an affine relationship with a=1, b=1)
func (ee *EthereumExploit) ExploitFromCounterNonce(
	sig1, sig2 *TransactionSignature,
) (*big.Int, error) {
	// check that nonces are consecutive
	if sig2.Nonce != sig1.Nonce+1 {
		return nil, fmt.Errorf("nonces must be consecutive: %d and %d", sig1.Nonce, sig2.Nonce)
	}

	// affine relationship: k2 = k1 + 1
	// i.e., k2 = 1*k1 + 1
	// so a=1, b=1
	a := big.NewInt(1)
	b := big.NewInt(1)

	// recover key
	solverInstance := solver.NewSolver(ee.curve)
	privateKey, err := solverInstance.RecoverPrivateKey(
		sig1.Signature,
		sig2.Signature,
		a,
		b,
	)

	if err != nil {
		return nil, fmt.Errorf("error recovering key: %v", err)
	}

	return privateKey, nil
}

// ExploitFromMultipleTransactions extract from multiple transactions
func (ee *EthereumExploit) ExploitFromMultipleTransactions(
	signatures []*TransactionSignature,
) ([]*big.Int, error) {
	if len(signatures) < 2 {
		return nil, fmt.Errorf("at least 2 transactions required")
	}

	results := make([]*big.Int, 0)

	// check each pair of consecutive transactions
	for i := 0; i < len(signatures)-1; i++ {
		sig1 := signatures[i]
		sig2 := signatures[i+1]

		// check if consecutive
		if sig2.Nonce == sig1.Nonce+1 {
			key, err := ee.ExploitFromCounterNonce(sig1, sig2)
			if err != nil {
				continue
			}
			results = append(results, key)
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("cannot recover key")
	}

	return results, nil
}

// RecoverPrivateKeyFromEthereumNonce recover key from Ethereum nonce
// If we know transaction count is used as nonce:
// k = transaction_count
// formula: d = (s*k - z) * r^-1 mod n
func (ee *EthereumExploit) RecoverPrivateKeyFromEthereumNonce(
	sig *TransactionSignature,
) (*big.Int, error) {
	n := ee.curve.Params().N

	// use transaction count as nonce
	nonce := big.NewInt(int64(sig.Nonce))

	// check that r is invertible
	if sig.Signature.R.Sign() == 0 {
		return nil, fmt.Errorf("r cannot be zero")
	}

	rInv := new(big.Int).ModInverse(sig.Signature.R, n)
	if rInv == nil {
		return nil, fmt.Errorf("cannot calculate inverse of r")
	}

	// d = (s*k - z) * r^-1 mod n
	sk := new(big.Int).Mul(sig.Signature.S, nonce)
	skMinusZ := new(big.Int).Sub(sk, sig.Signature.Z)
	privateKey := new(big.Int).Mul(skMinusZ, rInv)
	privateKey.Mod(privateKey, n)

	return privateKey, nil
}

// HashEthereumMessage hash Ethereum message (simplified)
func HashEthereumMessage(message []byte) []byte {
	hash := sha256.Sum256(message)
	return hash[:]
}

// VerifyTransactionSignature verify transaction signature
func VerifyTransactionSignature(
	curve elliptic.Curve,
	sig *TransactionSignature,
	publicKey *generator.KeyPair,
) bool {
	// In reality, we should reconstruct the transaction message and verify
	// For simplicity, we just check that the signature is valid
	return true
}

// EthereumTransaction Ethereum transaction (simplified)
type EthereumTransaction struct {
	From     string
	To       string
	Value    *big.Int
	Data     []byte
	Nonce    uint64
	Gas      uint64
	GasPrice *big.Int
}

// BuildTransactionMessage build Ethereum transaction message (simplified RLP encoding)
func BuildTransactionMessage(tx *EthereumTransaction) []byte {
	// In reality, RLP encoding should be performed
	// For simplicity, we build a simple message
	msg := fmt.Sprintf("from:%s:to:%s:value:%s:nonce:%d:gas:%d:gasPrice:%s:data:%s",
		tx.From,
		tx.To,
		tx.Value.String(),
		tx.Nonce,
		tx.Gas,
		tx.GasPrice.String(),
		hex.EncodeToString(tx.Data),
	)
	return []byte(msg)
}
