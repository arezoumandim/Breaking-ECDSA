package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"slippage/config"
	"slippage/generator"
	"slippage/pattern"
	"slippage/solver"
)

// This example shows how to recover the private key
// if we know how the nonce is generated

func main() {
	fmt.Println("=== Example: Key Recovery When We Know the Nonce Pattern ===\n")

	cfg := config.DefaultConfig()
	curve := cfg.Curve

	// Scenario 1: If we know the nonce directly
	fmt.Println("--- Scenario 1: Known Nonce ---")
	scenario1_knownNonce(curve)

	// Scenario 2: If we know the nonce generation pattern (e.g., counter)
	fmt.Println("\n--- Scenario 2: Counter Pattern ---")
	scenario2_counterPattern(curve)

	// Scenario 3: Brute-force affine relationship
	fmt.Println("\n--- Scenario 3: Brute-Force Affine Relationship ---")
	scenario3_bruteForce(curve)
}

// scenario1_knownNonce if we know the nonce
func scenario1_knownNonce(curve elliptic.Curve) {
	// generate key and signature
	keyPair, err := generator.GenerateKeyPair(curve)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// assume we know the nonce
	message := []byte("Test message")
	knownNonce := big.NewInt(123456789)

	// generate signature with known nonce
	sig, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message, knownNonce)
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		return
	}

	fmt.Printf("Original private key: %s\n", keyPair.PrivateKey.String())
	fmt.Printf("Public key (X): %s\n", keyPair.PublicKey.X.String())
	fmt.Printf("Public key (Y): %s\n", keyPair.PublicKey.Y.String())
	fmt.Printf("\nMessage: %s\n", string(message))
	fmt.Printf("Nonce used: %s\n", knownNonce.String())
	fmt.Printf("\nSignature:\n")
	fmt.Printf("  r: %s\n", sig.R.String())
	fmt.Printf("  s: %s\n", sig.S.String())
	fmt.Printf("  z (message hash): %s\n", sig.Z.String())

	// display formula
	fmt.Printf("\nRecovery formula:\n")
	fmt.Printf("  d = (s*k - z) * r^-1 mod n\n")
	fmt.Printf("  where:\n")
	fmt.Printf("    k = nonce = %s\n", knownNonce.String())
	fmt.Printf("    s = %s\n", sig.S.String())
	fmt.Printf("    z = %s\n", sig.Z.String())
	fmt.Printf("    r = %s\n", sig.R.String())

	// recover key using known nonce
	knownNonceSolver := pattern.NewKnownNonceSolver(curve)
	recoveredKey, err := knownNonceSolver.RecoverFromKnownNonce(*sig, knownNonce)
	if err != nil {
		fmt.Printf("\nError recovering: %v\n", err)
		return
	}

	fmt.Printf("\nRecovered key: %s\n", recoveredKey.String())

	// verify
	if recoveredKey.Cmp(keyPair.PrivateKey) == 0 {
		fmt.Println("✓ Key successfully recovered!")
		fmt.Println("✓ Recovered key matches original key")
	} else {
		fmt.Println("✗ Recovered key is incorrect")
		fmt.Printf("  Original key:   %s\n", keyPair.PrivateKey.String())
		fmt.Printf("  Recovered key: %s\n", recoveredKey.String())
	}
}

// scenario2_counterPattern if we know the counter pattern
func scenario2_counterPattern(curve elliptic.Curve) {
	// generate key
	keyPair, err := generator.GenerateKeyPair(curve)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Original private key: %s\n", keyPair.PrivateKey.String())

	// create nonce generator with counter pattern
	nonceGen := pattern.NewPredictableNonceGenerator(pattern.PatternCounter, curve)
	nonceGen.SetSeed(big.NewInt(1000))

	message := []byte("Test message")

	// generate two signatures with consecutive nonces
	k1 := nonceGen.NextNonce()
	k2 := nonceGen.NextNonce()

	fmt.Printf("\nFirst nonce (k1): %s\n", k1.String())
	fmt.Printf("Second nonce (k2): %s\n", k2.String())

	// check relationship: k2 = k1 + 1 (for counter)
	expectedK2 := new(big.Int).Add(k1, big.NewInt(1))
	n := curve.Params().N
	expectedK2.Mod(expectedK2, n)

	fmt.Printf("\nCounter relationship: k2 = k1 + 1\n")
	fmt.Printf("Calculated k2: %s\n", expectedK2.String())

	if k2.Cmp(expectedK2) == 0 {
		fmt.Println("✓ Counter pattern confirmed!")
	}

	// generate signatures
	sig1, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message, k1)
	if err != nil {
		fmt.Printf("Error generating first signature: %v\n", err)
		return
	}
	sig2, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message, k2)
	if err != nil {
		fmt.Printf("Error generating second signature: %v\n", err)
		return
	}

	fmt.Printf("\nFirst signature:\n")
	fmt.Printf("  r1: %s\n", sig1.R.String())
	fmt.Printf("  s1: %s\n", sig1.S.String())
	fmt.Printf("  z1: %s\n", sig1.Z.String())
	fmt.Printf("\nSecond signature:\n")
	fmt.Printf("  r2: %s\n", sig2.R.String())
	fmt.Printf("  s2: %s\n", sig2.S.String())
	fmt.Printf("  z2: %s\n", sig2.Z.String())

	// recover key using affine relationship (a=1, b=1)
	fmt.Printf("\nRecovering key with relationship: k2 = 1*k1 + 1\n")
	solverInstance := solver.NewSolver(curve)
	recoveredKey, err := solverInstance.RecoverPrivateKey(
		*sig1, *sig2,
		big.NewInt(1), // a = 1
		big.NewInt(1), // b = 1
	)

	if err != nil {
		fmt.Printf("Error recovering: %v\n", err)
		return
	}

	fmt.Printf("Recovered key: %s\n", recoveredKey.String())
	if recoveredKey.Cmp(keyPair.PrivateKey) == 0 {
		fmt.Println("✓ Key successfully recovered!")
		fmt.Println("✓ Recovered key matches original key")
	} else {
		fmt.Println("✗ Recovered key is incorrect")
		fmt.Printf("  Original key:   %s\n", keyPair.PrivateKey.String())
		fmt.Printf("  Recovered key: %s\n", recoveredKey.String())
	}
}

// scenario3_bruteForce brute-force affine relationship
func scenario3_bruteForce(curve elliptic.Curve) {
	// generate key and signature with known affine relationship
	cfg := config.DefaultConfig()
	data, err := generator.GenerateSampleData(cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Original private key: %s\n", data.KeyPair.PrivateKey.String())
	fmt.Printf("Real affine relationship: k2 = %s*k1 + %s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())

	// display signature information
	fmt.Printf("\nFirst signature:\n")
	fmt.Printf("  r1: %s\n", data.Signature1.R.String())
	fmt.Printf("  s1: %s\n", data.Signature1.S.String())
	fmt.Printf("  z1: %s\n", data.Signature1.Z.String())
	fmt.Printf("\nSecond signature:\n")
	fmt.Printf("  r2: %s\n", data.Signature2.R.String())
	fmt.Printf("  s2: %s\n", data.Signature2.S.String())
	fmt.Printf("  z2: %s\n", data.Signature2.Z.String())
	fmt.Printf("\nFirst nonce (k1): %s\n", data.K1.String())
	fmt.Printf("Second nonce (k2): %s\n", data.K2.String())

	// now assume we don't know the relationship and find it with brute-force
	bfs := pattern.NewBruteForceSolver(curve)
	// search range should include a=2, b=3
	// a from 1 to 5 (including 2), b from 0 to 5 (including 3)
	bfs.SetSearchRange(5, 5) // sufficient range to find a=2, b=3

	message1 := cfg.Message1
	message2 := cfg.Message2
	if cfg.UseSameMessage {
		message2 = message1
	}

	fmt.Println("\nStarting brute-force...")
	fmt.Printf("Search range: a from 1 to 5, b from 0 to 5\n")
	fmt.Printf("Target: find a=%s, b=%s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())

	// use brute-force with key verification
	results := bfs.BruteForceAffineRelationWithVerification(
		data.Signature1,
		data.Signature2,
		message1,
		message2,
		data.KeyPair.PublicKey.X, // use public key for verification
		data.KeyPair.PublicKey.Y,
	)

	// get first successful result
	found := false
	allResults := []*pattern.BruteForceResult{}

	for result := range results {
		if result.Success {
			allResults = append(allResults, result)
			// verify by comparing key
			if result.PrivateKey.Cmp(data.KeyPair.PrivateKey) == 0 {
				fmt.Printf("\n✓ Relationship found!\n")
				fmt.Printf("  a = %s\n", result.A.String())
				fmt.Printf("  b = %s\n", result.B.String())
				fmt.Printf("  Recovered key: %s\n", result.PrivateKey.String())
				fmt.Printf("  Attempts: %d\n", result.Attempts)
				fmt.Println("\n✓ Key is correct!")
				fmt.Println("✓ Recovered key matches original key")
				found = true
				break
			}
		}
	}

	// if correct relationship not found, check other results
	if !found {
		// check if a=2, b=3 is in results
		correctA := cfg.AffineRelationship.A.Int64()
		correctB := cfg.AffineRelationship.B.Int64()

		for _, result := range allResults {
			if result.A.Int64() == correctA && result.B.Int64() == correctB {
				fmt.Printf("\n✓ Correct relationship found (but key is different)!\n")
				fmt.Printf("  a = %s (correct)\n", result.A.String())
				fmt.Printf("  b = %s (correct)\n", result.B.String())
				fmt.Printf("  Recovered key: %s\n", result.PrivateKey.String())
				fmt.Printf("  Original key: %s\n", data.KeyPair.PrivateKey.String())
				fmt.Printf("  Attempts: %d\n", result.Attempts)
				fmt.Println("\n⚠️  Relationship is correct but key is different")
				fmt.Println("  This may be due to calculation error or solver issue")
				found = true
				break
			}
		}
	}

	if !found {
		fmt.Println("\n✗ Correct relationship not found")
		fmt.Println("⚠️  Search range may not be sufficient")
		fmt.Printf("  Real relationship: a=%s, b=%s\n",
			cfg.AffineRelationship.A.String(),
			cfg.AffineRelationship.B.String())
		fmt.Printf("  Search range: a from 1 to %d, b from 0 to %d\n", 5, 5)
	}
}
