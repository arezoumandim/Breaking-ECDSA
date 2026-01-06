package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"breaking-ecdsa/config"
	"breaking-ecdsa/generator"
	"breaking-ecdsa/solver"
)

// This file shows a more advanced example of using the tool

func main() {
	fmt.Println("=== Advanced Example: Multiple Tests ===\n")

	// create configuration
	cfg := config.DefaultConfig()

	// test with different values of a and b
	testCases := []struct {
		name string
		a    int64
		b    int64
	}{
		{"a=1, b=0 (same nonce)", 1, 0},
		{"a=2, b=3", 2, 3},
		{"a=5, b=7", 5, 7},
		{"a=10, b=100", 10, 100},
		{"a=1, b=1", 1, 1},
	}

	solverInstance := solver.NewSolver(cfg.Curve)
	totalTests := 0
	successfulTests := 0

	for _, tc := range testCases {
		fmt.Printf("\n--- Test: %s ---\n", tc.name)
		cfg.AffineRelationship.A = big.NewInt(tc.a)
		cfg.AffineRelationship.B = big.NewInt(tc.b)

		// run 5 tests for each case
		for i := 0; i < 5; i++ {
			data, err := generator.GenerateSampleData(cfg)
			if err != nil {
				fmt.Printf("  Error generating data: %v\n", err)
				continue
			}

			recoveredKey, err := solverInstance.Solve(data)
			if err != nil {
				fmt.Printf("  Error recovering: %v\n", err)
				continue
			}

			totalTests++
			if solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey) {
				successfulTests++
				fmt.Printf("  ✓ Test %d: Success\n", i+1)
			} else {
				fmt.Printf("  ✗ Test %d: Failed\n", i+1)
			}
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Successful tests: %d/%d\n", successfulTests, totalTests)
	fmt.Printf("Success rate: %.2f%%\n", float64(successfulTests)/float64(totalTests)*100)
}

// Example usage with different messages
func exampleWithDifferentMessages() {
	cfg := config.DefaultConfig()
	cfg.UseSameMessage = false
	cfg.Message1 = []byte("First message")
	cfg.Message2 = []byte("Second message")

	data, err := generator.GenerateSampleData(cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	solverInstance := solver.NewSolver(cfg.Curve)
	recoveredKey, err := solverInstance.Solve(data)
	if err != nil {
		fmt.Printf("Error recovering: %v\n", err)
		return
	}

	fmt.Printf("Recovered key: %s\n", recoveredKey.String())
}

// Example usage with different curves
func exampleWithDifferentCurves() {
	curves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		cfg := config.DefaultConfig()
		cfg.Curve = curve

		fmt.Printf("\n--- Test with curve %s ---\n", curve.Params().Name)

		data, err := generator.GenerateSampleData(cfg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		solverInstance := solver.NewSolver(cfg.Curve)
		recoveredKey, err := solverInstance.Solve(data)
		if err != nil {
			fmt.Printf("Error recovering: %v\n", err)
			continue
		}

		if solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey) {
			fmt.Printf("✓ Success with curve %s\n", curve.Params().Name)
		} else {
			fmt.Printf("✗ Failed with curve %s\n", curve.Params().Name)
		}
	}
}
