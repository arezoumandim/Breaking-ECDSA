package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"time"

	"breaking-ecdsa/config"
	"breaking-ecdsa/ethereum"
	"breaking-ecdsa/generator"
	"breaking-ecdsa/pattern"
	"breaking-ecdsa/solver"
	"breaking-ecdsa/worker"
)

func main() {
	fmt.Println("=== ECDSA Breaking Tool with Affine Nonces (Multi-Thread) ===\n")

	// create configuration
	cfg := config.DefaultConfig()

	// we can get parameters from command line
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "demo":
			runDemoParallel(cfg)
		case "custom":
			runCustom(cfg)
		case "batch":
			runBatchMode(cfg)
		case "known":
			runKnownNonceDemo(cfg)
		case "bruteforce":
			runBruteForceDemo(cfg)
		case "ethereum":
			runEthereumExploitDemo(cfg)
		case "help":
			printHelp()
		default:
			runDemoParallel(cfg)
		}
	} else {
		runDemoParallel(cfg)
	}
}

// runDemoParallel run demo using multi-threading
func runDemoParallel(cfg *config.Config) {
	fmt.Println("--- Demo Mode (Multi-Thread) ---")
	fmt.Printf("Curve: %s\n", cfg.Curve.Params().Name)
	fmt.Printf("Affine relationship: k2 = %s*k1 + %s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())
	fmt.Printf("Message: %s\n", string(cfg.Message1))

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // limit to 8 workers to prevent overhead
	}
	fmt.Printf("Number of workers: %d\n\n", numWorkers)

	startTime := time.Now()

	// use worker pool
	wp := worker.NewWorkerPool(cfg, numWorkers)
	results := wp.GenerateAndSolve(1) // one test for demo

	// receive result
	var r *worker.Result
	done := make(chan bool)

	go func() {
		for result := range results {
			r = result
			done <- true
			return
		}
		done <- true
	}()

	// wait for result
	<-done

	if r.Error != nil {
		fmt.Printf("Error: %v\n", r.Error)
		return
	}

	if r.Data == nil {
		fmt.Println("Error: data not generated")
		return
	}

	elapsed := time.Since(startTime)

	// display results
	fmt.Println("1. Generate keys and signatures (parallel)...")
	fmt.Printf("   Original private key: %s\n", r.Data.KeyPair.PrivateKey.String())
	fmt.Printf("   First nonce (k1): %s\n", r.Data.K1.String())
	fmt.Printf("   Second nonce (k2): %s\n", r.Data.K2.String())
	fmt.Printf("   First signature - r: %s, s: %s\n",
		r.Data.Signature1.R.String(), r.Data.Signature1.S.String())
	fmt.Printf("   Second signature - r: %s, s: %s\n\n",
		r.Data.Signature2.R.String(), r.Data.Signature2.S.String())

	fmt.Println("2. Recover private key (parallel)...")
	if r.RecoveredKey != nil {
		fmt.Printf("   Recovered private key: %s\n\n", r.RecoveredKey.String())
	}

	fmt.Println("3. Verification...")
	if r.Success {
		fmt.Println("   ✓ Private key successfully recovered!")
		fmt.Printf("   ✓ Recovered key matches original key\n")
	} else {
		fmt.Println("   ✗ Recovered key differs from original key")
		if r.RecoveredKey != nil {
			fmt.Printf("   Original key:   %s\n", r.Data.KeyPair.PrivateKey.String())
			fmt.Printf("   Recovered key: %s\n", r.RecoveredKey.String())
		}
	}

	fmt.Printf("\nExecution time: %v\n", elapsed)
}

// runDemo run demo with default settings (old version - single thread)
func runDemo(cfg *config.Config) {
	fmt.Println("--- Demo Mode (Single-Thread) ---")
	fmt.Printf("Curve: %s\n", cfg.Curve.Params().Name)
	fmt.Printf("Affine relationship: k2 = %s*k1 + %s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())
	fmt.Printf("Message: %s\n\n", string(cfg.Message1))

	// generate sample data
	fmt.Println("1. Generate keys and signatures...")
	data, err := generator.GenerateSampleData(cfg)
	if err != nil {
		fmt.Printf("Error generating data: %v\n", err)
		return
	}

	fmt.Printf("   Original private key: %s\n", data.KeyPair.PrivateKey.String())
	fmt.Printf("   First nonce (k1): %s\n", data.K1.String())
	fmt.Printf("   Second nonce (k2): %s\n", data.K2.String())
	fmt.Printf("   First signature - r: %s, s: %s\n",
		data.Signature1.R.String(), data.Signature1.S.String())
	fmt.Printf("   Second signature - r: %s, s: %s\n\n",
		data.Signature2.R.String(), data.Signature2.S.String())

	// recover private key
	fmt.Println("2. Recover private key...")
	solverInstance := solver.NewSolver(cfg.Curve)
	recoveredKey, err := solverInstance.Solve(data)
	if err != nil {
		fmt.Printf("Error recovering key: %v\n", err)
		return
	}

	fmt.Printf("   Recovered private key: %s\n\n", recoveredKey.String())

	// verify
	fmt.Println("3. Verification...")
	isValid := solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey)
	if isValid {
		fmt.Println("   ✓ Private key successfully recovered!")
		fmt.Printf("   ✓ Recovered key matches original key\n")
	} else {
		fmt.Println("   ✗ Recovered key differs from original key")
		fmt.Printf("   Original key:   %s\n", data.KeyPair.PrivateKey.String())
		fmt.Printf("   Recovered key: %s\n", recoveredKey.String())
	}
}

// runCustom run with custom settings
func runCustom(cfg *config.Config) {
	fmt.Println("--- Custom Mode ---")
	fmt.Println("Using default settings with custom values...")

	// change affine relationship
	cfg.AffineRelationship.A = big.NewInt(5)
	cfg.AffineRelationship.B = big.NewInt(7)
	cfg.Message1 = []byte("Custom message for testing")
	cfg.UseSameMessage = true

	fmt.Printf("Affine relationship: k2 = %s*k1 + %s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())

	runDemo(cfg)
}

// runBatchMode batch execution with multi-threading
func runBatchMode(cfg *config.Config) {
	numTests := 10
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &numTests)
	}

	fmt.Printf("\n--- Running %d tests (Multi-Thread) ---\n", numTests)

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	fmt.Printf("Number of workers: %d\n\n", numWorkers)

	startTime := time.Now()

	// use worker pool
	wp := worker.NewWorkerPool(cfg, numWorkers)
	results := wp.GenerateAndSolve(numTests)

	// collect results
	var mu sync.Mutex
	successCount := 0
	totalCount := 0
	resultsList := make([]*worker.Result, 0, numTests)
	done := make(chan bool)

	// print results in real-time
	go func() {
		for r := range results {
			mu.Lock()
			resultsList = append(resultsList, r)
			totalCount++
			if r.Success {
				successCount++
				fmt.Printf("✓ Test %d: Success - Key recovered\n", r.Index+1)
				if r.Data != nil && r.RecoveredKey != nil {
					fmt.Printf("  Original key: %s\n", r.Data.KeyPair.PrivateKey.String())
					fmt.Printf("  Recovered key: %s\n", r.RecoveredKey.String())
				}
			} else if r.Error != nil {
				fmt.Printf("✗ Test %d: Error - %v\n", r.Index+1, r.Error)
			} else {
				fmt.Printf("✗ Test %d: Failed\n", r.Index+1)
			}
			mu.Unlock()
		}
		done <- true
	}()

	// wait for all tasks to complete
	<-done

	elapsed := time.Since(startTime)

	mu.Lock()
	finalSuccess := successCount
	finalTotal := totalCount
	mu.Unlock()

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Successful tests: %d/%d\n", finalSuccess, finalTotal)
	if finalTotal > 0 {
		fmt.Printf("Success rate: %.2f%%\n", float64(finalSuccess)/float64(finalTotal)*100)
	}
	fmt.Printf("Total time: %v\n", elapsed)
	fmt.Printf("Average time per test: %v\n", elapsed/time.Duration(finalTotal))
}

// runMultipleTests run multiple tests (old version - single thread)
func runMultipleTests(cfg *config.Config, numTests int) {
	fmt.Printf("\n--- Running %d tests (Single-Thread) ---\n", numTests)
	successCount := 0
	solverInstance := solver.NewSolver(cfg.Curve)

	for i := 0; i < numTests; i++ {
		data, err := generator.GenerateSampleData(cfg)
		if err != nil {
			fmt.Printf("Error in test %d: %v\n", i+1, err)
			continue
		}

		recoveredKey, err := solverInstance.Solve(data)
		if err != nil {
			fmt.Printf("Error recovering test %d: %v\n", i+1, err)
			continue
		}

		if solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey) {
			successCount++
		}
	}

	fmt.Printf("\nResults: %d/%d tests successful\n", successCount, numTests)
}

// runKnownNonceDemo demo for when we know the nonce
func runKnownNonceDemo(cfg *config.Config) {
	fmt.Println("=== Demo: Key Recovery When We Know the Nonce Pattern ===\n")

	// simple example: if we know the nonce
	keyPair, err := generator.GenerateKeyPair(cfg.Curve)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	knownNonce := big.NewInt(123456789)
	message := cfg.Message1

	sig, err := generator.SignWithNonce(cfg.Curve, keyPair.PrivateKey, message, knownNonce)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Original private key: %s\n", keyPair.PrivateKey.String())
	fmt.Printf("Nonce used: %s\n\n", knownNonce.String())

	// recover using pattern package
	knownSolver := pattern.NewKnownNonceSolver(cfg.Curve)
	recoveredKey, err := knownSolver.RecoverFromKnownNonce(*sig, knownNonce)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Recovered key: %s\n", recoveredKey.String())
	if recoveredKey.Cmp(keyPair.PrivateKey) == 0 {
		fmt.Println("✓ Success!")
	}
}

// runBruteForceDemo demo for brute-force
func runBruteForceDemo(cfg *config.Config) {
	fmt.Println("=== Demo: Brute-Forcing Affine Relationship ===\n")

	// generate data with known affine relationship
	data, err := generator.GenerateSampleData(cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Real affine relationship: k2 = %s*k1 + %s\n",
		cfg.AffineRelationship.A.String(),
		cfg.AffineRelationship.B.String())
	fmt.Println("(but we assume we don't know it)\n")

	bfs := pattern.NewBruteForceSolver(cfg.Curve)
	bfs.SetSearchRange(20, 20) // small range for testing

	message1 := cfg.Message1
	message2 := cfg.Message2
	if cfg.UseSameMessage {
		message2 = message1
	}

	fmt.Println("Starting brute-force...")
	results := bfs.BruteForceAffineRelation(
		data.Signature1,
		data.Signature2,
		message1,
		message2,
	)

	for result := range results {
		if result.Success {
			fmt.Printf("✓ Found: a=%s, b=%s\n", result.A.String(), result.B.String())
			fmt.Printf("  Key: %s\n", result.PrivateKey.String())
			fmt.Printf("  Attempts: %d\n", result.Attempts)
			return
		}
	}

	fmt.Println("✗ Not found")
}

// runEthereumExploitDemo demo for extracting from Ethereum address
func runEthereumExploitDemo(cfg *config.Config) {
	fmt.Println("=== Key Extraction from Ethereum Address ===\n")
	fmt.Println("⚠️  This is a real vulnerability!")
	fmt.Println("If transaction count is used as ECDSA nonce,")
	fmt.Println("the private key can be recovered.\n")

	// create an Ethereum address
	address, err := ethereum.NewEthereumAddress(cfg.Curve)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Ethereum address created\n")
	fmt.Printf("Original private key: %s\n\n", address.PrivateKey.String())

	// create two consecutive transactions
	fmt.Println("Creating two consecutive transactions...")
	tx1, err := address.SignTransactionWithCounterNonce(
		"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
		big.NewInt(1000000000000000000), // 1 ETH
		[]byte("transfer"),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	tx2, err := address.SignTransactionWithCounterNonce(
		"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
		big.NewInt(2000000000000000000), // 2 ETH
		[]byte("transfer"),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Transaction 1: nonce=%d\n", tx1.Nonce)
	fmt.Printf("Transaction 2: nonce=%d\n\n", tx2.Nonce)

	// extract key
	fmt.Println("Starting key extraction from transactions...")
	exploit := ethereum.NewEthereumExploit(cfg.Curve)
	recoveredKey, err := exploit.ExploitFromCounterNonce(tx1, tx2)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Recovered key: %s\n\n", recoveredKey.String())

	if recoveredKey.Cmp(address.PrivateKey) == 0 {
		fmt.Println("✓ Key successfully recovered!")
		fmt.Println("✓ This demonstrates that using transaction count as nonce is dangerous!")
	} else {
		fmt.Println("✗ Recovered key is incorrect")
	}

	fmt.Println("\nSolution:")
	fmt.Println("- Always use random and unique nonces")
	fmt.Println("- Use RFC 6979 for deterministic nonce generation")
	fmt.Println("- Never use transaction count as ECDSA nonce")
}

// printHelp display help
func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  go run main.go              - run demo (multi-thread)")
	fmt.Println("  go run main.go demo         - run demo (multi-thread)")
	fmt.Println("  go run main.go custom        - run with custom settings")
	fmt.Println("  go run main.go batch [N]    - run N tests in parallel (default: 10)")
	fmt.Println("  go run main.go known         - demo: recovery when we know the nonce")
	fmt.Println("  go run main.go bruteforce    - demo: brute-force affine relationship")
	fmt.Println("  go run main.go ethereum      - demo: extraction from Ethereum address (transaction count nonce)")
	fmt.Println("  go run main.go help         - display this help")
	fmt.Println("\nMulti-Thread Features:")
	fmt.Println("  - use all CPU cores")
	fmt.Println("  - parallel processing of data generation and solving")
	fmt.Println("  - real-time result display")
	fmt.Println("  - execution time reporting")
	fmt.Println("\nNonce Patterns:")
	fmt.Println("  - Known Nonce: if we know the nonce, we recover the key directly")
	fmt.Println("  - Counter Pattern: k_i = k_0 + i")
	fmt.Println("  - Linear Pattern: k_i = a*k_{i-1} + b")
	fmt.Println("  - Affine Pattern: k_i = a*k_j + b")
	fmt.Println("  - Brute-Force: search for affine relationship with brute-force")
	fmt.Println("\nThis tool is designed for educational and research purposes.")
	fmt.Println("Based on paper: 'Breaking ECDSA with Two Affinely Related Nonces'")
}

// init initial settings
func init() {
	// we can use SECP256k1 if appropriate library is available
	// currently we use P256 which is available by default in Go
	_ = elliptic.P256()
}
