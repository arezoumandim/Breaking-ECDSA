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

	"breaking-ecdsa/ethereum"
	"breaking-ecdsa/generator"
	"breaking-ecdsa/solver"
)

// EthereumData JSON data structure
type EthereumData struct {
	Address   string   `json:"address"`    // Ethereum address
	PublicKey string   `json:"public_key"` // public key (hex)
	TxIDs     []string `json:"tx_ids"`     // list of transaction IDs
}

// TransactionInfo transaction information from blockchain
// using type from ethereum package
type TransactionInfo = ethereum.TransactionInfo

// EthereumKeyFinder private key finder from transactions
type EthereumKeyFinder struct {
	curve        elliptic.Curve
	data         *EthereumData
	transactions []*TransactionInfo
}

// NewEthereumKeyFinder create a new finder
func NewEthereumKeyFinder(curve elliptic.Curve) *EthereumKeyFinder {
	return &EthereumKeyFinder{
		curve:        curve,
		transactions: make([]*TransactionInfo, 0),
	}
}

// LoadFromJSON load data from JSON file
func (ekf *EthereumKeyFinder) LoadFromJSON(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var ethData EthereumData
	if err := json.Unmarshal(data, &ethData); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	ekf.data = &ethData
	return nil
}

// LoadTransactionsFromJSON load transactions from JSON file
func (ekf *EthereumKeyFinder) LoadTransactionsFromJSON(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var transactions []*TransactionInfo
	if err := json.Unmarshal(data, &transactions); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	ekf.transactions = transactions
	return nil
}

// LoadTransactionsFromEtherscan load transactions from Etherscan API
// if transactions.json exists, uses it
func (ekf *EthereumKeyFinder) LoadTransactionsFromEtherscan(apiKey string, useTxIDs bool, cacheFile string) error {
	// check for cache file
	if cacheFile == "" {
		cacheFile = "transactions.json"
	}

	// try to read from file
	if _, err := os.Stat(cacheFile); err == nil {
		fmt.Printf("File %s found. Using cached data...\n", cacheFile)
		if err := ekf.LoadTransactionsFromJSON(cacheFile); err != nil {
			fmt.Printf("⚠️  Error reading cache file: %v\n", err)
			fmt.Println("Fetching from API...")
		} else {
			fmt.Printf("✓ %d transactions loaded from file\n", len(ekf.transactions))
			return nil
		}
	}

	// if file doesn't exist or has error, fetch from API
	client := ethereum.NewEtherscanClient(apiKey)

	var transactions []*TransactionInfo
	var err error

	if useTxIDs && ekf.data != nil && len(ekf.data.TxIDs) > 0 {
		// get transactions with specified IDs
		fmt.Println("Fetching transactions from Etherscan API with TX IDs...")
		transactions, err = client.GetTransactionsByIDs(ekf.data.TxIDs)
		if err != nil {
			return fmt.Errorf("error fetching transactions: %v", err)
		}
		fmt.Printf("✓ %d transactions fetched\n", len(transactions))
	} else if ekf.data != nil && ekf.data.Address != "" {
		// get all transactions for address
		fmt.Printf("Fetching all transactions for address %s from Etherscan API...\n", ekf.data.Address)
		transactions, err = client.GetTransactionsByAddress(ekf.data.Address)
		if err != nil {
			return fmt.Errorf("error fetching transactions: %v", err)
		}
		fmt.Printf("✓ %d transactions fetched\n", len(transactions))
	} else {
		return fmt.Errorf("address or TX IDs required")
	}

	ekf.transactions = transactions

	// save to file
	fmt.Printf("Saving transactions to file %s...\n", cacheFile)
	if err := ekf.SaveTransactionsToJSON(cacheFile); err != nil {
		fmt.Printf("⚠️  Error saving file: %v\n", err)
	} else {
		fmt.Printf("✓ Transactions saved to %s\n", cacheFile)
	}

	return nil
}

// SaveTransactionsToJSON save transactions to JSON file
func (ekf *EthereumKeyFinder) SaveTransactionsToJSON(filename string) error {
	data, err := json.MarshalIndent(ekf.transactions, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	return nil
}

// ParsePublicKey convert public key from hex string
func (ekf *EthereumKeyFinder) ParsePublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	// remove 0x if present
	if len(publicKeyHex) > 2 && publicKeyHex[:2] == "0x" {
		publicKeyHex = publicKeyHex[2:]
	}

	// decode hex
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %v", err)
	}

	// public key can be compressed (33 bytes) or uncompressed (65 bytes)
	if len(pubKeyBytes) == 65 {
		// Uncompressed: 0x04 + x (32 bytes) + y (32 bytes)
		if pubKeyBytes[0] != 0x04 {
			return nil, fmt.Errorf("invalid public key format")
		}
		x := new(big.Int).SetBytes(pubKeyBytes[1:33])
		y := new(big.Int).SetBytes(pubKeyBytes[33:65])
		return &ecdsa.PublicKey{
			Curve: ekf.curve,
			X:     x,
			Y:     y,
		}, nil
	} else if len(pubKeyBytes) == 33 {
		// Compressed: 0x02 or 0x03 + x (32 bytes)
		// use Unmarshal for decompression
		prefix := pubKeyBytes[0]
		if prefix != 0x02 && prefix != 0x03 {
			return nil, fmt.Errorf("invalid compressed public key format")
		}

		// use Unmarshal for decompression
		// but Unmarshal in crypto/elliptic is not for compressed key
		// so we use manual method
		x := new(big.Int).SetBytes(pubKeyBytes[1:33])

		// calculate y from x for P256
		// formula: y² = x³ - 3x + b (mod p)
		// for P256: b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
		p := ekf.curve.Params().P

		// x³
		x3 := new(big.Int).Exp(x, big.NewInt(3), p)

		// -3x
		threeX := new(big.Int).Mul(x, big.NewInt(3))
		threeX.Mod(threeX, p)
		negThreeX := new(big.Int).Sub(p, threeX)

		// b for P256
		b := new(big.Int)
		b.SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

		// y² = x³ - 3x + b
		y2 := new(big.Int).Add(x3, negThreeX)
		y2.Add(y2, b)
		y2.Mod(y2, p)

		// calculate y = sqrt(y²)
		y := new(big.Int).ModSqrt(y2, p)
		if y == nil {
			return nil, fmt.Errorf("cannot calculate y")
		}

		// check parity and adjust y
		// prefix 0x02 = even y, 0x03 = odd y
		yIsOdd := y.Bit(0) == 1
		prefixIsOdd := prefix == 0x03

		if yIsOdd != prefixIsOdd {
			// y must be inverted
			y.Sub(p, y)
		}

		return &ecdsa.PublicKey{
			Curve: ekf.curve,
			X:     x,
			Y:     y,
		}, nil
	} else if len(pubKeyBytes) == 64 {
		// only x and y without prefix
		x := new(big.Int).SetBytes(pubKeyBytes[0:32])
		y := new(big.Int).SetBytes(pubKeyBytes[32:64])
		return &ecdsa.PublicKey{
			Curve: ekf.curve,
			X:     x,
			Y:     y,
		}, nil
	}

	return nil, fmt.Errorf("invalid public key length: %d bytes", len(pubKeyBytes))
}

// FindPrivateKeyFromTransactions search for private key from transactions
func (ekf *EthereumKeyFinder) FindPrivateKeyFromTransactions() (*big.Int, error) {
	if len(ekf.transactions) < 2 {
		return nil, fmt.Errorf("at least 2 transactions required")
	}

	fmt.Println("Starting private key search...")
	fmt.Printf("Number of transactions: %d\n\n", len(ekf.transactions))

	// Method 1: use transaction count nonce (if consecutive)
	for i := 0; i < len(ekf.transactions)-1; i++ {
		tx1 := ekf.transactions[i]
		tx2 := ekf.transactions[i+1]
		println(tx2.Nonce, tx1.Nonce+1)
		// check if nonces are consecutive
		if tx2.Nonce == tx1.Nonce+1 {
			fmt.Printf("✓ Found: two consecutive transactions (nonce %d and %d)\n", tx1.Nonce, tx2.Nonce)
			fmt.Printf("  TX1: r=%s, s=%s, message=%s\n", tx1.R, tx1.S, tx1.Message)
			fmt.Printf("  TX2: r=%s, s=%s, message=%s\n", tx2.R, tx2.S, tx2.Message)

			// check that r, s are valid (not placeholder)
			if tx1.R == "0x0" || tx1.S == "0x0" || tx2.R == "0x0" || tx2.S == "0x0" {
				fmt.Printf("  ⚠️  Warning: r or s is not valid (placeholder)\n")
				fmt.Printf("    These transactions cannot be used for key recovery\n")
				fmt.Printf("    Need real r, s, v from blockchain\n")
				continue
			}

			// convert signatures
			r1, err := hexToBigInt(tx1.R)
			if err != nil {
				fmt.Printf("  ⚠️  Error converting r1: %v\n", err)
				continue
			}
			s1, err := hexToBigInt(tx1.S)
			if err != nil {
				fmt.Printf("  ⚠️  Error converting s1: %v\n", err)
				continue
			}
			r2, err := hexToBigInt(tx2.R)
			if err != nil {
				fmt.Printf("  ⚠️  Error converting r2: %v\n", err)
				continue
			}
			s2, err := hexToBigInt(tx2.S)
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

			// calculate z (message hash)
			// in real Ethereum, should use Keccak256(RLP(tx))
			// but for testing, we use transaction hash
			z1 := hashMessage(msg1, ekf.curve)
			z2 := hashMessage(msg2, ekf.curve)

			fmt.Printf("  Debug: z1=%s, z2=%s\n", z1.String(), z2.String())
			fmt.Printf("  Debug: r1=%s, s1=%s, r2=%s, s2=%s\n",
				r1.String(), s1.String(), r2.String(), s2.String())

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

			// use affine relationship: k2 = k1 + 1 (a=1, b=1)
			solverInstance := solver.NewSolver(ekf.curve)
			privateKey, err := solverInstance.RecoverPrivateKey(
				sig1,
				sig2,
				big.NewInt(1), // a = 1
				big.NewInt(1), // b = 1
			)

			if err != nil {
				fmt.Printf("  ⚠️  Error recovering key: %v\n", err)
				continue
			}

			fmt.Printf("  Recovered key: %s\n", privateKey.String())

			// verify with public key
			if ekf.verifyPrivateKey(privateKey) {
				fmt.Printf("  ✓ Private key successfully recovered!\n")
				return privateKey, nil
			} else {
				fmt.Printf("  ⚠️  Recovered key does not match public key\n")
				// display for debug
				pubX, pubY := ekf.curve.ScalarBaseMult(privateKey.Bytes())
				expectedPubKey, err := ekf.ParsePublicKey(ekf.data.PublicKey)
				if err == nil && expectedPubKey != nil {
					fmt.Printf("    Recovered key: X=%s, Y=%s\n", pubX.String(), pubY.String())
					fmt.Printf("    Expected key: X=%s, Y=%s\n", expectedPubKey.X.String(), expectedPubKey.Y.String())

					// check if only one bit differs (may be curve issue)
					if pubX.Cmp(expectedPubKey.X) == 0 {
						fmt.Printf("    ✓ X matches\n")
					}
					if pubY.Cmp(expectedPubKey.Y) == 0 {
						fmt.Printf("    ✓ Y matches\n")
					}
				} else {
					fmt.Printf("    ⚠️  Error parsing public key: %v\n", err)
				}
			}
		}
	}

	// Method 2: if we know the nonce (transaction count)
	for _, tx := range ekf.transactions {
		// check that r, s are valid
		if tx.R == "0x0" || tx.S == "0x0" {
			continue
		}

		r, err := hexToBigInt(tx.R)
		if err != nil {
			continue
		}
		s, err := hexToBigInt(tx.S)
		if err != nil {
			continue
		}

		// check that r and s are not zero
		if r.Sign() == 0 || s.Sign() == 0 {
			continue
		}

		msg, err := hex.DecodeString(tx.Message)
		if err != nil {
			msg = []byte(tx.Message)
		}
		z := hashMessage(msg, ekf.curve)

		// use nonce = transaction count
		nonce := big.NewInt(int64(tx.Nonce))
		n := ekf.curve.Params().N

		rInv := new(big.Int).ModInverse(r, n)
		if rInv == nil {
			continue
		}

		// d = (s*k - z) * r^-1 mod n
		sk := new(big.Int).Mul(s, nonce)
		skMinusZ := new(big.Int).Sub(sk, z)
		privateKey := new(big.Int).Mul(skMinusZ, rInv)
		privateKey.Mod(privateKey, n)

		// verify
		if ekf.verifyPrivateKey(privateKey) {
			fmt.Printf("✓ Found: from transaction with nonce %d\n", tx.Nonce)
			return privateKey, nil
		}
	}

	return nil, fmt.Errorf("cannot find private key")
}

// verifyPrivateKey verify private key using public key
func (ekf *EthereumKeyFinder) verifyPrivateKey(privateKey *big.Int) bool {
	if ekf.data == nil || ekf.data.PublicKey == "" {
		return false
	}

	// calculate public key from private key
	// ScalarBaseMult calculates: privateKey * G
	pubX, pubY := ekf.curve.ScalarBaseMult(privateKey.Bytes())

	// compare with provided public key
	expectedPubKey, err := ekf.ParsePublicKey(ekf.data.PublicKey)
	if err != nil {
		return false
	}

	return pubX.Cmp(expectedPubKey.X) == 0 && pubY.Cmp(expectedPubKey.Y) == 0
}

// hexToBigInt convert hex string to big.Int
// use function from ethereum package
func hexToBigInt(hexStr string) (*big.Int, error) {
	return ethereum.HexToBigInt(hexStr)
}

// hashMessage hash message
func hashMessage(message []byte, curve elliptic.Curve) *big.Int {
	hash := sha256.Sum256(message)
	z := new(big.Int).SetBytes(hash[:])
	n := curve.Params().N
	z.Mod(z, n)
	return z
}

func main() {
	fmt.Println("=== Private Key Search from Address and Transactions ===\n")

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run main1.go <data.json> [transactions.json|--etherscan <api_key> [cache_file]]")
		fmt.Println("\nOptions:")
		fmt.Println("  transactions.json           - use JSON file")
		fmt.Println("  --etherscan <key> [cache]   - use Etherscan API")
		fmt.Println("                                if cache_file is provided, data is saved to it")
		fmt.Println("                                if cache_file exists, it is used (no API call)")
		fmt.Println("\ndata.json format:")
		fmt.Println(`  {
    "address": "0x...",
    "public_key": "0x...",
    "tx_ids": ["tx1", "tx2", ...]
  }`)
		fmt.Println("\nExample:")
		fmt.Println("  go run main1.go data.json transactions.json")
		fmt.Println("  go run main1.go data.json --etherscan YOUR_API_KEY")
		os.Exit(1)
	}

	curve := elliptic.P256()
	finder := NewEthereumKeyFinder(curve)

	// load data
	fmt.Println("Loading data...")
	if err := finder.LoadFromJSON(os.Args[1]); err != nil {
		fmt.Printf("Error loading data.json: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address: %s\n", finder.data.Address)
	fmt.Printf("Public key: %s\n", finder.data.PublicKey)
	fmt.Printf("Number of TX IDs: %d\n\n", len(finder.data.TxIDs))

	// load transactions
	if len(os.Args) > 2 {
		if os.Args[2] == "--etherscan" || os.Args[2] == "-e" {
			// use Etherscan API
			if len(os.Args) < 4 {
				fmt.Println("⚠️  API Key required")
				fmt.Println("Usage: go run main1.go data.json --etherscan YOUR_API_KEY [cache_file]")
				fmt.Println("\nTo get API Key:")
				fmt.Println("  https://etherscan.io/apis")
				os.Exit(1)
			}
			apiKey := os.Args[3]
			useTxIDs := len(finder.data.TxIDs) > 0

			// determine cache file (optional)
			cacheFile := "transactions.json"
			if len(os.Args) > 4 {
				cacheFile = os.Args[4]
			}

			if err := finder.LoadTransactionsFromEtherscan(apiKey, useTxIDs, cacheFile); err != nil {
				fmt.Printf("Error loading from Etherscan: %v\n", err)
				os.Exit(1)
			}
		} else {
			// use JSON file
			fmt.Println("Loading transactions from JSON file...")
			if err := finder.LoadTransactionsFromJSON(os.Args[2]); err != nil {
				fmt.Printf("Error loading transactions.json: %v\n", err)
				os.Exit(1)
			}
		}
	} else {
		// suggest using Etherscan
		fmt.Println("⚠️  transactions.json file or Etherscan API not provided")
		fmt.Println("\nOptions:")
		fmt.Println("  1. Use JSON file:")
		fmt.Println("     go run main1.go data.json transactions.json")
		fmt.Println("  2. Use Etherscan API:")
		fmt.Println("     go run main1.go data.json --etherscan YOUR_API_KEY")
		fmt.Println("\nTo get API Key: https://etherscan.io/apis")
		os.Exit(1)
	}

	// search for private key
	privateKey, err := finder.FindPrivateKeyFromTransactions()
	if err != nil {
		fmt.Printf("\n✗ Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Private key found!\n")
	fmt.Printf("Private key: %s\n", privateKey.String())
	fmt.Printf("Private key (hex): 0x%s\n", privateKey.Text(16))

	// final verification
	if finder.verifyPrivateKey(privateKey) {
		fmt.Println("\n✓ Private key matches public key!")
	} else {
		fmt.Println("\n⚠️  Private key does not match public key!")
	}
}
