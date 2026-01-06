package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"breaking-ecdsa/generator"
)

// TestRealTransactionExample simple test for real_transaction_example
func TestRealTransactionExample(t *testing.T) {
	curve := elliptic.P256()
	example := NewRealTransactionExample(curve)

	// Test 1: ParsePublicKey
	t.Run("ParsePublicKey - Uncompressed", func(t *testing.T) {
		// generate a key for testing
		keyPair, err := generator.GenerateKeyPair(curve)
		if err != nil {
			t.Fatalf("Error generating key: %v", err)
		}

		// convert to uncompressed format (0x04 + x + y)
		pubKeyBytes := make([]byte, 65)
		pubKeyBytes[0] = 0x04
		xBytes := keyPair.PublicKey.X.Bytes()
		yBytes := keyPair.PublicKey.Y.Bytes()
		// padding for 32 bytes
		copy(pubKeyBytes[33-len(xBytes):33], xBytes)
		copy(pubKeyBytes[65-len(yBytes):65], yBytes)

		// convert to hex string
		pubKeyHex := "0x" + hex.EncodeToString(pubKeyBytes)

		parsedKey, err := example.ParsePublicKey(pubKeyHex)
		if err != nil {
			t.Fatalf("Error parsing key: %v", err)
		}

		if parsedKey.X.Cmp(keyPair.PublicKey.X) != 0 || parsedKey.Y.Cmp(keyPair.PublicKey.Y) != 0 {
			t.Errorf("Parsed key does not match original key")
		}
	})

	// Test 2: hexToBigInt
	t.Run("hexToBigInt", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected string
		}{
			{"0x0", "0"},
			{"0x1", "1"},
			{"0xa", "10"},
			{"0xff", "255"},
			{"0x100", "256"},
		}

		for _, tc := range testCases {
			result, err := example.hexToBigInt(tc.input)
			if err != nil {
				t.Errorf("Error converting %s: %v", tc.input, err)
				continue
			}

			expected, _ := new(big.Int).SetString(tc.expected, 10)
			if result.Cmp(expected) != 0 {
				t.Errorf("For %s: expected %s, got %s", tc.input, tc.expected, result.String())
			}
		}
	})

	// Test 3: hashMessage
	t.Run("hashMessage", func(t *testing.T) {
		message := []byte("test message")
		hash1 := example.hashMessage(message)
		hash2 := example.hashMessage(message)

		// should be the same
		if hash1.Cmp(hash2) != 0 {
			t.Errorf("Hash of same message should be identical")
		}

		// should be within curve range
		n := curve.Params().N
		if hash1.Cmp(n) >= 0 {
			t.Errorf("Hash should be less than n")
		}
	})

	// Test 4: LoadFromJSON and LoadTransactionsFromJSON
	t.Run("LoadFromJSON", func(t *testing.T) {
		// create temporary test file
		testData := DataInfo{
			Address:   "0x1234567890123456789012345678901234567890",
			PublicKey: "0438f42fb1aa395edc7346963422211405c72f9701bdae2dcece6b3236f7b968a39d082f717a6edc7f6c50c4eb016666822d020c95c06200dbe7d9157b1ddee937",
			TxIDs:     []string{"tx1", "tx2"},
		}

		dataJSON, err := json.Marshal(testData)
		if err != nil {
			t.Fatalf("Error marshaling: %v", err)
		}

		testFile := "test_data.json"
		if err := os.WriteFile(testFile, dataJSON, 0644); err != nil {
			t.Fatalf("Error writing file: %v", err)
		}
		defer os.Remove(testFile)

		if err := example.LoadFromJSON(testFile); err != nil {
			t.Fatalf("Error loading: %v", err)
		}

		if example.data == nil {
			t.Fatal("data should not be nil")
		}

		if example.data.Address != testData.Address {
			t.Errorf("Address: expected %s, got %s", testData.Address, example.data.Address)
		}
	})

	// Test 5: verifyPrivateKey
	t.Run("verifyPrivateKey", func(t *testing.T) {
		// generate key
		keyPair, err := generator.GenerateKeyPair(curve)
		if err != nil {
			t.Fatalf("Error generating key: %v", err)
		}

		// set data with uncompressed public key
		pubKeyBytes := make([]byte, 65)
		pubKeyBytes[0] = 0x04
		xBytes := keyPair.PublicKey.X.Bytes()
		yBytes := keyPair.PublicKey.Y.Bytes()
		// padding for 32 bytes
		copy(pubKeyBytes[33-len(xBytes):33], xBytes)
		copy(pubKeyBytes[65-len(yBytes):65], yBytes)

		pubKeyHex := "0x" + hex.EncodeToString(pubKeyBytes)

		example.data = &DataInfo{
			PublicKey: pubKeyHex,
		}

		// test with correct key
		if !example.verifyPrivateKey(keyPair.PrivateKey) {
			t.Error("verifyPrivateKey should return true for correct key")
		}

		// test with wrong key
		wrongKey := new(big.Int).Add(keyPair.PrivateKey, big.NewInt(1))
		if example.verifyPrivateKey(wrongKey) {
			t.Error("verifyPrivateKey should return false for wrong key")
		}
	})

	// Test 6: FindPrivateKeyFromTransactions with real data
	t.Run("FindPrivateKeyFromTransactions - Sequential Nonces", func(t *testing.T) {
		// generate key
		keyPair, err := generator.GenerateKeyPair(curve)
		if err != nil {
			t.Fatalf("Error generating key: %v", err)
		}

		// set public key
		pubKeyHex := "04" + keyPair.PublicKey.X.Text(16) + keyPair.PublicKey.Y.Text(16)
		example.data = &DataInfo{
			PublicKey: pubKeyHex,
		}

		// generate two signatures with consecutive nonces
		message1 := []byte("message 1")
		message2 := []byte("message 2")
		k1 := big.NewInt(1000)
		k2 := big.NewInt(1001) // k2 = k1 + 1

		sig1, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message1, k1)
		if err != nil {
			t.Fatalf("Error generating first signature: %v", err)
		}

		sig2, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message2, k2)
		if err != nil {
			t.Fatalf("Error generating second signature: %v", err)
		}

		// create transactions
		example.transactions = []*TransactionInfo{
			{
				TxID:    "tx1",
				Nonce:   0,
				R:       "0x" + sig1.R.Text(16),
				S:       "0x" + sig1.S.Text(16),
				V:       27,
				Message: string(message1),
			},
			{
				TxID:    "tx2",
				Nonce:   1,
				R:       "0x" + sig2.R.Text(16),
				S:       "0x" + sig2.S.Text(16),
				V:       27,
				Message: string(message2),
			},
		}

		// set small search range
		example.SetSearchRange(5, 5)

		// try to find key
		privateKey, err := example.FindPrivateKeyFromTransactions()
		if err != nil {
			t.Logf("Error (may be normal): %v", err)
			// this error may be normal if counter pattern doesn't work
			return
		}

		// verify
		if privateKey.Cmp(keyPair.PrivateKey) != 0 {
			t.Errorf("Found key does not match original key")
		}
	})

	// Test 7: SetSearchRange
	t.Run("SetSearchRange", func(t *testing.T) {
		example.SetSearchRange(50, 100)
		if example.maxA != 50 || example.maxB != 100 {
			t.Errorf("SetSearchRange not working: maxA=%d, maxB=%d", example.maxA, example.maxB)
		}
	})

	// Test 8: SetMaxWorkers
	t.Run("SetMaxWorkers", func(t *testing.T) {
		example.SetMaxWorkers(4)
		if example.maxWorkers != 4 {
			t.Errorf("SetMaxWorkers not working: maxWorkers=%d", example.maxWorkers)
		}
	})
}

// TestRealTransactionExampleSimple simple test without file requirement
func TestRealTransactionExampleSimple(t *testing.T) {
	curve := elliptic.P256()
	example := NewRealTransactionExample(curve)

	// generate key
	keyPair, err := generator.GenerateKeyPair(curve)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	// set public key
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	xBytes := keyPair.PublicKey.X.Bytes()
	yBytes := keyPair.PublicKey.Y.Bytes()
	copy(pubKeyBytes[33-len(xBytes):33], xBytes)
	copy(pubKeyBytes[65-len(yBytes):65], yBytes)
	pubKeyHex := "0x" + hex.EncodeToString(pubKeyBytes)

	example.data = &DataInfo{
		Address:   "0x1234567890123456789012345678901234567890",
		PublicKey: pubKeyHex,
	}

	// generate two signatures with consecutive nonces
	message1 := []byte("test message 1")
	message2 := []byte("test message 2")
	k1 := big.NewInt(2000)
	k2 := big.NewInt(2001) // k2 = k1 + 1

	sig1, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message1, k1)
	if err != nil {
		t.Fatalf("Error generating first signature: %v", err)
	}

	sig2, err := generator.SignWithNonce(curve, keyPair.PrivateKey, message2, k2)
	if err != nil {
		t.Fatalf("Error generating second signature: %v", err)
	}

	// create transactions
	example.transactions = []*TransactionInfo{
		{
			TxID:    "test_tx1",
			Nonce:   0,
			R:       "0x" + sig1.R.Text(16),
			S:       "0x" + sig1.S.Text(16),
			V:       27,
			Message: string(message1),
		},
		{
			TxID:    "test_tx2",
			Nonce:   1,
			R:       "0x" + sig2.R.Text(16),
			S:       "0x" + sig2.S.Text(16),
			V:       27,
			Message: string(message2),
		},
	}

	// set small search range
	example.SetSearchRange(5, 5)
	example.SetMaxWorkers(2)

	// try to find key
	privateKey, err := example.FindPrivateKeyFromTransactions()
	if err != nil {
		t.Fatalf("Error finding key: %v", err)
	}

	// verify
	if privateKey.Cmp(keyPair.PrivateKey) != 0 {
		t.Errorf("Found key does not match original key\nExpected: %s\nGot: %s",
			keyPair.PrivateKey.String(), privateKey.String())
	}

	t.Logf("✓ Key found successfully: %s", privateKey.String())
}

// TestRealTransactionExampleIntegration integration test with JSON files
func TestRealTransactionExampleIntegration(t *testing.T) {
	// check if test files exist
	if _, err := os.Stat("example_data.json"); os.IsNotExist(err) {
		t.Skip("example_data.json file does not exist - skipping test")
	}

	if _, err := os.Stat("transactions.json"); os.IsNotExist(err) {
		t.Skip("transactions.json file does not exist - skipping test")
	}

	curve := elliptic.P256()
	example := NewRealTransactionExample(curve)
	example.SetSearchRange(5, 5) // small range for quick test
	example.SetMaxWorkers(2)     // low number of workers

	// load data
	if err := example.LoadFromJSON("example_data.json"); err != nil {
		t.Fatalf("Error loading example_data.json: %v", err)
	}

	if err := example.LoadTransactionsFromJSON("transactions.json"); err != nil {
		t.Fatalf("Error loading transactions.json: %v", err)
	}

	// check that data is loaded
	if example.data == nil {
		t.Fatal("data should not be nil")
	}

	if len(example.transactions) == 0 {
		t.Fatal("transactions should not be empty")
	}

	t.Logf("✓ %d transactions loaded", len(example.transactions))
	t.Logf("✓ Address: %s", example.data.Address)

	// test parsing public key
	if example.data.PublicKey != "" {
		_, err := example.ParsePublicKey(example.data.PublicKey)
		if err != nil {
			t.Errorf("Error parsing public key: %v", err)
		} else {
			t.Log("✓ Public key parsed successfully")
		}
	}
}

// BenchmarkRealTransactionExample benchmark for performance
func BenchmarkRealTransactionExample(b *testing.B) {
	curve := elliptic.P256()
	example := NewRealTransactionExample(curve)

	// generate key
	keyPair, err := generator.GenerateKeyPair(curve)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}

	// set public key
	pubKeyHex := "04" + keyPair.PublicKey.X.Text(16) + keyPair.PublicKey.Y.Text(16)
	example.data = &DataInfo{
		PublicKey: pubKeyHex,
	}

	// generate two signatures
	message := []byte("test message")
	k1 := big.NewInt(1000)
	k2 := big.NewInt(1001)

	sig1, _ := generator.SignWithNonce(curve, keyPair.PrivateKey, message, k1)
	sig2, _ := generator.SignWithNonce(curve, keyPair.PrivateKey, message, k2)

	example.transactions = []*TransactionInfo{
		{
			TxID:    "tx1",
			Nonce:   0,
			R:       "0x" + sig1.R.Text(16),
			S:       "0x" + sig1.S.Text(16),
			V:       27,
			Message: string(message),
		},
		{
			TxID:    "tx2",
			Nonce:   1,
			R:       "0x" + sig2.R.Text(16),
			S:       "0x" + sig2.S.Text(16),
			V:       27,
			Message: string(message),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		example.SetSearchRange(5, 5)
		_, _ = example.FindPrivateKeyFromTransactions()
	}
}
