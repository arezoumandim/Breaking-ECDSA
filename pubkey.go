package main

//
//import (
//	"crypto/ecdsa"
//	"encoding/json"
//	"fmt"
//	"io"
//	"log"
//	"math/big"
//	"net/http"
//	"strings"
//
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/ethereum/go-ethereum/crypto"
//)
//
//const (
//	EtherscanAPIURL = "https://api.etherscan.io/v2/api"
//	APIKey          = "FYTRFAWRBDE5CMAWN24KYBXP1PB5BI56WK"
//	//APIKey          = "FWCCUB2BTYAH862VCZUJ98SEPNY8TG72XV"
//)
//
//type EtherscanTxResponse struct {
//	Status  string `json:"status"`
//	Message string `json:"message"`
//	Result  struct {
//		BlockNumber          string `json:"blockNumber"`
//		TimeStamp            string `json:"timeStamp"`
//		Hash                 string `json:"hash"`
//		Nonce                string `json:"nonce"`
//		From                 string `json:"from"`
//		To                   string `json:"to"`
//		Value                string `json:"value"`
//		Gas                  string `json:"gas"`
//		GasPrice             string `json:"gasPrice"`
//		Input                string `json:"input"`
//		TransactionIndex     string `json:"transactionIndex"`
//		Type                 string `json:"type"`
//		V                    string `json:"v"`
//		R                    string `json:"r"`
//		S                    string `json:"s"`
//		ChainId              string `json:"chainId"`
//		MaxFeePerGas         string `json:"maxFeePerGas"`
//		MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
//	} `json:"result"`
//}
//
//func main() {
//	// Example transaction hash
//	txHash := "0xa8312a549cdf57ac3364d3fe16bb016a230f1191faa16463a4955d62e20af395" // Replace with your transaction hash
//
//	// Get transaction details from Etherscan
//	txData, err := getTransactionFromEtherscan(txHash)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Recover the public key
//	pubKey, err := recoverPublicKey(txData)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Transaction Hash: %s\n", txHash)
//	fmt.Printf("From Address: %s\n", txData.Result.From)
//	fmt.Printf("Public Key (hex): %x\n", crypto.FromECDSAPub(pubKey))
//	fmt.Printf("Public Key (compressed): %x\n", crypto.CompressPubkey(pubKey))
//
//	// Verify by deriving address from public key
//	derivedAddress := crypto.PubkeyToAddress(*pubKey)
//	fmt.Printf("Derived Address: %s\n", derivedAddress.Hex())
//	fmt.Printf("Match: %v\n", strings.ToLower(derivedAddress.Hex()) == txData.Result.From)
//	fmt.Printf("Match: %s == %s\n", strings.ToLower(derivedAddress.Hex()), txData.Result.From)
//}
//
//func getTransactionFromEtherscan(txHash string) (*EtherscanTxResponse, error) {
//	url := fmt.Sprintf("%s?chainid=1&module=proxy&action=eth_getTransactionByHash&txhash=%s&apikey=%s",
//		EtherscanAPIURL, txHash, APIKey)
//
//	resp, err := http.Get(url)
//	if err != nil {
//		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
//	}
//	defer resp.Body.Close()
//
//	body, err := io.ReadAll(resp.Body)
//	if err != nil {
//		return nil, fmt.Errorf("failed to read response: %w", err)
//	}
//
//	var txResp EtherscanTxResponse
//	if err := json.Unmarshal(body, &txResp); err != nil {
//		return nil, fmt.Errorf("failed to parse response: %w", err)
//	}
//
//	if txResp.Status == "0" {
//		return nil, fmt.Errorf("etherscan API error: %s", txResp.Message)
//	}
//
//	return &txResp, nil
//}
//
//// Fixed function signature
//func recoverPublicKey(txData *EtherscanTxResponse) (*ecdsa.PublicKey, error) {
//	// Parse transaction parameters
//	nonce := hexToBigInt(txData.Result.Nonce)
//	gasPrice := hexToBigInt(txData.Result.GasPrice)
//	gasLimit := hexToBigInt(txData.Result.Gas)
//	to := common.HexToAddress(txData.Result.To)
//	value := hexToBigInt(txData.Result.Value)
//	data := common.FromHex(txData.Result.Input)
//
//	v := hexToBigInt(txData.Result.V)
//	r := hexToBigInt(txData.Result.R)
//	s := hexToBigInt(txData.Result.S)
//
//	// Determine transaction type and create appropriate transaction
//	var tx *types.Transaction
//
//	if txData.Result.Type == "0x2" || txData.Result.Type == "2" {
//		// EIP-1559 transaction (Type 2)
//		maxFeePerGas := hexToBigInt(txData.Result.MaxFeePerGas)
//		maxPriorityFeePerGas := hexToBigInt(txData.Result.MaxPriorityFeePerGas)
//		chainID := hexToBigInt(txData.Result.ChainId)
//
//		tx = types.NewTx(&types.DynamicFeeTx{
//			ChainID:   chainID,
//			Nonce:     nonce.Uint64(),
//			GasTipCap: maxPriorityFeePerGas,
//			GasFeeCap: maxFeePerGas,
//			Gas:       gasLimit.Uint64(),
//			To:        &to,
//			Value:     value,
//			Data:      data,
//			V:         v,
//			R:         r,
//			S:         s,
//		})
//	} else if txData.Result.Type == "0x1" || txData.Result.Type == "1" {
//		// EIP-2930 transaction (Type 1)
//		chainID := hexToBigInt(txData.Result.ChainId)
//
//		tx = types.NewTx(&types.AccessListTx{
//			ChainID:  chainID,
//			Nonce:    nonce.Uint64(),
//			GasPrice: gasPrice,
//			Gas:      gasLimit.Uint64(),
//			To:       &to,
//			Value:    value,
//			Data:     data,
//			V:        v,
//			R:        r,
//			S:        s,
//		})
//	} else {
//		// Legacy transaction (Type 0)
//		tx = types.NewTransaction(
//			nonce.Uint64(),
//			to,
//			value,
//			gasLimit.Uint64(),
//			gasPrice,
//			data,
//		)
//
//		var err error = nil
//		tx, err = tx.WithSignature(types.HomesteadSigner{}, createSignature(r, s, v))
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// Create appropriate signer
//	chainID := hexToBigInt(txData.Result.ChainId)
//	if chainID == nil || chainID.Sign() == 0 {
//		chainID = big.NewInt(1) // Mainnet
//	}
//
//	var signer types.Signer
//	switch txData.Result.Type {
//	case "0x2", "2":
//		signer = types.NewLondonSigner(chainID)
//	case "0x1", "1":
//		signer = types.NewEIP2930Signer(chainID)
//	default:
//		signer = types.NewEIP155Signer(chainID)
//	}
//
//	// Recover public key - returns *ecdsa.PublicKey
//	pubKey, err := crypto.SigToPub(signer.Hash(tx).Bytes(), createSignature(r, s, v))
//	if err != nil {
//		return nil, fmt.Errorf("failed to recover public key: %w", err)
//	}
//
//	return pubKey, nil
//}
//
//func hexToBigInt(hex string) *big.Int {
//	if hex == "" || hex == "0x" {
//		return big.NewInt(0)
//	}
//	n := new(big.Int)
//	n.SetString(hex[2:], 16) // Remove "0x" prefix
//	return n
//}
//
//func createSignature(r, s, v *big.Int) []byte {
//	sig := make([]byte, 65)
//	copy(sig[32-len(r.Bytes()):32], r.Bytes())
//	copy(sig[64-len(s.Bytes()):64], s.Bytes())
//
//	// Normalize V value (should be 0 or 1 for recovery)
//	vByte := byte(v.Uint64())
//	if vByte >= 27 {
//		vByte -= 27
//	}
//	sig[64] = vByte
//
//	return sig
//}
