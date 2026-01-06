package ethereum

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EtherscanClient client for Etherscan API
type EtherscanClient struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// NewEtherscanClient create a new client
func NewEtherscanClient(apiKey string) *EtherscanClient {
	return &EtherscanClient{
		apiKey:  apiKey,
		baseURL: "https://api.etherscan.io/v2/api", // use v2 API
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// EtherscanTransactionResponse Etherscan API response
type EtherscanTransactionResponse struct {
	Status  string                    `json:"status"`
	Message string                    `json:"message"`
	Result  []EtherscanTransactionRaw `json:"result"`
}

// EtherscanTransactionRaw raw transaction from Etherscan (v2 API format)
type EtherscanTransactionRaw struct {
	BlockNumber          string `json:"blockNumber"`
	TimeStamp            string `json:"timeStamp"`
	Hash                 string `json:"hash"`
	Nonce                string `json:"nonce"`
	BlockHash            string `json:"blockHash"`
	TransactionIndex     string `json:"transactionIndex"`
	From                 string `json:"from"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Gas                  string `json:"gas"`
	GasPrice             string `json:"gasPrice"`
	Input                string `json:"input"`
	Type                 string `json:"type"`
	V                    string `json:"v"`
	R                    string `json:"r"`
	S                    string `json:"s"`
	ChainId              string `json:"chainId"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	IsError              string `json:"isError"`
	TxReceiptStatus      string `json:"txreceipt_status"`
	ContractAddress      string `json:"contractAddress"`
	CumulativeGasUsed    string `json:"cumulativeGasUsed"`
	GasUsed              string `json:"gasUsed"`
	Confirmations        string `json:"confirmations"`
}

// EtherscanTransactionReceiptResponse receipt response
type EtherscanTransactionReceiptResponse struct {
	Status  string                      `json:"status"`
	Message string                      `json:"message"`
	Result  EtherscanTransactionReceipt `json:"result"`
}

// EtherscanTransactionReceipt transaction receipt
type EtherscanTransactionReceipt struct {
	BlockHash         string        `json:"blockHash"`
	BlockNumber       string        `json:"blockNumber"`
	ContractAddress   string        `json:"contractAddress"`
	CumulativeGasUsed string        `json:"cumulativeGasUsed"`
	From              string        `json:"from"`
	GasUsed           string        `json:"gasUsed"`
	Logs              []interface{} `json:"logs"`
	LogsBloom         string        `json:"logsBloom"`
	Status            string        `json:"status"`
	To                string        `json:"to"`
	TransactionHash   string        `json:"transactionHash"`
	TransactionIndex  string        `json:"transactionIndex"`
}

// GetTransactions get list of transactions for an address
func (ec *EtherscanClient) GetTransactions(address string, startBlock, endBlock int64) ([]EtherscanTransactionRaw, error) {
	// use v1 API for txlist (v2 may not support it)
	url := fmt.Sprintf("https://api.etherscan.io/api?module=account&action=txlist&address=%s&startblock=%d&endblock=%d&sort=asc&apikey=%s",
		address, startBlock, endBlock, ec.apiKey)

	resp, err := ec.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error in API request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	var apiResp EtherscanTransactionResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	if apiResp.Status != "1" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	return apiResp.Result, nil
}

// GetTransactionByHash get transaction information by hash (v2 API)
func (ec *EtherscanClient) GetTransactionByHash(txHash string) (*EtherscanTransactionRaw, error) {
	// use v2 API with chainid=1 for mainnet
	url := fmt.Sprintf("%s?chainid=1&module=proxy&action=eth_getTransactionByHash&txhash=%s&apikey=%s",
		ec.baseURL, txHash, ec.apiKey)

	resp, err := ec.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error in API request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	// v2 API structure - result is an object not an array
	// use structure similar to pubkey.go
	var apiResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  struct {
			BlockNumber          string `json:"blockNumber"`
			TimeStamp            string `json:"timeStamp"`
			Hash                 string `json:"hash"`
			Nonce                string `json:"nonce"`
			From                 string `json:"from"`
			To                   string `json:"to"`
			Value                string `json:"value"`
			Gas                  string `json:"gas"`
			GasPrice             string `json:"gasPrice"`
			Input                string `json:"input"`
			TransactionIndex     string `json:"transactionIndex"`
			Type                 string `json:"type"`
			V                    string `json:"v"`
			R                    string `json:"r"`
			S                    string `json:"s"`
			ChainId              string `json:"chainId"`
			MaxFeePerGas         string `json:"maxFeePerGas"`
			MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	if apiResp.Status == "0" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	// convert to EtherscanTransactionRaw
	rawTx := &EtherscanTransactionRaw{
		BlockNumber:          apiResp.Result.BlockNumber,
		TimeStamp:            apiResp.Result.TimeStamp,
		Hash:                 apiResp.Result.Hash,
		Nonce:                apiResp.Result.Nonce,
		From:                 apiResp.Result.From,
		To:                   apiResp.Result.To,
		Value:                apiResp.Result.Value,
		Gas:                  apiResp.Result.Gas,
		GasPrice:             apiResp.Result.GasPrice,
		Input:                apiResp.Result.Input,
		TransactionIndex:     apiResp.Result.TransactionIndex,
		Type:                 apiResp.Result.Type,
		V:                    apiResp.Result.V,
		R:                    apiResp.Result.R,
		S:                    apiResp.Result.S,
		ChainId:              apiResp.Result.ChainId,
		MaxFeePerGas:         apiResp.Result.MaxFeePerGas,
		MaxPriorityFeePerGas: apiResp.Result.MaxPriorityFeePerGas,
	}

	// Debug: check if r, s, v are populated
	if rawTx.R == "" || rawTx.S == "" || rawTx.V == "" {
		fmt.Printf("⚠️  Warning: r, s, v not received from API for transaction %s\n", txHash)
		fmt.Printf("  R: '%s', S: '%s', V: '%s'\n", rawTx.R, rawTx.S, rawTx.V)
		fmt.Printf("  This transaction cannot be used for key recovery\n")
	} else {
		fmt.Printf("✓ r, s, v received for transaction %s\n", txHash)
		fmt.Printf("  R: %s... (length: %d), S: %s... (length: %d), V: %s\n",
			rawTx.R[:min(20, len(rawTx.R))], len(rawTx.R),
			rawTx.S[:min(20, len(rawTx.S))], len(rawTx.S),
			rawTx.V)
	}

	return rawTx, nil
}

// GetTransactionReceipt get transaction receipt (for v and r, s)
func (ec *EtherscanClient) GetTransactionReceipt(txHash string) (*EtherscanTransactionReceipt, error) {
	url := fmt.Sprintf("%s?module=proxy&action=eth_getTransactionReceipt&txhash=%s&apikey=%s",
		ec.baseURL, txHash, ec.apiKey)

	resp, err := ec.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error in API request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	var apiResp EtherscanTransactionReceiptResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	if apiResp.Status != "1" && apiResp.Message != "" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	return &apiResp.Result, nil
}

// GetRawTransaction get raw transaction (including r, s, v) - v2 API
func (ec *EtherscanClient) GetRawTransaction(txHash string) (map[string]interface{}, error) {
	// use v2 API with chainid=1
	url := fmt.Sprintf("%s?chainid=1&module=proxy&action=eth_getTransactionByHash&txhash=%s&apikey=%s",
		ec.baseURL, txHash, ec.apiKey)

	resp, err := ec.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error in API request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	// v2 API structure - result can be object or string
	var apiResp struct {
		Status  string      `json:"status"`
		Message string      `json:"message"`
		Result  interface{} `json:"result"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	if apiResp.Status == "0" {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	if apiResp.Result == nil {
		return nil, fmt.Errorf("result is empty")
	}

	// check result type
	resultMap, ok := apiResp.Result.(map[string]interface{})
	if !ok {
		// if result is a string
		if resultStr, ok := apiResp.Result.(string); ok {
			if resultStr == "null" || resultStr == "" {
				return nil, fmt.Errorf("transaction not found")
			}
			return nil, fmt.Errorf("result is a string: %s", resultStr)
		}
		return nil, fmt.Errorf("invalid result type: %T", apiResp.Result)
	}

	return resultMap, nil
}

// ConvertEtherscanTxToTransactionInfo convert Etherscan transaction to TransactionInfo
func ConvertEtherscanTxToTransactionInfo(
	rawTx *EtherscanTransactionRaw,
	rawTxData map[string]interface{},
) (*TransactionInfo, error) {
	// convert nonce
	var nonce uint64
	if strings.HasPrefix(rawTx.Nonce, "0x") {
		// nonce is in hex format
		nonceBig, err := hexToBigInt(rawTx.Nonce)
		if err != nil {
			return nil, fmt.Errorf("error converting nonce hex: %v", err)
		}
		nonce = nonceBig.Uint64()
	} else {
		// nonce is in decimal format
		var err error
		nonce, err = strconv.ParseUint(rawTx.Nonce, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error converting nonce decimal: %v", err)
		}
	}

	// extract r, s, v from raw transaction
	// in v2 API, these values are directly in Result
	var r, s string
	var v uint8

	// first try from rawTxData (raw transaction)
	if rawTxData != nil {
		if rVal, ok := rawTxData["r"].(string); ok {
			r = rVal
		}
		if sVal, ok := rawTxData["s"].(string); ok {
			s = sVal
		}
		if vVal, ok := rawTxData["v"].(string); ok {
			vBig, err := hexToBigInt(vVal)
			if err == nil {
				v = uint8(vBig.Uint64())
			}
		}
	}

	// if not found, use rawTx (from GetTransactionByHash)
	if r == "" && rawTx.R != "" {
		r = rawTx.R
	}
	if s == "" && rawTx.S != "" {
		s = rawTx.S
	}
	if v == 0 && rawTx.V != "" {
		vBig, err := hexToBigInt(rawTx.V)
		if err == nil {
			v = uint8(vBig.Uint64())
		}
	}

	// if still not found, use default values
	if r == "" {
		r = "0x0" // placeholder
	}
	if s == "" {
		s = "0x0" // placeholder
	}
	if v == 0 {
		v = 27 // default for mainnet
	}

	// calculate message hash (in reality RLP encoding should be performed)
	// for simplicity, use transaction hash
	message := rawTx.Hash

	return &TransactionInfo{
		TxID:    rawTx.Hash,
		From:    rawTx.From,
		To:      rawTx.To,
		Value:   rawTx.Value,
		Nonce:   nonce,
		R:       r,
		S:       s,
		V:       v,
		Message: message,
		Data:    rawTx.Input,
	}, nil
}

// hexToBigInt convert hex string to big.Int
// use common function
func hexToBigInt(hexStr string) (*big.Int, error) {
	return HexToBigInt(hexStr)
}

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

// GetTransactionsByIDs get multiple transactions by specified IDs
func (ec *EtherscanClient) GetTransactionsByIDs(txIDs []string) ([]*TransactionInfo, error) {
	transactions := make([]*TransactionInfo, 0, len(txIDs))

	for _, txID := range txIDs {
		// get transaction info from txlist API (has more information)
		rawTx, err := ec.GetTransactionByHash(txID)
		if err != nil {
			fmt.Printf("⚠️  Error getting transaction %s: %v\n", txID, err)
			continue
		}

		// try to get raw transaction (for r, s, v)
		// but if error, continue
		rawTxData, err := ec.GetRawTransaction(txID)
		if err != nil {
			// if we can't get raw transaction, use default values
			fmt.Printf("⚠️  Warning: cannot get r, s, v for transaction %s: %v\n", txID, err)
			rawTxData = nil
		}

		// convert to TransactionInfo
		txInfo, err := ConvertEtherscanTxToTransactionInfo(rawTx, rawTxData)
		if err != nil {
			fmt.Printf("⚠️  Error converting transaction %s: %v\n", txID, err)
			continue
		}

		transactions = append(transactions, txInfo)
	}

	return transactions, nil
}

// GetTransactionsByAddress get all transactions for an address
func (ec *EtherscanClient) GetTransactionsByAddress(address string) ([]*TransactionInfo, error) {
	// get list of transactions
	rawTxs, err := ec.GetTransactions(address, 0, 99999999)
	if err != nil {
		return nil, err
	}

	transactions := make([]*TransactionInfo, 0, len(rawTxs))

	for _, rawTx := range rawTxs {
		// get raw transaction data for r, s, v
		// but if error, continue with rawTxData = nil
		rawTxData, err := ec.GetRawTransaction(rawTx.Hash)
		if err != nil {
			// if we can't get raw transaction, use default values
			fmt.Printf("⚠️  Warning: cannot get r, s, v for transaction %s: %v\n", rawTx.Hash, err)
			rawTxData = nil
		}

		// convert to TransactionInfo
		txInfo, err := ConvertEtherscanTxToTransactionInfo(&rawTx, rawTxData)
		if err != nil {
			fmt.Printf("⚠️  Error converting transaction %s: %v\n", rawTx.Hash, err)
			continue
		}

		transactions = append(transactions, txInfo)
	}

	return transactions, nil
}
