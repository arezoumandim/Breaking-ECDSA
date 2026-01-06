package ethereum

import (
	"encoding/hex"
	"math/big"
)

// HexToBigInt convert hex string to big.Int (common function)
func HexToBigInt(hexStr string) (*big.Int, error) {
	// remove 0x
	if len(hexStr) > 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// if empty, return zero
	if hexStr == "" {
		return big.NewInt(0), nil
	}

	// if length is odd, add a zero at the beginning
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(bytes), nil
}

// HexToBigIntSafe convert hex string to big.Int with error handling
func HexToBigIntSafe(hexStr string) *big.Int {
	result, err := HexToBigInt(hexStr)
	if err != nil {
		return big.NewInt(0)
	}
	return result
}
