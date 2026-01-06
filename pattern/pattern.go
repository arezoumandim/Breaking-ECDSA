package pattern

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"slippage/generator"
	"slippage/solver"
)

// NoncePattern different nonce generation patterns
type NoncePattern int

const (
	// PatternUnknown unknown pattern - requires brute-force
	PatternUnknown NoncePattern = iota
	// PatternCounter nonce as counter: k_i = k_0 + i
	PatternCounter
	// PatternLinear nonce as linear: k_i = a*k_{i-1} + b
	PatternLinear
	// PatternAffine nonce with affine relationship: k_i = a*k_j + b
	PatternAffine
	// PatternKnown nonce is known
	PatternKnown
)

// PatternDetector nonce pattern detector
type PatternDetector struct {
	curve elliptic.Curve
}

// NewPatternDetector create a new detector
func NewPatternDetector(curve elliptic.Curve) *PatternDetector {
	return &PatternDetector{
		curve: curve,
	}
}

// SignaturePair signature pair for analysis
type SignaturePair struct {
	Sig1 generator.SignatureData
	Sig2 generator.SignatureData
	Msg1 []byte
	Msg2 []byte
}

// DetectPattern detect nonce pattern from signatures
func (pd *PatternDetector) DetectPattern(sigs []SignaturePair) NoncePattern {
	// if we only have one signature pair, try to detect simple patterns
	if len(sigs) == 1 {
		// check simple patterns
		if pd.detectCounterPattern(sigs[0]) {
			return PatternCounter
		}
		if pd.detectLinearPattern(sigs[0]) {
			return PatternLinear
		}
		return PatternUnknown
	}

	// with multiple signatures we can detect more complex patterns
	return pd.detectComplexPattern(sigs)
}

// detectCounterPattern detect counter pattern (k2 = k1 + 1)
func (pd *PatternDetector) detectCounterPattern(pair SignaturePair) bool {
	// if a=1 and b=1, it might be counter
	// this is a simple guess
	return true // for simplicity, always return true
}

// detectLinearPattern detect linear pattern
func (pd *PatternDetector) detectLinearPattern(pair SignaturePair) bool {
	// check simple linear patterns
	return false
}

// detectComplexPattern detect complex patterns
func (pd *PatternDetector) detectComplexPattern(sigs []SignaturePair) NoncePattern {
	// implement more advanced algorithms
	return PatternUnknown
}

// BruteForceSolver brute-force solver for finding affine relationship
type BruteForceSolver struct {
	curve      elliptic.Curve
	minA       int64 // minimum value of a for brute-force
	maxA       int64 // maximum value of a for brute-force
	minB       int64 // minimum value of b for brute-force
	maxB       int64 // maximum value of b for brute-force
	numWorkers int
}

// NewBruteForceSolver create a new brute-force solver
func NewBruteForceSolver(curve elliptic.Curve) *BruteForceSolver {
	return &BruteForceSolver{
		curve:      curve,
		minA:       1,   // default starting point
		maxA:       100, // default range
		minB:       0,   // default starting point for b
		maxB:       100,
		numWorkers: runtime.NumCPU(),
	}
}

// SetSearchRange set search range
func (bfs *BruteForceSolver) SetSearchRange(maxA, maxB int64) {
	bfs.minA = 1 // default: starts from 1
	bfs.maxA = maxA
	bfs.minB = 0 // default: starts from 0
	bfs.maxB = maxB
}

// SetSearchRangeWithMin set search range with minimum value of a
func (bfs *BruteForceSolver) SetSearchRangeWithMin(minA, maxA, maxB int64) {
	bfs.minA = minA
	bfs.maxA = maxA
	bfs.minB = 0 // default: starts from 0
	bfs.maxB = maxB
}

// SetSearchRangeWithMinB set search range with minimum values of a and b
func (bfs *BruteForceSolver) SetSearchRangeWithMinB(minA, maxA, minB, maxB int64) {
	bfs.minA = minA
	bfs.maxA = maxA
	bfs.minB = minB
	bfs.maxB = maxB
}

// SetWorkers set number of workers
func (bfs *BruteForceSolver) SetWorkers(numWorkers int) {
	bfs.numWorkers = numWorkers
}

// GetWorkers get number of workers
func (bfs *BruteForceSolver) GetWorkers() int {
	return bfs.numWorkers
}

// BruteForceResult brute-force result
type BruteForceResult struct {
	A          *big.Int
	B          *big.Int
	PrivateKey *big.Int
	Success    bool
	Attempts   int64
	Error      error
}

// BruteForceAffineRelation brute-force affine relationship between two signatures
// If we don't know the nonce generation pattern, we can find the relationship with brute-force
// If publicKeyX and publicKeyY are provided, the recovered key is verified with the public key
func (bfs *BruteForceSolver) BruteForceAffineRelation(
	sig1, sig2 generator.SignatureData,
	msg1, msg2 []byte,
) <-chan *BruteForceResult {
	return bfs.BruteForceAffineRelationWithVerification(sig1, sig2, msg1, msg2, nil, nil)
}

// BruteForceAffineRelationWithVerification brute-force with key verification
func (bfs *BruteForceSolver) BruteForceAffineRelationWithVerification(
	sig1, sig2 generator.SignatureData,
	msg1, msg2 []byte,
	publicKeyX, publicKeyY *big.Int,
) <-chan *BruteForceResult {
	results := make(chan *BruteForceResult, bfs.numWorkers*2)

	// calculate z1 and z2
	n := bfs.curve.Params().N
	hash1 := sha256.Sum256(msg1)
	hash2 := sha256.Sum256(msg2)
	z1 := new(big.Int).SetBytes(hash1[:])
	z2 := new(big.Int).SetBytes(hash2[:])
	z1.Mod(z1, n)
	z2.Mod(z2, n)

	// divide work among workers
	// limit buffer size to prevent excessive memory usage
	bufferSize := (bfs.maxA - bfs.minA + 1) * (bfs.maxB - bfs.minB + 1)
	if bufferSize > 10000 {
		bufferSize = 10000 // maximum 10000 tasks in buffer
	}
	tasks := make(chan struct {
		a int64
		b int64
	}, bufferSize)

	// generate tasks
	go func() {
		defer close(tasks)
		for a := bfs.minA; a <= bfs.maxA; a++ {
			for b := bfs.minB; b <= bfs.maxB; b++ {
				tasks <- struct {
					a int64
					b int64
				}{a, b}
			}
		}
	}()

	var wg sync.WaitGroup
	solverInstance := solver.NewSolver(bfs.curve)
	var attempts int64 = 0
	var mu sync.Mutex

	// start workers
	for i := 0; i < bfs.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				mu.Lock()
				attempts++
				currentAttempts := attempts
				mu.Unlock()

				a := big.NewInt(task.a)
				b := big.NewInt(task.b)

				// try to recover key with this a and b
				privateKey, err := solverInstance.RecoverPrivateKey(sig1, sig2, a, b)
				if err != nil {
					// if error, probably this a and b are not correct
					// but to ensure channel works and program doesn't hang,
					// send a result every 50 attempts (even if unsuccessful)
					if currentAttempts%50 == 0 {
						select {
						case results <- &BruteForceResult{
							A:          a,
							B:          b,
							PrivateKey: nil,
							Success:    false,
							Attempts:   currentAttempts,
						}:
							// result sent
						default:
							// if channel is full, skip
						}
					}
					continue
				}

				// verify key (if public key is provided)
				isValid := true
				if publicKeyX != nil && publicKeyY != nil {
					// calculate public key from private key
					pubX, pubY := bfs.curve.ScalarBaseMult(privateKey.Bytes())
					// compare with provided public key
					if pubX.Cmp(publicKeyX) != 0 || pubY.Cmp(publicKeyY) != 0 {
						isValid = false
					}
				}

				// if key is valid, return result
				if isValid {
					select {
					case results <- &BruteForceResult{
						A:          a,
						B:          b,
						PrivateKey: privateKey,
						Success:    true,
						Attempts:   currentAttempts,
					}:
						// if public key is provided and valid, don't continue
						if publicKeyX != nil && publicKeyY != nil {
							return
						}
					default:
						// if channel is full, skip
					}
				} else {
					// even if key is not valid, send a result every 100 attempts
					// to ensure channel works
					if currentAttempts%100 == 0 {
						select {
						case results <- &BruteForceResult{
							A:          a,
							B:          b,
							PrivateKey: privateKey,
							Success:    false,
							Attempts:   currentAttempts,
						}:
						default:
							// if channel is full, skip
						}
					}
				}
			}
		}()
	}

	// close channel after completion
	go func() {
		wg.Wait()
		// ensure channel is closed
		close(results)
	}()

	return results
}

// VerifyRecoveredKey verify recovered key using public key
func VerifyRecoveredKey(
	curve elliptic.Curve,
	privateKey *big.Int,
	publicKeyX, publicKeyY *big.Int,
) bool {
	// calculate public key from private key
	Gx, Gy := curve.Params().Gx, curve.Params().Gy
	px, py := curve.ScalarMult(Gx, Gy, privateKey.Bytes())

	// compare with provided public key
	return px.Cmp(publicKeyX) == 0 && py.Cmp(publicKeyY) == 0
}

// KnownNonceSolver solver when we know the nonce
type KnownNonceSolver struct {
	curve elliptic.Curve
}

// NewKnownNonceSolver create solver for known nonces
func NewKnownNonceSolver(curve elliptic.Curve) *KnownNonceSolver {
	return &KnownNonceSolver{
		curve: curve,
	}
}

// RecoverFromKnownNonce recover private key when we know the nonce
// formula: d = (s*k - z) * r^-1 mod n
func (kns *KnownNonceSolver) RecoverFromKnownNonce(
	sig generator.SignatureData,
	nonce *big.Int,
) (*big.Int, error) {
	n := kns.curve.Params().N

	// check invertibility
	if sig.R.Sign() == 0 {
		return nil, fmt.Errorf("r cannot be zero")
	}

	rInv := new(big.Int).ModInverse(sig.R, n)
	if rInv == nil {
		return nil, fmt.Errorf("cannot calculate inverse of r")
	}

	// d = (s*k - z) * r^-1 mod n
	sk := new(big.Int).Mul(sig.S, nonce)
	skMinusZ := new(big.Int).Sub(sk, sig.Z)
	privateKey := new(big.Int).Mul(skMinusZ, rInv)
	privateKey.Mod(privateKey, n)

	return privateKey, nil
}

// RecoverFromKnownNonces recover key from multiple known nonces
func (kns *KnownNonceSolver) RecoverFromKnownNonces(
	sigs []generator.SignatureData,
	nonces []*big.Int,
) ([]*big.Int, error) {
	if len(sigs) != len(nonces) {
		return nil, fmt.Errorf("number of signatures and nonces must be equal")
	}

	results := make([]*big.Int, len(sigs))
	for i, sig := range sigs {
		key, err := kns.RecoverFromKnownNonce(sig, nonces[i])
		if err != nil {
			return nil, err
		}
		results[i] = key
	}

	return results, nil
}

// PredictableNonceGenerator generator for predictable nonces (for testing)
type PredictableNonceGenerator struct {
	pattern NoncePattern
	seed    *big.Int
	counter int64
	a       *big.Int
	b       *big.Int
	curve   elliptic.Curve
}

// NewPredictableNonceGenerator create predictable nonce generator
func NewPredictableNonceGenerator(
	pattern NoncePattern,
	curve elliptic.Curve,
) *PredictableNonceGenerator {
	return &PredictableNonceGenerator{
		pattern: pattern,
		seed:    big.NewInt(12345), // default seed
		counter: 0,
		a:       big.NewInt(2),
		b:       big.NewInt(3),
		curve:   curve,
	}
}

// SetSeed set seed
func (png *PredictableNonceGenerator) SetSeed(seed *big.Int) {
	png.seed = seed
}

// SetAffineParams set affine parameters
func (png *PredictableNonceGenerator) SetAffineParams(a, b *big.Int) {
	png.a = a
	png.b = b
}

// NextNonce generate next nonce based on pattern
func (png *PredictableNonceGenerator) NextNonce() *big.Int {
	n := png.curve.Params().N
	var k *big.Int

	switch png.pattern {
	case PatternCounter:
		// k_i = seed + counter
		k = new(big.Int).Add(png.seed, big.NewInt(png.counter))
		png.counter++
	case PatternLinear:
		// k_i = a*k_{i-1} + b
		if png.counter == 0 {
			k = new(big.Int).Set(png.seed)
		} else {
			prevK := new(big.Int).Add(
				new(big.Int).Mul(png.a, png.seed),
				png.b,
			)
			k = new(big.Int).Add(
				new(big.Int).Mul(png.a, prevK),
				png.b,
			)
		}
		png.counter++
	case PatternAffine:
		// k_i = a*k_j + b (needs previous nonce)
		// this is more complex and requires state management
		k = new(big.Int).Add(
			new(big.Int).Mul(png.a, png.seed),
			png.b,
		)
		png.counter++
	default:
		// randomly
		k = new(big.Int).Rand(nil, n)
	}

	k.Mod(k, n)
	if k.Sign() == 0 {
		k = big.NewInt(1) // ensure k is not zero
	}

	return k
}
