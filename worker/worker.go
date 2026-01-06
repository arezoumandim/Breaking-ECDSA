package worker

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"slippage/config"
	"slippage/generator"
	"slippage/solver"
)

// Result result of a task including generated data and recovered key
type Result struct {
	Data         *generator.GeneratedData
	RecoveredKey *big.Int
	Error        error
	Index        int
	Success      bool
}

// WorkerPool worker pool for parallel processing
type WorkerPool struct {
	config       *config.Config
	numWorkers   int
	results      chan *Result
	wg           sync.WaitGroup
	mu           sync.Mutex
	successCount int
	totalCount   int
}

// NewWorkerPool create a new worker pool
func NewWorkerPool(cfg *config.Config, numWorkers int) *WorkerPool {
	return &WorkerPool{
		config:     cfg,
		numWorkers: numWorkers,
		results:    make(chan *Result, numWorkers*2), // buffer for results
	}
}

// GenerateAndSolve generate data and solve in parallel
func (wp *WorkerPool) GenerateAndSolve(numTasks int) <-chan *Result {
	// create channel for tasks
	tasks := make(chan int, numTasks)

	// start workers
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(tasks)
	}

	// send tasks
	go func() {
		defer close(tasks)
		for i := 0; i < numTasks; i++ {
			tasks <- i
		}
	}()

	// close results channel after all tasks complete
	go func() {
		wp.wg.Wait()
		close(wp.results)
	}()

	return wp.results
}

// worker worker that generates data and solves
func (wp *WorkerPool) worker(tasks <-chan int) {
	defer wp.wg.Done()

	solverInstance := solver.NewSolver(wp.config.Curve)

	for taskIndex := range tasks {
		// generate data
		data, err := generator.GenerateSampleData(wp.config)
		if err != nil {
			wp.results <- &Result{
				Index: taskIndex,
				Error: err,
			}
			wp.incrementTotal()
			continue
		}

		// solve
		recoveredKey, err := solverInstance.Solve(data)
		if err != nil {
			wp.results <- &Result{
				Index: taskIndex,
				Data:  data,
				Error: err,
			}
			wp.incrementTotal()
			continue
		}

		// verify
		success := solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey)

		wp.results <- &Result{
			Index:        taskIndex,
			Data:         data,
			RecoveredKey: recoveredKey,
			Success:      success,
		}

		if success {
			wp.incrementSuccess()
		}
		wp.incrementTotal()
	}
}

// incrementSuccess increment success count (thread-safe)
func (wp *WorkerPool) incrementSuccess() {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.successCount++
}

// incrementTotal increment total count (thread-safe)
func (wp *WorkerPool) incrementTotal() {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.totalCount++
}

// GetStats get statistics
func (wp *WorkerPool) GetStats() (success, total int) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return wp.successCount, wp.totalCount
}

// BatchGenerator batch data generator
type BatchGenerator struct {
	config     *config.Config
	numWorkers int
}

// NewBatchGenerator create a new batch generator
func NewBatchGenerator(cfg *config.Config, numWorkers int) *BatchGenerator {
	return &BatchGenerator{
		config:     cfg,
		numWorkers: numWorkers,
	}
}

// GenerateBatch generate batch data in parallel
func (bg *BatchGenerator) GenerateBatch(count int) <-chan *generator.GeneratedData {
	results := make(chan *generator.GeneratedData, bg.numWorkers*2)
	var wg sync.WaitGroup

	// create workers
	for i := 0; i < bg.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < count/bg.numWorkers+1; j++ {
				data, err := generator.GenerateSampleData(bg.config)
				if err != nil {
					continue
				}
				select {
				case results <- data:
				default:
					return
				}
			}
		}()
	}

	// close channel after completion
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// ParallelSolver parallel solver
type ParallelSolver struct {
	curve      elliptic.Curve
	numWorkers int
}

// NewParallelSolver create a new parallel solver
func NewParallelSolver(curve elliptic.Curve, numWorkers int) *ParallelSolver {
	return &ParallelSolver{
		curve:      curve,
		numWorkers: numWorkers,
	}
}

// SolveBatch solve batch data in parallel
func (ps *ParallelSolver) SolveBatch(dataChan <-chan *generator.GeneratedData) <-chan *Result {
	results := make(chan *Result, ps.numWorkers*2)
	var wg sync.WaitGroup

	solverInstance := solver.NewSolver(ps.curve)

	// create workers
	for i := 0; i < ps.numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			index := 0
			for data := range dataChan {
				recoveredKey, err := solverInstance.Solve(data)
				if err != nil {
					results <- &Result{
						Index: index,
						Data:  data,
						Error: err,
					}
					index++
					continue
				}

				success := solverInstance.VerifyPrivateKey(recoveredKey, data.KeyPair.PrivateKey)
				results <- &Result{
					Index:        index,
					Data:         data,
					RecoveredKey: recoveredKey,
					Success:      success,
				}
				index++
			}
		}(i)
	}

	// close channel after completion
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

