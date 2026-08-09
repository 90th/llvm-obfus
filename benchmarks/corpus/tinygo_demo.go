package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

//go:export tinygo_protected_value
//go:noinline
func tinygoProtectedValue(seed uint64) uint64 {
	secret := []byte("tinygo-bench-visible-secret")
	state := seed*17 + 9
	for i, b := range secret {
		shift := uint((i & 7) * 8)
		lane := (uint64(b) << shift) ^ (uint64(i+3) * 0x1f3)
		if ((state ^ lane) & 1) == 0 {
			state = ((state << 7) | (state >> (64 - 7))) + lane
		} else {
			state = ((state >> 5) | (state << (64 - 5))) ^ (lane * 13)
		}
	}
	return state ^ 0x243f6a8885a308d3
}

func foldValue(value uint64) uint64 {
	return ((value << 11) | (value >> (64 - 11))) ^ 0x5a5aa5a5c3c33c3c
}

func benchIters() uint64 {
	text, ok := os.LookupEnv("OBF_BENCH_ITERS")
	if !ok || text == "" {
		return 0
	}
	count, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0
	}
	return count
}

func runOnce(seed uint64) uint64 {
	return foldValue(tinygoProtectedValue(seed))
}

func main() {
	iters := benchIters()
	if iters > 0 {
		var sink uint64
		for i := uint64(0); i < 2048; i++ {
			sink ^= runOnce(19 + i*5)
		}

		start := time.Now()
		for i := uint64(0); i < iters; i++ {
			sink ^= runOnce(19 + i*5)
		}
		elapsed := uint64(time.Since(start).Nanoseconds())
		fmt.Printf("BENCH tinygo_demo ns/op=%d sink=%d\n", elapsed/iters, sink)
		return
	}

	fmt.Printf("tinygo=%d\n", runOnce(19))
}
