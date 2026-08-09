package main

//go:export protected_value
//go:noinline
func protectedValue(x uint64) uint64 {
	return (x * 17) ^ (x + 29)
}

func main() {
	println(protectedValue(41))
}
