package main

import (
	"fmt"
	"os"
	"strconv"
)

func fibonacci(n int) int {
	if n <= 0 {
		return 0
	}
	if n == 1 {
		return 1
	}

	prev, curr := 0, 1
	for i := 2; i <= n; i++ {
		prev, curr = curr, prev+curr
	}

	return curr
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: fib n")
		os.Exit(1)
	}

	n, err := strconv.Atoi(os.Args[1])
	if err != nil || n < 0 {
		fmt.Println("Error: a non-negative integer is required.")
		os.Exit(1)
	}

	result := fibonacci(n)
	fmt.Printf("%d\n", result)
}
