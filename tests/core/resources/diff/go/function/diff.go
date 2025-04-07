







func fibonacci(n int) int {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}

	prev, curr := 0, 1
	for i := 3; i <= n; i++ {
		prev, curr = curr, prev+curr
	}

	return curr
}
