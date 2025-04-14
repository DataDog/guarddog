function fibonacci(n) {
    if (n <= 1) return 0;
    if (n === 2) return 1;
  
    let prev = 0, curr = 1;
  
    for (let i = 3; i <= n; i++) {
      [prev, curr] = [curr, prev + curr];
    }
  
    return curr;
  }
