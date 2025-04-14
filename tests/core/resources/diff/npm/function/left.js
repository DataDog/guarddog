function fibonacci(n) {
    if (n <= 0) return 0;
    if (n === 1) return 1;
  
    let prev = 0, curr = 1;
  
    for (let i = 2; i <= n; i++) {
      [prev, curr] = [curr, prev + curr];
    }
  
    return curr;
  }
  
function main() {
    const args = process.argv.slice(2);
    if (args.length !== 1) {
      console.error('Usage: fib n');
      process.exit(1);
    }
  
    const n = parseInt(args[0], 10);
    if (isNaN(n) || n < 0) {
      console.error('Error: a non-negative index is required');
      process.exit(1);
    }

    const result = fibonacci(n)
    console.log(`${result}`);
  }
  
  main();
