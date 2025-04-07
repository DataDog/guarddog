







def fibonacci(n: int) -> int:
    """
    Return the nth Fibonacci number, starting from 1.
    """
    if n < 1:
        raise ValueError("A positive integer is required")
    
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b

    return a
