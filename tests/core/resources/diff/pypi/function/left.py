"""
A program to generate Fibonacci numbers.
"""

from argparse import ArgumentParser
import sys


def fibonacci(n: int) -> int:
    """
    Return the nth Fibonacci number, starting from 0.
    """
    if n < 0:
        raise ValueError("A non-negative integer is required")
    
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b

    return a


def cli() -> ArgumentParser:
    parser = ArgumentParser(
        prog="fib.py",
        description="A program to generate Fibonacci numbers"
    )

    parser.add_argument("n", type=int, metavar="N")

    return parser


def main() -> int:
    try:
        args = cli().parse_args()

        print(f"{fibonacci(args.n)}")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
