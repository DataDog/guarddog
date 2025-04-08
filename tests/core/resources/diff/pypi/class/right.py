"""
A guessing game.
"""

import random
import sys


class Game:
    def __init__(self, min=1, max=100):
        self.min = min
        self.max = max
        # Changed the name of this attribute
        self.value = random.randint(self.min, self.max)

    def play(self):
        print(f"I'm thinking of a number between {self.min} and {self.max}!")

        while True:
            try:
                guess = int(input("Enter your guess: "))
                
                if guess < self.value:
                    print("Too low!")
                elif guess > self.value:
                    print("Too high!")
                else:
                    print("You won!")
                    break
            except ValueError:
                print("Please enter a valid integer.")


def main() -> int:
    try:
        Game().play()
        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
