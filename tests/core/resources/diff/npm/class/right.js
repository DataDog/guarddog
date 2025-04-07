/**
 * A guessing game.
 */

const readline = require('readline');

class Game {
  constructor(min = 1, max = 100) {
    this.min = min;
    this.max = max;
    // Rename this attribute
    this.value = this.getRandomInt(this.min, this.max);
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
  }

  getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  async askQuestion(query) {
    return new Promise((resolve) => {
      this.rl.question(query, resolve);
    });
  }

  async play() {
    console.log(`I'm thinking of a number between ${this.min} and ${this.max}!`);

    while (true) {
      try {
        const input = await this.askQuestion('Enter your guess: ');
        const guess = parseInt(input, 10);

        if (isNaN(guess)) {
          console.log('Please enter a valid integer.');
        } else if (guess < this.value) {
          console.log('Too low!');
        } else if (guess > this.value) {
          console.log('Too high!');
        } else {
          console.log('You won!');
          break;
        }
      } catch (error) {
        console.error(`Error: ${error.message}`);
        break;
      }
    }

    this.rl.close();
  }
}

(async () => {
  try {
    const game = new Game();
    await game.play();
  } catch (error) {
    console.error(`Failed to start the game: ${error.message}`);
    process.exit(1);
  }
})();
