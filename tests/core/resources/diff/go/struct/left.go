package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

type Game struct {
	min   int
	max   int
	target int
}

func NewGame(min, max int) *Game {
	rand.Seed(time.Now().UnixNano())
	return &Game{
		min:   min,
		max:   max,
		target: rand.Intn(max-min+1) + min,
	}
}

func (g *Game) Play() {
	fmt.Printf("I'm thinking of a number between %d and %d!\n", g.min, g.max)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter your guess: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		guess, err := strconv.Atoi(input)

		if err != nil {
			fmt.Println("Please enter a valid integer.")
			continue
		}

		if guess < g.target {
			fmt.Println("Too low!")
		} else if guess > g.target {
			fmt.Println("Too high!")
		} else {
			fmt.Println("You won!")
			break
		}
	}
}

func main() {
	game := NewGame(1, 100)
	game.Play()
}
