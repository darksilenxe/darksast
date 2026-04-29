package main

import "os/exec"

func main() {
	userInput := "echo test"
	exec.Command("sh", "-c", userInput)
}
