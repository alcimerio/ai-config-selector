package main

import (
	"encoding/json"
	"fmt"
	"os"
)

var first, second string

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--print" {
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"first": first, "second": second}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
