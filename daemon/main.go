//go:build go1.17
// +build go1.17

package main

import (
	"fmt"

	"tomato.com/watch-dog/daemon/cmd"

	gops "github.com/google/gops/agent"
)

func main() {
	if err := gops.Listen(gops.Options{}); err != nil {
		fmt.Printf("Unable to start gops: %s", err.Error())
		return
	}
	cmd.Execute()
}
