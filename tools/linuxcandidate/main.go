// linuxcandidate exercises local candidate updates without enabling production
// Linux updates or launching a target. It never downloads or publishes assets.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/selfupdate"
)

func main() {
	dist := flag.String("dist", "", "absolute local candidate directory")
	version := flag.String("version", "", "pinned candidate version")
	current := flag.String("current", "", "installed version")
	executable := flag.String("executable", "", "absolute installed acs path")
	flag.Parse()
	if *dist == "" || *version == "" || *current == "" || *executable == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: linuxcandidate --dist <directory> --version <version> --current <version> --executable <acs>")
		os.Exit(2)
	}
	_, err := selfupdate.Run(context.Background(), *current, *version, false, selfupdate.Config{
		CandidateDirectory: *dist, Executable: *executable,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "candidate update failed: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
	fmt.Println("Local Linux candidate updated; production launches remain disabled.")
}
