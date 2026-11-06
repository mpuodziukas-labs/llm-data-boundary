// Command pdp reads one JSON request on standard input and prints the decision as JSON.
//
//	pdp --registry REGISTRY.json [--now YYYY-MM-DD] < REQUEST.json
//
// Exit code: 0 allow or redact, 1 deny, 2 bad input (message on standard error).
// Unlike boundary.py it keeps no evidence log; it is the decision point only.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mpuodziukas-labs/llm-data-boundary/go/pdp"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pdp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registry := fs.String("registry", "", "provider registry JSON file (required)")
	now := fs.String("now", "", "override today, YYYY-MM-DD (default: UTC today)")
	if err := fs.Parse(args); err != nil || *registry == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: pdp --registry REGISTRY.json [--now YYYY-MM-DD] < REQUEST.json")
		return 2
	}
	if *now == "" {
		*now = time.Now().UTC().Format("2006-01-02")
	}
	req, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "bad input: %v\n", err)
		return 2
	}
	reg, err := os.ReadFile(*registry)
	if err != nil {
		fmt.Fprintf(stderr, "bad input: %v\n", err)
		return 2
	}
	d, code, err := pdp.Evaluate(req, reg, *now)
	if err != nil {
		fmt.Fprintf(stderr, "bad input: %v\n", err)
		return 2
	}
	fmt.Fprintln(stdout, d.CLIJSON())
	return code
}
