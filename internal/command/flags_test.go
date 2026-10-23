// Verify shared command-line parsing and option validation boundaries.

package command

import (
	"errors"
	"flag"
	"io"
	"testing"
)

// TestParse preserves standard boolean/help behavior while rejecting silent duplicate overrides.
func TestParse(t *testing.T) {
	for _, test := range []struct {
		args []string
		bad  bool
	}{
		{[]string{"--port=1", "--enabled"}, false},
		{[]string{"--port", "1", "--enabled=false"}, false},
		{[]string{"--port=1", "--port=2"}, true},
		{[]string{"--enabled", "--enabled=false"}, true},
		{[]string{"--absent=1"}, true},
	} {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		flags.Int("port", 0, "test port")
		flags.Bool("enabled", false, "test switch")
		if err := Parse(flags, test.args); (err != nil) != test.bad {
			t.Fatalf("parse %v: unexpected result", test.args)
		}
	}
	flags := flag.NewFlagSet("help", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Bool("enabled", false, "test switch")
	flags.String("name", "value", "test text")
	if !errors.Is(Parse(flags, []string{"--help"}), flag.ErrHelp) {
		t.Fatal("standard help lost")
	}
}
