// Exercise the internal public parser boundary against literal CLI expectations and the native standard-library parser.
package command_test

import (
	"bytes"
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"

	"github.com/eosforge/astra/internal/command"
)

// values is the externally observable parse result; remaining argument order and accepted prefixes are significant.
type values struct {
	number  int      // Parsed signed integer, initially zero.
	enabled bool     // Parsed switch, initially false.
	name    string   // Parsed text, initially "initial"; empty remains distinct.
	args    []string // Unconsumed arguments in their original order.
	visited int      // Number of explicitly set registered flags.
	kind    string   // Success, help sentinel or rejected input.
}

// parse creates an independent caller-owned FlagSet and exposes values rather than wrapper internals.
func parse(invoke func(*flag.FlagSet, []string) error, arguments []string) (values, string, string) {
	var output bytes.Buffer
	set := flag.NewFlagSet("compatibility", flag.ContinueOnError)
	set.SetOutput(&output)
	number := set.Int("count", 0, "item count")
	enabled := set.Bool("enabled", false, "enable work")
	name := set.String("name", "initial", "item name")
	err := invoke(set, arguments)
	result := values{number: *number, enabled: *enabled, name: *name, args: append([]string(nil), set.Args()...), visited: set.NFlag(), kind: "ok"}
	message := ""
	if err != nil {
		result.kind, message = "error", err.Error()
		if errors.Is(err, flag.ErrHelp) {
			result.kind = "help"
		}
	}
	return result, output.String(), message
}

// TestCompatibility fixes the supported one-parse CLI semantics; duplicate rejection is covered by the separate full core proof.
func TestCompatibility(t *testing.T) {
	hits := 0
	check := func(ok bool, reason string) {
		t.Helper()
		if !ok {
			t.Fatal(reason)
		}
		hits++
	}
	// Literal expectations independently anchor the standard-library comparison and accepted-prefix semantics.
	cases := []struct {
		args []string // A complete nonduplicate CLI invocation, including rejected and early-stopping inputs.
		want values   // Fixed expected values, remaining arguments, visit count and result class.
	}{
		{nil, values{0, false, "initial", nil, 0, "ok"}},
		{[]string{"--count=3"}, values{3, false, "initial", nil, 1, "ok"}},
		{[]string{"-count", "3"}, values{3, false, "initial", nil, 1, "ok"}},
		{[]string{"--count=-3"}, values{-3, false, "initial", nil, 1, "ok"}},
		{[]string{"--count=0x10"}, values{16, false, "initial", nil, 1, "ok"}},
		{[]string{"--enabled"}, values{0, true, "initial", nil, 1, "ok"}},
		{[]string{"--enabled=false"}, values{0, false, "initial", nil, 1, "ok"}},
		{[]string{"-enabled=T"}, values{0, true, "initial", nil, 1, "ok"}},
		{[]string{"--name="}, values{0, false, "", nil, 1, "ok"}},
		{[]string{"--name=-x"}, values{0, false, "-x", nil, 1, "ok"}},
		{[]string{"--name=a=b"}, values{0, false, "a=b", nil, 1, "ok"}},
		{[]string{"--name=λ"}, values{0, false, "λ", nil, 1, "ok"}},
		{[]string{"--", "--enabled"}, values{0, false, "initial", []string{"--enabled"}, 0, "ok"}},
		{[]string{"pos", "--enabled"}, values{0, false, "initial", []string{"pos", "--enabled"}, 0, "ok"}},
		{[]string{"-"}, values{0, false, "initial", []string{"-"}, 0, "ok"}},
		{[]string{"-h"}, values{0, false, "initial", nil, 0, "help"}},
		{[]string{"--help"}, values{0, false, "initial", nil, 0, "help"}},
		{[]string{"--count=3", "--help"}, values{3, false, "initial", nil, 1, "help"}},
		{[]string{"--enabled", "--missing"}, values{0, true, "initial", nil, 1, "error"}},
		{[]string{"--count"}, values{0, false, "initial", nil, 0, "error"}},
		{[]string{"--count=invalid"}, values{0, false, "initial", nil, 0, "error"}},
		{[]string{"--enabled=nope"}, values{0, false, "initial", nil, 0, "error"}},
		{[]string{"--name=x", "--count=oops"}, values{0, false, "x", nil, 1, "error"}},
		{[]string{"--enabled", "false"}, values{0, true, "initial", []string{"false"}, 1, "ok"}},
		{[]string{"--", "--help"}, values{0, false, "initial", []string{"--help"}, 0, "ok"}},
	}
	check(len(cases) == 25, "compatibility domain changed without updating its independent inventory")
	// This assignment also compiles the caller-facing signature without access to once or its admission bit.
	var invoke func(*flag.FlagSet, []string) error = command.Parse
	for index, test := range cases {
		actual, output, message := parse(invoke, test.args)
		standard, _, native := parse((*flag.FlagSet).Parse, test.args)
		if !reflect.DeepEqual(standard, test.want) || !reflect.DeepEqual(actual, test.want) {
			t.Fatalf("case %d (%q): native=%+v wrapper=%+v want=%+v", index, test.args, standard, actual, test.want)
		}
		hits += 2
		check(message == native, "wrapper changed the standard parser error")
		check(!strings.Contains(output, "panic calling String"), "help invoked an invalid zero-value wrapper")
		if test.want.kind == "ok" {
			check(output == "", "successful parsing emitted a diagnostic")
		} else {
			// Formatting and optional zero-default decoration are not the CLI contract; names, descriptions and defaults are.
			for _, marker := range []string{"Usage of compatibility:", "-count", "item count", "-enabled", "enable work", "-name", "item name", "(default initial)"} {
				check(strings.Contains(output, marker), "help or rejection lost a registered flag or its default")
			}
		}
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-COMPATIBILITY","hits":%d}`, hits)
}
