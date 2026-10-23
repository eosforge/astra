// Verify duplicate-option and native flag behavior with actual, counted boundary assertions.
package command

import (
	"errors"
	"flag"
	"io"
	"testing"
)

// TestVerification anchors wrapper behavior to the standard flag contract, including rejected underlying writes.
func TestVerification(t *testing.T) {
	hits := 0
	check := func(condition bool) {
		t.Helper()
		if !condition {
			t.Fatal("command contract violated")
		}
		hits++
	}
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-BOUNDARY","hits":%d}`, hits) })
	check((&once{}).String() == "")
	for _, arguments := range [][]string{{"--value=3"}, {"--value=3", "--value=4"}, {"--value=wrong"}, {"--enabled"}, {"--enabled=false"}, {"--help"}} {
		set := flag.NewFlagSet("contract", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		value := set.Int("value", 0, "value")
		enabled := set.Bool("enabled", false, "enabled")
		err := Parse(set, arguments)
		switch arguments[0] {
		case "--value=3":
			check((err != nil) == (len(arguments) > 1))
			check(*value == 3)
		case "--value=wrong":
			check(err != nil && *value == 0)
		case "--enabled":
			check(err == nil && *enabled)
		case "--enabled=false":
			check(err == nil && !*enabled)
		case "--help":
			check(errors.Is(err, flag.ErrHelp))
		}
		check(set.Lookup("value").Value.String() != "")
		check(!set.Lookup("value").Value.(*once).IsBoolFlag())
		check(set.Lookup("enabled").Value.(*once).IsBoolFlag())
	}
	set := flag.NewFlagSet("failed-write", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Int("value", 0, "value")
	check(Parse(set, []string{"--value=wrong"}) != nil)
	check(set.Set("value", "4") != nil)
}
