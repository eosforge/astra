// Package command preserves standard flag behavior while rejecting duplicate deployment-option assignments.
package command

import (
	"errors"
	"flag"
)

type once struct {
	flag.Value
	set bool
}

// String returns the wrapped flag text, or an empty string for a zero value used by flag help.
func (value *once) String() string {
	if value.Value == nil {
		return "" // flag help constructs zero values by reflection; never call String on a nil embedded interface.
	}
	return value.Value.String()
}

// Set forwards the first assignment attempt and rejects every later attempt, including after an initial parse error.
func (value *once) Set(text string) error {
	if value.set {
		return errors.New("duplicate option")
	}
	value.set = true
	return value.Value.Set(text)
}

// IsBoolFlag reports whether the wrapped value accepts a valueless boolean option.
func (value *once) IsBoolFlag() bool {
	boolean, ok := value.Value.(interface{ IsBoolFlag() bool })
	return ok && boolean.IsBoolFlag()
}

// Parse wraps registered options before parsing; each FlagSet is parsed once.
func Parse(flags *flag.FlagSet, arguments []string) error {
	flags.VisitAll(func(option *flag.Flag) { option.Value = &once{Value: option.Value} })
	return flags.Parse(arguments)
}
