// Exercise independent input pairs for the Name, Role, Valid and NewDirectory decision scopes.
package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/protobuf/proto"
)

// TestPredicates retains actual inputs and results; nil-member pairs use short-circuit masking.
func TestPredicates(t *testing.T) {
	check := counter(t, "ADMISSION-PREDICATES")
	record := func(function string, condition int, before, after any, first, second, expected bool) {
		t.Helper()
		check(first == expected, "predicate baseline changed")
		check(second != expected, "predicate boundary was ignored")
		data, err := json.Marshal(map[string]any{
			"function": function, "condition": condition,
			"before": map[string]any{"input": before, "result": first},
			"after":  map[string]any{"input": after, "result": second},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("ADMISSION-PREDICATES " + string(data))
	}
	for index, pair := range [][2]string{
		{"a", ""}, {strings.Repeat("a", 64), strings.Repeat("a", 65)},
		{"a", "`"}, {"z", "{"}, {"A", "@"}, {"Z", "["}, {"0", "/"}, {"9", ":"},
		{".", "/"}, {"_", "^"}, {"-", "/"},
	} {
		record("Name", index, pair[0], pair[1], Name(pair[0]), Name(pair[1]), true)
	}
	for index, role := range []orbit.Role{orbit.Role_ROLE_STAR, orbit.Role_ROLE_PLANET, orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		record("Role", index, int32(0), int32(role), Role(0), Role(role), false)
	}
	for condition := range 10 {
		before := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: bytes.Repeat([]byte{1}, 32), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_STAR, Group: "default"}
		after := proto.Clone(before).(*orbit.Member)
		switch condition {
		case 0:
			after = nil
		case 1:
			after.Galaxy = ""
		case 2:
			after.Group = ""
		case 3:
			after.Id = nil
		case 4:
			after.Id = bytes.Repeat([]byte{'a'}, 129)
		case 5:
			after.Id = []byte{0xff}
		case 6:
			after.Epoch = 0
		case 7:
			after.Role = 0
		case 8:
			after.Principal = bytes.Repeat([]byte{1}, 31)
		case 9:
			after.Advertise = "127.0.0.1:0"
		}
		record("Valid", condition, before, after, Valid(before), Valid(after), true)
	}
	// Each constructor pair changes one public input and one guard truth value.
	type input struct {
		Identity bool       `json:"identity"`
		Galaxy   string     `json:"galaxy"`
		Role     orbit.Role `json:"role"`
		Maximum  int        `json:"maximum"`
	}
	construct := func(value input) bool {
		t.Helper()
		var identity *Identity
		if value.Identity {
			identity = &Identity{}
		}
		directory, err := NewDirectory(identity, value.Galaxy, value.Role, value.Maximum)
		if err != nil {
			check(directory == nil && errors.Is(err, ErrIdentity), "constructor refusal published state or changed its error")
		} else {
			check(directory != nil && directory.identity == identity && directory.galaxy == value.Galaxy && directory.role == value.Role && directory.maximum == value.Maximum && len(directory.Members()) == 0, "constructor changed accepted inputs or published members")
		}
		return err == nil
	}
	for condition := range 6 {
		before := input{true, "alpha", orbit.Role_ROLE_POLARIS, 1}
		if condition == 5 {
			before.Maximum = 16384
		}
		after := before
		switch condition {
		case 0:
			after.Identity = false
		case 1:
			after.Galaxy = ""
		case 2:
			after.Role = 0
		case 3:
			after.Role = orbit.Role_ROLE_PLANET
		case 4:
			after.Maximum = 0
		case 5:
			after.Maximum = 16385
		}
		record("NewDirectory", condition, before, after, construct(before), construct(after), true)
	}
}
