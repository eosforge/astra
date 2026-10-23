// Verify each semantic member-equality condition with an independent opposite-outcome input pair.
package admission

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/protobuf/proto"
)

// TestSame changes exactly one nullable operand or identity field per pair; the source-bound interpreter checks all nine.
func TestSame(t *testing.T) {
	check := counter(t, "ADMISSION-SAME")
	for condition := range 9 {
		a := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: bytes.Repeat([]byte{1}, 32), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_STAR, Group: "default"}
		b := proto.Clone(a).(*orbit.Member)
		before := map[string]any{"a": proto.Clone(a), "b": proto.Clone(b), "result": same(a, b)}
		check(before["result"] == true, "equal independent member copies were rejected")
		switch condition {
		case 0:
			a = nil
		case 1:
			b = nil
		case 2:
			b.Galaxy = "beta"
		case 3:
			b.Id = []byte("other")
		case 4:
			b.Principal[0] = 2
		case 5:
			b.Advertise = "127.0.0.1:7444"
		case 6:
			b.Epoch = 2
		case 7:
			b.Role = orbit.Role_ROLE_POLARIS
		case 8:
			b.Group = "other"
		}
		after := map[string]any{"a": a, "b": b, "result": same(a, b)}
		check(after["result"] == false, "changed identity condition was ignored")
		data, err := json.Marshal(map[string]any{"case": condition, "before": before, "after": after})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("ADMISSION-SAME " + string(data))
	}
}
