// Verify admitted backend connectivity and management request forwarding.

package bridge

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// TestObservation checks directory projections and retained observations independently of live admission or Polaris RPC acceptance.
func TestObservation(t *testing.T) {
	member := &orbit.Member{Id: []byte("node"), Role: orbit.Role_ROLE_STAR, Galaxy: "test", Group: "region", Advertise: "127.0.0.1:4000", Epoch: math.MaxUint64, Principal: bytes.Repeat([]byte{0x61}, 32)}
	backend := &Backend{nodes: []node{describe(member)}, observed: time.Now()}
	old := backend.Nodes()
	member.Id = []byte("changed") // Capture field values rather than retaining a mutable Protobuf pointer.
	backend.mutex.Lock()
	backend.nodes = []node{describe(member)}
	backend.stale = true
	backend.mutex.Unlock()
	before, err := json.Marshal(old)
	if err != nil || !strings.Contains(string(before), `"id":"node"`) || !strings.Contains(string(before), `"epoch":"18446744073709551615"`) || !strings.Contains(string(before), `"stale":false`) || strings.Contains(string(before), "principal") {
		t.Fatal("old observation changed or exposed private identity")
	}
	after, err := json.Marshal(backend.Nodes())
	if err != nil || !strings.Contains(string(after), `"id":"changed"`) || !strings.Contains(string(after), `"stale":true`) {
		t.Fatal("new observation not published")
	}
	backend = &Backend{}
	empty, err := json.Marshal(backend.Nodes())
	if err != nil || !strings.Contains(string(empty), `"nodes":[]`) || !strings.Contains(string(empty), `"stale":true`) {
		t.Fatal("unobserved directory claimed freshness")
	}
}
