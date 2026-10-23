// Verify rare session-token collisions with finite entropy and unchanged production admission rules.
package web

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"testing"
	"time"
)

// entropy provides finite public collision bytes and observes whether generation holds the session lock.
type entropy struct {
	input *bytes.Reader // Exact public token bytes; exhaustion fails instead of generating extra samples.
	state *sessions     // Session owner whose ordinary operations must remain unblocked.
	free  bool          // False if any randomness request observed the session lock held.
	calls int           // Number of entropy requests, independent of implementation attempt counters.
}

// Read uses a nonblocking lock observation so a locking regression cannot hang the fixture.
func (source *entropy) Read(data []byte) (int, error) {
	source.calls++
	if source.state.mutex.TryLock() {
		source.state.mutex.Unlock()
	} else {
		source.free = false
	}
	return source.input.Read(data)
}

// TestSessionCollision fixes rare token collisions without changing the production random source or retry policy.
// These cases are serial because crypto/rand.Reader is process-global; no background fixture owns it.
func TestSessionCollision(t *testing.T) {
	for _, name := range []string{"retry", "exhausted"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			now := time.Unix(100000, 0)
			expire := now.Add(time.Hour)
			old := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			other := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
			fresh := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
			state := sessions{values: map[string]time.Time{old: expire, other: expire}, maximum: 2}
			before := maps.Clone(state.values)
			attempts := 2
			if name == "exhausted" {
				attempts = 4
			}
			data := append(bytes.Repeat([]byte{1}, 32*attempts), bytes.Repeat([]byte{3}, 32)...)
			source := entropy{input: bytes.NewReader(data), state: &state, free: true}
			original := rand.Reader
			rand.Reader = &source
			defer func() { rand.Reader = original }()
			token, until, ok := state.create(now, old)
			if name == "exhausted" {
				check(!ok && token == "" && until.IsZero(), "exhausted entropy published a successful session")
				check(source.calls == 4 && source.input.Len() == 32, "collision refusal exceeded or shortened its four-attempt budget")
				check(maps.Equal(state.values, before), "collision refusal revoked or changed a live session")
				observed, valid := state.get(old, now)
				check(valid && observed.Equal(expire), "refused replacement invalidated its original cookie")
				token, until, ok = state.create(now, old)
			}
			check(ok && token == fresh && until.Equal(now.Add(8*time.Hour)), "collision recovery did not install the exact fresh session")
			check(source.calls == attempts+1 && source.input.Len() == 0, "successful replacement consumed unexpected entropy")
			check(maps.Equal(state.values, map[string]time.Time{other: expire, fresh: now.Add(8 * time.Hour)}), "replacement changed another browser or retained the old token")
			check(source.free, "randomness was acquired while holding the session lock")
			_, valid := state.get(old, now)
			check(!valid, "replaced cookie remained authorized")
		})
	}
}
