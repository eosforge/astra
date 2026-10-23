// Verify close linearization and sampled-update fencing with controlled local schedules.
package comet

import (
	"context"
	"crypto/tls"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// isolatedBlocked observes the actual mutex wait before allowing a closing owner to continue.
func isolatedBlocked(name string) bool {
	buffer := make([]byte, 1<<20)
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		count := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:count]), "\n\n") {
			if strings.Contains(stack, name) && strings.Contains(stack, "[sync.Mutex.Lock]") {
				return true
			}
		}
		runtime.Gosched()
	}
	return false
}

// TestIsolatedLockClosure rejects Secret and Tick after their initial check loses the owner lock.
func TestIsolatedLockClosure(t *testing.T) {
	for _, name := range []string{"secret", "tick"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("closing operation performed RPC"); return nil })
			beacon := isolatedBeacon(t, client, selected)
			client.secret = []byte("local-original")
			client.mu.Lock()
			done := make(chan error, 1)
			frame := "(*Client).Secret"
			if name == "secret" {
				go func() { done <- client.Secret([]byte("local-replacement")) }()
			} else {
				frame = "(*Client).sampleQueue"
				go func() {
					done <- beacon.Tick(time.Millisecond, func() ([]byte, error) { t.Error("closing sampler ran"); return nil, nil })
				}()
			}
			blocked := isolatedBlocked(frame)
			client.closed.Store(true)
			client.mu.Unlock()
			cause := <-done
			client.closed.Store(false)
			if !blocked {
				t.Fatal("controlled operation did not reach its owned mutex wait")
			}
			isolatedCode(t, cause, CodeClosed)
			if string(client.secret) != "local-original" || beacon.tick != nil || client.sampling != nil {
				t.Fatal("closing admission changed credentials or created sampling workers")
			}
		})
	}
}

// TestIsolatedSampleReplacement discards a result superseded during request preparation.
func TestIsolatedSampleReplacement(t *testing.T) {
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("obsolete sample performed RPC"); return nil })
	beacon := isolatedBeacon(t, client, selected)
	ticket := &sampleTicket{}
	beacon.ticket = ticket
	var calls atomic.Int32
	beacon.life.ctx = isolatedContext{Context: beacon.life.ctx, err: func() {
		if calls.Add(1) == 2 {
			beacon.mu.Lock()
			beacon.ticket = &sampleTicket{}
			beacon.mu.Unlock()
		}
	}}
	_, cause := beacon.submit(context.Background(), []byte("obsolete"), ticket)
	isolatedCode(t, cause, CodeObsolete)
	if beacon.data.String() != "confirmed" || beacon.issued != 1 || len(client.explicit) != 0 {
		t.Fatal("superseded sample consumed a send order or cached data")
	}
}

// TestIsolatedTransition preserves a pending state notification independently of content delivery.
func TestIsolatedTransition(t *testing.T) {
	client := isolatedClient(t)
	life := isolatedLife(t, client, true)
	watch := &watching{life: life, phase: Waiting, notice: &viewNotice{call: func(View) {}}}
	watch.note = &notification{queue: client.notifications, life: life, run: func() {}}
	watch.transition(Failed, localError(CodeProtocol))
	if !watch.notice.pending || watch.phase != Failed || watch.root != nil {
		t.Fatal("state failure was suppressed or fabricated a content baseline")
	}
	isolatedCode(t, watch.failure, CodeProtocol)
}

// TestIsolatedConnectionRefusal drains a rejected login without exposing its private secret copy.
func TestIsolatedConnectionRefusal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	client := &Client{trust: &tls.Config{}, changed: make(chan struct{}), secret: []byte("unit-only"),
		options: Options{Plaintext: true, Endpoints: []string{"%zz"}, Timeout: time.Second}}
	client.ctx = isolatedContext{Context: ctx, done: func() { once.Do(cancel) }}
	client.manager.Add(1)
	client.connect()
	client.manager.Wait()
	isolatedCode(t, client.blocked, CodeInput)
	if client.binding != nil {
		t.Fatal("rejected login published a connection")
	}
}
