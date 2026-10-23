// Verify factory cancellation and invalid endpoint rejection before any service is contacted.
package comet

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"
)

// TestIsolatedFactoryClosure closes the newly admitted role while readiness observes its binding.
func TestIsolatedFactoryClosure(t *testing.T) {
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("closed factory performed RPC"); return nil })
	var once sync.Once
	var captured *lifecycle
	selected.ctx = isolatedContext{Context: selected.ctx, err: func() {
		once.Do(func() {
			for life := range client.actors {
				captured = life
				life.stop()
			}
			selected.cancel()
		})
	}}
	beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("initial"), time.Second, 100*time.Millisecond)
	isolatedCode(t, cause, CodeClosed)
	if beacon != nil || captured == nil {
		t.Fatal("closed construction returned a handle or lost its owned role")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if cause := waitDone(ctx, captured.done); cause != nil {
		t.Fatal(cause)
	}
	if client.used.Load() != 0 {
		t.Fatal("closed construction retained registration storage")
	}
}

// TestIsolatedTransportRefusal rejects an unparseable endpoint without creating a connection.
func TestIsolatedTransportRefusal(t *testing.T) {
	client := isolatedClient(t)
	client.trust = &tls.Config{}
	client.options.Plaintext = true
	selected, stream, cause := client.login("%zz", nil)
	isolatedCode(t, cause, CodeInput)
	if selected != nil || stream != nil {
		t.Fatal("malformed transport target returned a connection")
	}
}
