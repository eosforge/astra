// Exercise rejected public operations without admitting transports or role ownership.
package comet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// rejected checks stable public classification and explicit pre-submission evidence.
func rejected(t *testing.T, cause error, code comet.Code) {
	t.Helper()
	var failure *comet.Error
	if !errors.As(cause, &failure) || failure == nil || failure.Code != code || failure.Effect != comet.Unapplied {
		t.Fatalf("expected unapplied rejection %v, got %v", code, cause)
	}
}

// TestUninitializedClient cannot create owners or revive authentication.
func TestUninitializedClient(t *testing.T) {
	t.Parallel()
	scope := comet.Scope{Sector: "test", Spectrum: "closed"}
	for _, client := range []*comet.Client{nil, {}} {
		client.Close()
		client.Close()
		if cause := client.Wait(context.Background()); cause != nil || client.Panics() != 0 {
			t.Fatalf("uninitialized client acquired work: %v", cause)
		}
		rejected(t, client.Wait(nil), comet.CodeInput)
		rejected(t, client.Secret([]byte("replacement")), comet.CodeClosed)
		publisher, cause := client.Publisher(scope)
		rejected(t, cause, comet.CodeClosed)
		if publisher != nil {
			t.Fatal("closed client returned a Publisher")
		}
		beacon, cause := client.Beacon(context.Background(), scope, nil, nil, time.Second, time.Millisecond)
		rejected(t, cause, comet.CodeClosed)
		if beacon != nil {
			t.Fatal("closed client returned a Beacon")
		}
		subscriber, cause := client.Subscriber(scope)
		rejected(t, cause, comet.CodeClosed)
		if subscriber != nil {
			t.Fatal("closed client returned a Subscriber")
		}
		reader, cause := client.Reader(scope)
		rejected(t, cause, comet.CodeClosed)
		if reader != nil {
			t.Fatal("closed client returned a Reader")
		}
		observer, cause := client.Observer(scope)
		rejected(t, cause, comet.CodeClosed)
		if observer != nil {
			t.Fatal("closed client returned an Observer")
		}
		_, cause = client.SubscriberKey(scope, "key")
		rejected(t, cause, comet.CodeClosed)
		_, cause = client.ReaderKey(scope, "key")
		rejected(t, cause, comet.CodeClosed)
	}
}

// TestUninitializedRoles reject callbacks and writes while permitting idempotent cleanup.
func TestUninitializedRoles(t *testing.T) {
	t.Parallel()
	for _, publisher := range []*comet.Publisher{nil, {}} {
		publisher.Close()
		publisher.Close()
		if cause := publisher.Wait(context.Background()); cause != nil {
			t.Fatal(cause)
		}
		rejected(t, publisher.Wait(nil), comet.CodeInput)
		receipt, cause := publisher.Update(context.Background(), []comet.Entry{{Key: "key"}}, time.Second)
		rejected(t, cause, comet.CodeClosed)
		if receipt != (comet.Receipt{}) {
			t.Fatal("uninitialized Publisher invented commit evidence")
		}
	}
	for _, beacon := range []*comet.Beacon{nil, {}} {
		beacon.Destroy()
		beacon.Close()
		if cause := beacon.Wait(context.Background()); cause != nil || beacon.State().Phase != comet.Closed || beacon.State().HasIdentity {
			t.Fatalf("uninitialized Beacon acquired identity or work: %v", cause)
		}
		rejected(t, beacon.Wait(nil), comet.CodeInput)
		rejected(t, beacon.Changed(func(comet.BeaconState) { t.Error("rejected callback ran") }), comet.CodeClosed)
		rejected(t, beacon.Tick(time.Second, func() ([]byte, error) { t.Error("rejected sampler ran"); return nil, nil }), comet.CodeClosed)
		receipt, cause := beacon.Update(context.Background(), nil)
		rejected(t, cause, comet.CodeClosed)
		if receipt != (comet.BeaconReceipt{}) {
			t.Fatal("uninitialized Beacon invented update evidence")
		}
	}
	for _, observer := range []*comet.Observer{nil, {}} {
		observer.Stop()
		observer.Stop()
		if cause := observer.Wait(context.Background()); cause != nil {
			t.Fatal(cause)
		}
		rejected(t, observer.Wait(nil), comet.CodeInput)
		item, cause := observer.One(func(comet.Pool) *comet.Item { t.Error("closed selector ran"); return nil })
		rejected(t, cause, comet.CodeClosed)
		if item != nil {
			t.Fatal("uninitialized Observer returned a selection")
		}
	}
	for _, item := range []*comet.Item{nil, {}} {
		if item.ID() != "" || item.Record() != (comet.Record{}) {
			t.Fatal("empty Item invented retained data")
		}
		rejected(t, item.Update(nil), comet.CodeClosed)
	}
}

// TestUninitializedReadViews keeps absence separate from a valid empty initialized map.
func TestUninitializedReadViews(t *testing.T) {
	t.Parallel()
	readers := []interface {
		State() comet.View
		Watch(func(comet.Map)) error
		WatchKey(func(string, comet.Value, bool)) error
		Changed(func(comet.View)) error
		Stop()
		Wait(context.Context) error
	}{&comet.Subscriber{}, &comet.Reader{}}
	for _, reader := range readers {
		reader.Stop()
		reader.Stop()
		state := reader.State()
		if state.Phase != comet.Closed || state.HasVersion || state.Instance != "" || state.Data.Len() != 0 {
			t.Fatal("uninitialized read role invented a baseline")
		}
		rejected(t, reader.Watch(func(comet.Map) { t.Error("rejected callback ran") }), comet.CodeClosed)
		rejected(t, reader.WatchKey(func(string, comet.Value, bool) { t.Error("rejected callback ran") }), comet.CodeClosed)
		rejected(t, reader.Changed(func(comet.View) { t.Error("rejected callback ran") }), comet.CodeClosed)
		rejected(t, reader.Wait(nil), comet.CodeInput)
		if cause := reader.Wait(context.Background()); cause != nil {
			t.Fatal(cause)
		}
	}
	var values comet.Map
	value, present := values.Get("missing")
	if values.Len() != 0 || present || value.Len() != 0 {
		t.Fatal("zero Map contains a present value")
	}
	values.Range(func(string, comet.Value) bool { t.Error("empty Map invoked a visitor"); return true })
	var pool comet.Pool
	if pool.Len() != 0 || pool.Find("missing") != nil {
		t.Fatal("zero Pool contains an Item")
	}
	pool.Range(func(*comet.Item) bool { t.Error("empty Pool invoked a visitor"); return true })
}
