// Verify immutable authority pages, shared snapshot budgets and credential validation.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// fixture owns its authority database until all borrowers exit and never touches deployment files.
func fixture(t *testing.T, limits storage.Limits) *storage.Store {
	t.Helper()
	store, err := storage.Open(t.Context(), filepath.Join(t.TempDir(), "polaris.db"), storage.Binding{Galaxy: "alpha", Username: "polaris", Advertise: "127.0.0.1:7445"}, limits, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

// TestPages covers empty baseline, zero-byte/large values, final-page positions, and send failure without a full encoding prepass.
func TestPages(t *testing.T) {
	t.Parallel()
	for _, count := range []int{0, 1, 100} {
		snapshot := storage.Snapshot{Position: storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: "p"}, Version: 9}}
		for index := range count {
			value := make([]byte, 8192)
			if index == 0 {
				value = nil
			}
			if index == 1 {
				value = make([]byte, 1<<20)
			}
			snapshot.Records = append(snapshot.Records, storage.Record{Key: fmt.Sprintf("k%04d", index), Value: value})
		}
		var received []*polaris.Snapshot
		if err := pages(&snapshot, 8<<20, func(page *polaris.Snapshot) error {
			received = append(received, proto.Clone(page).(*polaris.Snapshot))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		seen := 0
		for index, page := range received {
			last := index == len(received)-1
			if page.Complete != last || page.Version == nil || page.GetVersion() != 9 || string(page.Scope.Sector) != "s" || string(page.Scope.Spectrum) != "p" {
				t.Fatal("invalid snapshot completion boundary")
			}
			for _, entry := range page.Entries {
				if entry.Key != snapshot.Records[seen].Key {
					t.Fatal("snapshot reordered keys")
				}
				if _, ok := entry.Action.(*comet.AlmanacChange_Value); !ok {
					t.Fatal("zero byte value lost action presence")
				}
				seen++
			}
		}
		if seen != count || len(received) == 0 {
			t.Fatal("snapshot incomplete")
		}
		failure := errors.New("owned send failure")
		if err := pages(&snapshot, 8<<20, func(*polaris.Snapshot) error { return failure }); !errors.Is(err, failure) {
			t.Fatal("send failure swallowed")
		}
	}
}

// TestSmallPages charges complete Packet encoding against negotiated capacity; the default target cannot bypass small frames.
func TestSmallPages(t *testing.T) {
	t.Parallel()
	snapshot := storage.Snapshot{Position: storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: "p"}, Version: 1}}
	for index := range 20 {
		snapshot.Records = append(snapshot.Records, storage.Record{Key: fmt.Sprintf("k%02d", index), Value: make([]byte, 400)})
	}
	pagesSeen, recordsSeen, completions := 0, 0, 0
	if err := pages(&snapshot, 1024, func(page *polaris.Snapshot) error {
		if proto.Size(&polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: page}}) > 1024 {
			t.Fatal("negotiated frame limit exceeded")
		}
		pagesSeen++
		recordsSeen += len(page.Entries)
		if page.Complete {
			completions++
		}
		return nil
	}); err != nil || pagesSeen < 2 || recordsSeen != 20 || completions != 1 {
		t.Fatal("small frame snapshot incomplete", err, pagesSeen, recordsSeen, completions)
	}
	snapshot.Records[0].Value = make([]byte, 1024)
	if err := pages(&snapshot, 1024, func(*polaris.Snapshot) error {
		t.Fatal("oversized first record was sent")
		return nil
	}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("oversized single record did not fail explicitly", err)
	}
}

// TestCache shares pinned targets, preserves frozen versions and releases each reader's ownership once.
func TestCache(t *testing.T) {
	t.Parallel()
	store := fixture(t, storage.Default())
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	if _, err := store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "k", Value: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	cache := newCache(store, store.Limits(), 256<<20)
	a, err := cache.acquire(t.Context(), scope, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	b, err := cache.acquire(t.Context(), scope, 1)
	if err != nil || a.Snapshot != b.Snapshot {
		t.Fatal("identical active target was not shared", err)
	}
	defer b.release()
	if _, err := store.Commit(t.Context(), scope, storage.Change{Version: 2, Key: "k", Value: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	c, err := cache.acquire(t.Context(), scope, 2)
	if err != nil || c.Snapshot.Version != 2 || a.Snapshot.Version != 1 || a.Snapshot.Records[0].Value[0] != 1 {
		t.Fatal("new snapshot changed pinned old content", err)
	}
	c.release()
	a.release()
	a.release()
	if cache.used != cache.reserve || len(cache.entries) != 1 || cache.entries[position{Scope: scope, version: 1}] != b.entry || b.entry.references != 1 || b.Snapshot.Version != 1 || b.Snapshot.Records[0].Value[0] != 1 {
		t.Fatal("repeated release changed another reader's ownership or content")
	}
	b.release()
	b.release()
	c.release()
	if a.entry.references != 0 || b.entry.references != 0 || c.entry.references != 0 {
		t.Fatal("repeated release changed retired reference counts")
	}
	if cache.used != 0 || len(cache.entries) != 0 {
		t.Fatal("unreferenced snapshot retained budget")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if pin, err := cache.acquire(ctx, scope, 2); err == nil {
		pin.release()
		t.Fatal("cancelled preparation succeeded")
	}
	if cache.used != 0 {
		t.Fatal("failed preparation leaked budget")
	}
}

// TestCredentialValidation leaves ordinary values opaque while rejecting empty SECRET, malformed credentials, and oversized APIKEY.
func TestCredentialValidation(t *testing.T) {
	t.Parallel()
	scope := storage.Scope{Sector: "__auth", Spectrum: "comet"}
	valid, err := proto.Marshal(&orbit.Credential{Secret: []byte{0, 1, 255}})
	if err != nil {
		t.Fatal(err)
	}
	if !credential(scope, storage.Change{Key: "key", Value: valid}) || !credential(scope, storage.Change{Key: "key", Erase: true}) {
		t.Fatal("valid opaque credential rejected")
	}
	for _, change := range []storage.Change{{Key: "key"}, {Key: "key", Value: []byte{255}}, {Key: "", Value: valid}, {Key: "a\x00b", Erase: true}, {Key: string(make([]byte, 129)), Value: valid}} {
		if credential(scope, change) {
			t.Fatal("invalid internal credential accepted")
		}
	}
	if !credential(storage.Scope{Sector: "business", Spectrum: "comet"}, storage.Change{Key: "key", Value: []byte{255}}) {
		t.Fatal("ordinary content interpreted as credential")
	}
}

// TestCredentialBounds distinguishes the internal namespace, text validity and encoded size from secret size.
func TestCredentialBounds(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"other-spectrum", "invalid-utf8", "maximum", "above"} {
		t.Run(name, func(t *testing.T) {
			scope := storage.Scope{Sector: "__auth", Spectrum: "comet"}
			value := &orbit.Credential{Secret: []byte{1}}
			// A legal unknown field pads the whole message while leaving its one-byte secret unchanged.
			padding := 8185
			if name == "above" {
				padding++
			}
			value.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 100, protowire.BytesType), make([]byte, padding)))
			encoded, err := proto.Marshal(value)
			if err != nil || len(encoded) != padding+7 {
				t.Fatal("credential fixture does not exercise the exact encoded-size boundary", err)
			}
			change := storage.Change{Key: "key", Value: encoded}
			if name == "other-spectrum" {
				scope.Spectrum = "other"
				change = storage.Change{Key: "", Value: []byte{255}}
			} else if name == "invalid-utf8" {
				change.Key = "\xff"
			}
			want := name == "other-spectrum" || name == "maximum"
			if credential(scope, change) != want {
				t.Fatal("credential validation confused namespace, UTF-8 or complete encoded size")
			}
		})
	}
}
