// Observe durable authority history through public Readers during owned service faults.
package comet_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// systemAuthority keeps one Reader per original Client across a Polaris crash,
// durable reopening, deletion and empty-value replacement. Only the fixture writes.
func systemAuthority(t *testing.T, settings comet.Options, nodes []systemNode, addresses []string, control string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	scope := comet.Scope{Sector: "integration", Spectrum: "main"}
	readers := make([]*comet.Reader, len(nodes))
	for index := range nodes {
		reader, cause := nodes[index].client.Reader(scope)
		if cause != nil {
			t.Fatal(cause)
		}
		nodes[index].reader.Stop()
		if cause := nodes[index].reader.Wait(ctx); cause != nil {
			t.Fatal(cause)
		}
		nodes[index].reader, readers[index] = reader, reader
	}
	// The fixture's earlier native Reader history ends with a present empty v4.
	systemAuthorityViews(t, ctx, readers, 0, 4, []byte{})
	systemEvent(t, "go_authority_ready", 0)
	systemCommand(t, ctx, control, "authority-before", 0)
	systemAuthorityViews(t, ctx, readers, 4, 5, []byte("go-before"))
	retained := make([]comet.View, len(readers))
	for index, reader := range readers {
		retained[index] = reader.State()
	}
	systemEvent(t, "go_authority_before", 0)
	systemCommand(t, ctx, control, "authority-stopped", 0)
	systemAuthorityViews(t, ctx, readers, 5, 5, []byte("go-before"))
	// A fresh authenticated Reader pinned to each physical Star must also observe
	// that Star's complete cache while the only authority process is absent.
	for _, address := range addresses {
		func() {
			settings.Endpoints = []string{strings.TrimSpace(address)}
			client, cause := comet.New(settings)
			if cause != nil {
				t.Fatal(cause)
			}
			defer func() {
				client.Close()
				drain, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if cause := client.Wait(drain); cause != nil {
					t.Errorf("authority cache probe drain: %v", cause)
				}
			}()
			reader, cause := client.Reader(scope)
			if cause != nil {
				t.Fatal(cause)
			}
			systemAuthorityViews(t, ctx, []*comet.Reader{reader}, 0, 5, []byte("go-before"))
		}()
	}
	systemEvent(t, "go_authority_cached", 0)
	systemCommand(t, ctx, control, "authority-deleted", 0)
	systemAuthorityViews(t, ctx, readers, 5, 6, nil)
	for _, view := range retained {
		value, present := view.Data.Get("key")
		if !view.HasVersion || view.Version != 5 || !present || value.String() != "go-before" {
			t.Fatal("authority replacement mutated a retained Reader snapshot")
		}
	}
	systemEvent(t, "go_authority_deleted", 0)
	systemCommand(t, ctx, control, "authority-empty", 0)
	systemAuthorityViews(t, ctx, readers, 6, 7, []byte{})
	systemEvent(t, "go_authority_empty", 0)
	systemCommand(t, ctx, control, "authority-restored", 0)
	systemAuthorityViews(t, ctx, readers, 7, 8, []byte("go-after"))
	systemEvent(t, "go_authority_restored", 0)
}

// systemAuthorityViews checks fixed version/presence/content history and rejects
// regression below an already observed floor, independently of target identity.
func systemAuthorityViews(t *testing.T, ctx context.Context, readers []*comet.Reader, floor, version uint64, data []byte) {
	t.Helper()
	systemAwait(t, ctx, "complete authority views", func() bool {
		complete := true
		for _, reader := range readers {
			view := reader.State()
			if view.HasVersion && (view.Version < floor || view.Version > version) {
				t.Fatalf("authority history escaped its prescribed version interval [%d, %d]: %d", floor, version, view.Version)
			}
			value, present := view.Data.Get("key")
			if view.Phase != comet.Ready || !view.HasVersion || view.Version != version || present != (data != nil) || value.String() != string(data) {
				complete = false
			}
			count := 0
			if data != nil {
				count = 1
			}
			if view.Data.Len() != count {
				complete = false
			}
		}
		return complete
	})
}
