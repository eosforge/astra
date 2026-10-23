//go:build linux && cgo

// Verify explicit connection acquisition refuses closed pools and terminated contexts without touching durable state.
package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

// TestBorrowing covers each transaction owner before SQL starts; recovery remains possible after rejected acquisition.
func TestBorrowing(t *testing.T) {
	verified := verification(t, "STORAGE-BORROWING")
	for _, owner := range []string{"write", "read", "validation"} {
		for _, fault := range []string{"closed", "cancelled", "expired"} {
			verified(t.Run(owner+"/"+fault, func(t *testing.T) {
				store, path, binding := fixture(t, Default())
				scope := Scope{"borrowing", "state"}
				requireCommit(t, store, scope, Change{Version: 1, Key: "retained", Value: []byte("durable")})
				feed, err := store.Subscribe(4096, 8)
				if err != nil {
					t.Fatal(err)
				}
				defer feed.Close()
				changed, ready := store.Changed(), feed.Ready()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wanted := ErrUnavailable
				if fault == "cancelled" {
					cancel()
					wanted = context.Canceled
				} else if fault == "expired" {
					// A deadline in the past is deterministic and requires no physical-time waiting.
					ctx, cancel = context.WithDeadline(ctx, time.Time{})
					defer cancel()
					wanted = context.DeadlineExceeded
				} else if owner == "write" {
					if err := store.writeSQL.Close(); err != nil {
						t.Fatal(err)
					}
				} else if err := store.readSQL.Close(); err != nil {
					t.Fatal(err)
				}
				entered := false
				switch owner {
				case "write":
					err = store.transaction(ctx, func(*gorm.DB) error { entered = true; return nil })
				case "read":
					_, err = store.List(ctx)
				case "validation":
					err = store.validate(ctx, binding)
				}
				if !errors.Is(err, wanted) || entered {
					t.Fatal("rejected borrow entered SQL or lost its stable error", owner, fault, err, entered)
				}
				if len(store.writer) != 0 || store.readSQL.Stats().InUse != 0 || store.writeSQL.Stats().InUse != 0 {
					t.Fatal("rejected borrow retained a writer or native connection")
				}
				if events, err := feed.Take(); err != nil || len(events) != 0 {
					t.Fatal("rejected acquisition published a receipt", err)
				}
				select {
				case <-changed:
					t.Fatal("rejected acquisition announced a store change")
				case <-ready:
					t.Fatal("rejected acquisition announced a feed change")
				default:
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				opened, err := Open(t.Context(), path, binding, Default(), false)
				if err != nil {
					t.Fatal("reopen after refused connection acquisition", err)
				}
				defer opened.Close()
				view, err := opened.Load(t.Context(), scope)
				if err != nil || view.Version != 1 || len(view.Records) != 1 || view.Records[0].Key != "retained" || string(view.Records[0].Value) != "durable" {
					t.Fatal("refused connection acquisition changed the durable record", err, view)
				}
				t.Logf("STORAGE-BORROWING owner=%s fault=%s entered=0 in_use=0 published=0 version=1 records=1", owner, fault)
			}), "connection acquisition refusal: "+owner+"/"+fault)
		}
	}
}
