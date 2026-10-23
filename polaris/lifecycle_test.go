// Verify deterministic service termination and bounded draining without waiting for directory timers.
//go:build linux && cgo

package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// TestLifecycle uses explicit completion events for each select arm and a real open RPC for forced shutdown.
func TestLifecycle(t *testing.T) {
	for _, name := range []string{"cancel", "refresh", "normal", "cancelled-refresh", "stopped", "listener", "slow"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			rpc := grpc.NewServer()
			healthy := health.NewServer()
			grpc_health_v1.RegisterHealthServer(rpc, healthy)
			healthy.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
			ctx, cancel := context.WithCancel(t.Context())
			trigger, finished := make(chan struct{}), make(chan struct{})
			failure := errors.New("Directory fixture failed")
			refresh := func(ctx context.Context) error {
				defer close(finished)
				select {
				case <-trigger:
					if name == "normal" {
						return nil
					}
					if name == "cancelled-refresh" {
						return context.Canceled
					}
					return failure
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if name == "stopped" {
				rpc.Stop()
			}
			if name == "listener" {
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			waits := 0
			done := make(chan error, 1)
			go func() { done <- serve(ctx, listener, rpc, healthy, refresh, func() { waits++ }) }()
			joined := false
			t.Cleanup(func() {
				cancel()
				rpc.Stop()
				if !joined {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("service owner did not drain")
					}
				}
			})
			if name != "stopped" && name != "listener" {
				channel, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry())
				if err != nil {
					t.Fatal(err)
				}
				defer channel.Close()
				deadline, stop := context.WithTimeout(t.Context(), 12*time.Second)
				defer stop()
				client := grpc_health_v1.NewHealthClient(channel)
				ready, err := client.Check(deadline, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
				if err != nil || ready.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
					t.Fatal("fixture service never became ready", err)
				}
				if name == "slow" {
					watch, err := client.Watch(deadline, &grpc_health_v1.HealthCheckRequest{})
					if err != nil {
						t.Fatal(err)
					}
					ready, err = watch.Recv()
					if err != nil || ready.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
						t.Fatal("long-lived RPC did not enter the admitted scope", err)
					}
					cancel()
					ready, err = watch.Recv()
					if err != nil || ready.GetStatus() != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
						t.Fatal("health admission was not withdrawn before forced shutdown", err)
					}
					_, err = watch.Recv()
					if status.Code(err) != codes.Unavailable && status.Code(err) != codes.Canceled {
						t.Fatal("grace-period expiry did not terminate the outstanding RPC", err)
					}
					if deadline.Err() != nil {
						t.Fatal("caller timeout disguised a missing forced shutdown")
					}
				} else if name == "cancel" {
					cancel()
				} else {
					close(trigger)
				}
			}
			select {
			case err := <-done:
				joined = true
				var want error
				if name == "refresh" {
					want = failure
				}
				if name == "listener" {
					want = net.ErrClosed
				}
				if !errors.Is(err, want) {
					t.Fatal("service termination changed the triggering result", err, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("service termination exceeded the bounded drain")
			}
			select {
			case <-finished:
			default:
				t.Fatal("service returned before its refresh worker exited")
			}
			if waits != 1 {
				t.Fatal("stream ownership was not joined exactly once")
			}
			ready, err := healthy.Check(t.Context(), &grpc_health_v1.HealthCheckRequest{})
			if err != nil || ready.GetStatus() != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
				t.Fatal("terminated service remained healthy", err)
			}
		})
	}
}

// TestStatus checks process exit categories without bypassing deferred signal cleanup through os.Exit.
func TestStatus(t *testing.T) {
	for _, test := range []struct {
		name string   // Native exit category.
		args []string // Explicit isolated deployment input.
		code int      // Published process exit status.
	}{
		{"help", []string{"--help"}, 0},
		{"invalid", []string{"--unknown-entry-option"}, 2},
		{"startup", []string{"--listen=127.0.0.1:9553", "--super=127.0.0.1:9554", "--galaxy=entry", "--identity=" + t.TempDir()}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual := start(test.args); actual != test.code {
				t.Fatalf("process status = %d, want %d", actual, test.code)
			}
		})
	}
}
