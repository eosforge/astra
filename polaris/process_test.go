// Verify real process signals against the production entry with isolated TLS admission and durable state.
//go:build linux && cgo

package main

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestProcess enters main only in an owned child; signals never target the test runner or another service.
func TestProcess(t *testing.T) {
	process(t, true)
}

// TestStart lets the native test harness retain startup coverage and traces after the signal owner returns.
func TestStart(t *testing.T) {
	process(t, false)
}

// process isolates production signal handling; only a normal harness return may emit child diagnostics.
func process(t *testing.T, exit bool) {
	t.Helper()
	if os.Getenv("ASTRA_POLARIS_ENTRY") == "child" {
		for index, argument := range os.Args {
			if argument == "--" {
				if exit {
					os.Args = append([]string{"polaris"}, os.Args[index+1:]...)
					main()
				} else if code := start(os.Args[index+1:]); code != 0 {
					t.Fatalf("cancelled entry status = %d, want 0", code)
				}
				return
			}
		}
		t.Fatal("entry child lacks its explicit deployment arguments")
	}
	name := t.Name()
	for _, test := range []struct {
		name   string         // Lifecycle point and stable native case identity.
		signal syscall.Signal // Signal sent only to the owned child.
	}{
		{"terminated", syscall.SIGTERM},
		{"interrupt", syscall.SIGINT},
		{"admission", syscall.SIGTERM},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			endpoint := listener.Addr().String()
			config := options{listen: endpoint, advertise: endpoint, galaxy: "entry", group: "default", identity: filepath.Join("..", "tests", "fixtures", "star-a"), state: filepath.Join(t.TempDir(), "authority.db"), snapshots: 256 << 20}
			identity, err := admission.Load(config.identity, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			entered, exited := make(chan struct{}), make(chan struct{})
			var settings []grpc.ServerOption
			if test.name == "admission" {
				settings = append(settings, grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
					close(entered)
					defer close(exited)
					<-ctx.Done()
					return nil, status.FromContextError(ctx.Err()).Err()
				}))
			}
			service := launch(t, &config, identity, false, settings...)
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			// Returning through the child harness retains diagnostics; main still owns its actual process exit.
			arguments := []string{"-test.run=^" + name + "$", "-test.v"}
			profile := ""
			if !exit && testing.CoverMode() != "" {
				profile = filepath.Join(t.TempDir(), "entry.profile")
				arguments = append(arguments, "-test.coverprofile="+profile)
			}
			arguments = append(arguments, "--", "--listen="+endpoint, "--super="+config.super, "--galaxy="+config.galaxy, "--identity="+config.identity, "--state="+config.state, "--init")
			child := exec.CommandContext(ctx, binary, arguments...)
			child.Env = append(os.Environ(), "ASTRA_POLARIS_ENTRY=child")
			output, err := os.Create(filepath.Join(t.TempDir(), "process.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			child.Stdout, child.Stderr = output, output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					_ = child.Wait()
				}
			})
			if test.name == "admission" {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("entry never reached its in-flight admission request")
				}
			} else {
				channel, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(identity.Client())), grpc.WithDisableRetry())
				if err != nil {
					t.Fatal(err)
				}
				defer channel.Close()
				ready, err := grpc_health_v1.NewHealthClient(channel).Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
				if err != nil || ready.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
					t.Fatal("entry never reached authenticated readiness", err)
				}
			}
			if err := child.Process.Signal(test.signal); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			joined = true
			logs, read := os.ReadFile(output.Name())
			if read != nil {
				t.Fatal(read)
			}
			calls := int32(1)
			if test.name == "admission" {
				calls = 0
				select {
				case <-exited:
				case <-ctx.Done():
					t.Fatal("admission handler outlived cancelled entry")
				}
			}
			t.Logf("entry pid=%d signal=%s exit=%d output=%s", child.Process.Pid, test.signal, child.ProcessState.ExitCode(), logs)
			if err != nil || ctx.Err() != nil || service.calls.Load() != calls {
				t.Fatal("entry failed to exit normally before the cancellation budget", err, ctx.Err(), service.calls.Load())
			}
			if !exit {
				if profile != "" {
					data, err := os.ReadFile(profile)
					if err != nil || len(data) == 0 || len(data) > 1<<20 {
						t.Fatal("child omitted its bounded native coverage", err)
					}
					t.Log("POLARIS-ENTRY-PROFILE " + base64.StdEncoding.EncodeToString(data))
				}
			}
			rebound, err := net.Listen("tcp", endpoint)
			if err != nil {
				t.Fatal("entry retained its listener after signal shutdown", err)
			}
			if err := rebound.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := storage.Open(t.Context(), config.state, storage.Binding{Galaxy: config.galaxy, Username: identity.Username(), Advertise: endpoint}, storage.Default(), false)
			if err != nil {
				t.Fatal("entry did not release its valid exclusive database", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
