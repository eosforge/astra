// Verify production entry exit codes and owned Linux signals without touching deployment processes.
//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// incarnation identifies an unreaped child independently of its reusable numeric PID.
func incarnation(t *testing.T, pid int) string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data)[strings.LastIndex(string(data), ")")+1:])
	if len(fields) < 20 {
		t.Fatal("incomplete native process identity")
	}
	if ticks, err := strconv.ParseUint(fields[19], 10, 64); err != nil || ticks == 0 {
		t.Fatal("invalid native process start ticks")
	}
	return fields[19]
}

// TestProcess runs main only in a joined child and checks public exit status, readiness and remote cancellation.
func TestProcess(t *testing.T) {
	if os.Getenv("ASTRA_ASTROLABE_ENTRY") == "child" {
		for index, argument := range os.Args {
			if argument == "--" {
				os.Args = append([]string{"astrolabe"}, os.Args[index+1:]...)
				main()
				return
			}
		}
		t.Fatal("entry child lacks explicit deployment arguments")
	}
	for _, scenario := range []struct {
		name   string         // Public entry outcome or independently controlled lifecycle boundary.
		code   int            // Required process status, fixed before observing the implementation.
		signal syscall.Signal // Zero leaves the process to finish its own terminal error path.
	}{
		{"help", 0, 0}, {"usage", 2, 0}, {"startup", 1, 0}, {"refusal", 1, 0},
		{"terminate", 0, syscall.SIGTERM}, {"interrupt", 0, syscall.SIGINT}, {"pending", 0, syscall.SIGTERM},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			check := counter(t)
			config, listener, identity := deployment(t)
			mode := "http"
			if scenario.name == "pending" {
				mode = "cancel"
			} else if scenario.name == "refusal" {
				mode = "refusal"
			}
			service := launch(t, &config, identity, mode)
			check(listener.Close() == nil, "fixture did not release its listener reservation")
			arguments := []string{"--listen=" + config.listen, "--super=" + config.super, "--galaxy=" + config.galaxy, "--identity=" + config.identity, "--account=" + config.account, "--public=" + config.public, "--http"}
			switch scenario.name {
			case "help":
				arguments = []string{"--help"}
			case "usage":
				arguments = nil
			case "startup":
				arguments[3] = "--identity=" + t.TempDir()
			}
			binary, err := os.Executable()
			check(err == nil, "cannot identify the current entry test executable")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			// Only a normal harness return can flush native counters; os.Exit cases retain their actual status.
			command := []string{"-test.run=^TestProcess$", "-test.v"}
			profile := ""
			if scenario.code == 0 && testing.CoverMode() != "" {
				profile = filepath.Join(t.TempDir(), "entry.profile")
				command = append(command, "-test.coverprofile="+profile)
			}
			child := exec.CommandContext(ctx, binary, append(append(command, "--"), arguments...)...)
			child.Env = append(os.Environ(), "ASTRA_ASTROLABE_ENTRY=child")
			output, err := os.Create(filepath.Join(t.TempDir(), "entry.log"))
			check(err == nil, "cannot create owned entry output")
			defer output.Close()
			child.Stdout, child.Stderr = output, output
			check(child.Start() == nil, "cannot start the owned entry process")
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					_ = child.Wait()
				}
			})
			ticks := incarnation(t, child.Process.Pid)
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			check(err == nil && len(strings.TrimSpace(string(boot))) == 36, "cannot identify the host boot")
			if scenario.signal != 0 {
				select {
				case <-service.entered:
				case <-ctx.Done():
					t.Fatal("entry never reached its owned admission request")
				}
				transport := &http.Transport{Proxy: nil}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+config.listen+"/api/nodes", nil)
				check(err == nil, "cannot form local readiness request")
				response, err := client.Do(request)
				check(err == nil, "entry did not expose local readiness before the signal")
				body, read := io.ReadAll(io.LimitReader(response.Body, 1024))
				closed := response.Body.Close()
				check(read == nil && closed == nil && len(body) > 0 && len(body) < 1024, "readiness response was incomplete")
				check(response.StatusCode == http.StatusUnauthorized && response.Header.Get("Cache-Control") == "no-store", "entry readiness bypassed authentication")
				check(incarnation(t, child.Process.Pid) == ticks, "owned signal target identity changed")
				check(child.Process.Signal(scenario.signal) == nil, "cannot signal the owned entry process")
			}
			err = child.Wait()
			joined = true
			logs, read := os.ReadFile(output.Name())
			check(read == nil && len(logs) > 0 && len(logs) < 64<<10, "entry output was missing or exceeded its fixed bound")
			check(ctx.Err() == nil && child.ProcessState.ExitCode() == scenario.code, fmt.Sprintf("entry exit=%d, want %d; error=%v; output=%s", child.ProcessState.ExitCode(), scenario.code, err, logs))
			var failure *exec.ExitError
			check(scenario.code == 0 && err == nil || scenario.code != 0 && errors.As(err, &failure), "entry status did not match its native wait result")
			// Forward original child telemetry after joining; never manufacture counters for os.Exit paths.
			if scenario.code == 0 {
				for _, line := range strings.Split(string(logs), "\n") {
					if strings.HasPrefix(line, "GO-DECISIONS ") || strings.HasPrefix(line, "GO-CONTROLS ") {
						t.Log(line)
					}
				}
				if profile != "" {
					data, err := os.ReadFile(profile)
					if err != nil || len(data) == 0 || len(data) > 1<<20 {
						t.Fatal("child omitted its bounded native coverage", err)
					}
					t.Log("ASTROLABE-ENTRY-PROFILE " + base64.StdEncoding.EncodeToString(data))
				}
			}
			calls := int32(0)
			if scenario.signal != 0 || scenario.name == "refusal" {
				calls = 1
				select {
				case <-service.exited:
				case <-ctx.Done():
					t.Fatal("entry exit left its admission handler running")
				}
			}
			check(service.calls.Load() == calls, "entry contacted admission unexpectedly or replayed a terminal outcome")
			if scenario.code == 1 {
				check(strings.Contains(string(logs), `"level":"ERROR"`) && strings.Contains(string(logs), "Astrolabe stopped"), "fatal startup did not emit its structured terminal error")
			}
			rebound, err := net.Listen("tcp", config.listen)
			check(err == nil, "reaped entry retained its management listener")
			check(rebound.Close() == nil, "rebound listener failed to close")
			receipt, err := json.Marshal(map[string]any{"case": scenario.name, "pid": child.Process.Pid, "start_ticks": ticks, "boot_id": strings.TrimSpace(string(boot)), "signal": int(scenario.signal), "exit_code": child.ProcessState.ExitCode(), "reaped": joined, "calls": service.calls.Load()})
			check(err == nil, "cannot record the native child receipt")
			t.Log("ASTROLABE-PROCESS " + string(receipt))
		})
	}
}
