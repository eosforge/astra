// Verify the complete owned flag-wrapper failure boundary without replacing its parsing or admission rules.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// disturbance injects one callback failure and observes attempted writes and duplicate reentry independently.
type disturbance struct {
	calls   int
	err     error
	panic   bool
	wrapped *once
	blocked bool
}

// String exposes a persistent callback panic and a distinguishable healthy result.
func (value *disturbance) String() string {
	value.calls++
	if value.panic {
		panic(value.err)
	}
	return "visible"
}

// Set bounds recursive reentry to one attempted nested write, even against the late-admission mutant.
func (value *disturbance) Set(string) error {
	value.calls++
	if value.wrapped != nil && value.calls == 1 {
		value.blocked = value.wrapped.Set("nested") != nil
	}
	if value.panic {
		panic(value.err)
	}
	return value.err
}

// IsBoolFlag retains the registered optional-interface failure boundary.
func (value *disturbance) IsBoolFlag() bool {
	value.calls++
	if value.panic {
		panic(value.err)
	}
	return true
}

// condition is the complete public/callback observation carried by each fault matrix cell.
type condition struct {
	Result   string `json:"result"`
	Calls    int    `json:"calls"`
	Consumed bool   `json:"consumed"`
	Prefix   int    `json:"prefix"`
	Value    int    `json:"value"`
	Returned bool   `json:"returned"`
}

// capture distinguishes a returned error from an escaping panic without supplying production recovery.
func capture(action func() error) (result string, cause any) {
	result = "panic"
	defer func() {
		if recovered := recover(); recovered != nil {
			cause = recovered
		}
	}()
	err := action()
	if err == nil {
		return "ok", nil
	}
	if errors.Is(err, flag.ErrHelp) {
		return "help", err
	}
	return "error", err
}

// diagnostic witnesses state before standard flag's process exit or injects a failed diagnostic write.
type diagnostic struct {
	flags   *flag.FlagSet
	prefix  *int
	value   *int
	calls   int
	failure bool
	witness bool
}

// state reads the independent registered integers and the admission marker, without calling arbitrary values.
func (output *diagnostic) state() condition {
	return condition{Prefix: *output.prefix, Value: *output.value, Consumed: output.flags.Lookup("value").Value.(*once).set}
}

// Write records the pre-exit state; diagnostic I/O failure must not replace flag's ErrHelp result.
func (output *diagnostic) Write(text []byte) (int, error) {
	output.calls++
	if output.witness {
		data, err := json.Marshal(output.state())
		if err != nil {
			panic(err)
		}
		fmt.Println("COMMAND-EXIT-STATE " + string(data))
	}
	if output.failure {
		return 0, io.ErrClosedPipe
	}
	return len(text), nil
}

// parsing preserves the standard library's error-handling modes and retains already accepted prefix writes.
func parsing(mode, fault string, phase int, witness bool) condition {
	handling := map[string]flag.ErrorHandling{"continue": flag.ContinueOnError, "panic": flag.PanicOnError, "exit": flag.ExitOnError}[mode]
	flags := flag.NewFlagSet("fault", handling)
	prefix := flags.Int("prefix", 0, "accepted prefix")
	value := flags.Int("value", 0, "single attempted value")
	output := &diagnostic{flags: flags, prefix: prefix, value: value, witness: witness, failure: fault == "output" && phase < 2}
	flags.SetOutput(output)
	arguments := []string{"--prefix=7"}
	if phase == 2 {
		arguments = append(arguments, "--value=9")
	} else {
		arguments = append(arguments, map[string][]string{
			"unknown": {"--absent=1"}, "missing": {"--value"}, "invalid": {"--value=wrong"},
			"duplicate": {"--value=9", "--value=10"}, "help": {"--help"}, "output": {"--help"},
		}[fault]...)
	}
	result, cause := capture(func() error { return Parse(flags, arguments) })
	state := output.state()
	state.Result, state.Returned = result, result != "panic"
	if result == "panic" && cause == nil {
		panic("missing propagated parser panic")
	}
	if fault == "output" && output.calls > 0 {
		state.Calls = 1
	}
	return state
}

// TestFault covers three callback sites, single-attempt/reentry failures, all native parser modes and failed help output.
func TestFault(t *testing.T) {
	if selector := os.Getenv("ASTRA_COMMAND_EXIT"); selector != "" {
		var request struct {
			Fault string
			Phase int
		}
		if err := json.Unmarshal([]byte(selector), &request); err != nil {
			t.Fatal(err)
		}
		state := parsing("exit", request.Fault, request.Phase, true)
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("COMMAND-EXIT-STATE " + string(data))
		return
	}
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-FAULT","hits":%d}`, hits) })
	emit := func(id string, phase int, state, expected condition) {
		t.Helper()
		if state != expected {
			t.Fatalf("fault %s phase %d: %+v, expected %+v", id, phase, state, expected)
		}
		data, err := json.Marshal(struct {
			ID    string    `json:"id"`
			Phase int       `json:"phase"`
			State condition `json:"state"`
		}{id, phase, state})
		if err != nil {
			t.Fatal(err)
		}
		hits++
		t.Log("COMMAND-FAULT " + string(data))
	}
	for _, site := range []string{"set-error", "set-panic", "set-reentry", "string-panic", "boolean-panic"} {
		for phase := range 3 {
			sentinel := errors.New("registered callback failure")
			target := &disturbance{}
			if phase < 2 {
				target.err, target.panic = sentinel, strings.HasSuffix(site, "panic")
			}
			wrapped := &once{Value: target}
			if site == "set-reentry" {
				target.wrapped = wrapped
			}
			result, cause := capture(func() error {
				switch site {
				case "string-panic":
					if wrapped.String() != "visible" {
						t.Fatal("healthy display lost")
					}
				case "boolean-panic":
					if !wrapped.IsBoolFlag() {
						t.Fatal("healthy boolean lost")
					}
				default:
					return wrapped.Set("first")
				}
				return nil
			})
			if phase < 2 && cause != sentinel {
				t.Fatal("callback cause replaced or swallowed")
			}
			expected := condition{Result: "ok", Calls: 1, Returned: true}
			if strings.HasPrefix(site, "set-") {
				expected.Consumed = true
				if wrapped.Set("again") == nil || target.calls != 1 {
					t.Fatal("failed or completed attempt replayed")
				}
			}
			if site == "set-reentry" && !target.blocked {
				t.Fatal("callback reentry admitted a duplicate")
			}
			if phase < 2 {
				expected.Result = "error"
				if strings.HasSuffix(site, "panic") {
					expected.Result, expected.Returned = "panic", false
				}
			}
			emit(site, phase, condition{Result: result, Calls: target.calls, Consumed: wrapped.set, Returned: result != "panic"}, expected)
		}
	}
	for _, mode := range []string{"continue", "panic", "exit"} {
		for _, fault := range []string{"unknown", "missing", "invalid", "duplicate", "help"} {
			for phase := range 3 {
				expected := condition{Result: "ok", Prefix: 7, Value: 9, Consumed: true, Returned: true}
				if phase < 2 {
					expected.Result, expected.Value, expected.Consumed = "error", 0, fault == "invalid" || fault == "duplicate"
					if fault == "duplicate" {
						expected.Value = 9
					}
					if fault == "help" {
						expected.Result = "help"
					}
					if mode == "panic" {
						expected.Result, expected.Returned = "panic", false
					}
				}
				var state condition
				if mode == "exit" {
					selector, err := json.Marshal(struct {
						Fault string
						Phase int
					}{fault, phase})
					if err != nil {
						t.Fatal(err)
					}
					context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					child := exec.CommandContext(context, os.Args[0], "-test.run=^TestFault$")
					child.Env = []string{"ASTRA_COMMAND_EXIT=" + string(selector)}
					for _, key := range []string{"SYSTEMROOT", "SystemRoot", "SYSTEMDRIVE", "PATH", "TEMP", "TMP", "TMPDIR", "GOCOVERDIR"} {
						if value, present := os.LookupEnv(key); present {
							child.Env = append(child.Env, key+"="+value)
						}
					}
					output, runErr := child.CombinedOutput()
					timedOut := context.Err() != nil
					cancel()
					if timedOut || child.ProcessState == nil {
						t.Fatalf("owned parser child did not drain: %v", runErr)
					}
					code := child.ProcessState.ExitCode()
					if code != 0 && code != 2 {
						t.Fatalf("unexpected native exit %d: %s", code, output)
					}
					found := false
					for _, line := range bytes.Split(output, []byte{'\n'}) {
						if bytes.HasPrefix(line, []byte("COMMAND-EXIT-STATE ")) {
							if err := json.Unmarshal(bytes.TrimPrefix(line, []byte("COMMAND-EXIT-STATE ")), &state); err != nil {
								t.Fatal(err)
							}
							found = true
						}
					}
					if !found {
						t.Fatalf("missing native pre-exit/returned state: %s", output)
					}
					state.Result, expected.Result = "exit-ok", "exit-ok"
					if code == 2 {
						state.Result = "exit-error"
					}
					if phase < 2 {
						expected.Returned = false
						if fault != "help" {
							expected.Result = "exit-error"
						}
					}
				} else {
					state = parsing(mode, fault, phase, false)
				}
				emit("parser/"+mode+"/"+fault, phase, state, expected)
			}
		}
	}
	for phase := range 3 {
		expected := condition{Result: "help", Calls: 1, Prefix: 7, Returned: true}
		if phase == 2 {
			expected = condition{Result: "ok", Prefix: 7, Value: 9, Consumed: true, Returned: true}
		}
		emit("output-error", phase, parsing("continue", "output", phase, false), expected)
	}
	if hits != 63 {
		t.Fatal("incomplete fault domain")
	}
}
