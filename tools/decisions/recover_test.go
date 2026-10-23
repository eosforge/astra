// Preserve direct recover calls outside instrumented expressions and reject wrapped recovery explicitly.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTraceRecoverOutsideDecisions executes normal, panic and panic(nil) paths through unchanged deferred recovery.
func TestTraceRecoverOutsideDecisions(t *testing.T) {
	input := []byte(`package main
var calls int
func invoke(callback func()) (panicked bool) {
 panicked = true
 defer func() { _ = recover() }()
 callback()
 return false
}
func hold(flag bool) (value string) {
 defer func() { if flag { calls++ }; value = recover().(string) }()
 if flag { panic("left") }; panic("right")
}
`)
	changed, observed, cause := instrument("state.go", input)
	if cause != nil || len(observed) != 3 {
		t.Fatalf("independent deferred recovery blocked safe decision observation: %v %v", observed, cause)
	}
	if strings.Count(string(changed), "recover()") != 2 {
		t.Fatal("direct recovery was removed or duplicated")
	}
	harness := `package main
func main() {
 if invoke(func(){}) || !invoke(func(){panic("original")}) || !invoke(func(){panic(nil)}) { panic("callback recovery semantics changed") }
 if hold(true)!="left" || hold(false)!="right" || calls!=1 { panic("deferred direct recovery semantics changed") }
 astraProbeFinish(0)
}
`
	root := t.TempDir()
	for name, data := range map[string][]byte{
		"go.mod": []byte("module fixture\ngo 1.27.0\n"), "state.go": changed, "main.go": []byte(harness),
		"runtime.go": []byte(strings.Replace(traceRuntime, "package probe", "package main", 1)),
	} {
		if cause := os.WriteFile(filepath.Join(root, name), data, 0600); cause != nil {
			t.Fatal(cause)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// This ordinary semantic control is portable; existing Linux controls separately exercise -race.
	command := exec.CommandContext(ctx, "go", "run", "-p=2", ".")
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
	command.WaitDelay = time.Second
	output, cause := command.CombinedOutput()
	if cause != nil || ctx.Err() != nil || !strings.HasPrefix(string(output), "GO-DECISIONS ") {
		t.Fatalf("native direct-recovery control failed: %v %s", cause, output)
	}
	var receipt struct {
		PID  int `json:"pid"`  // Actual native child identity.
		Code int `json:"code"` // Terminal independent harness exit.
		Rows []struct {
			ID   string `json:"id"`   // Original observed decision.
			Hits uint64 `json:"hits"` // Completed evaluations only.
		} `json:"rows"`
	}
	if cause := json.Unmarshal(output[len("GO-DECISIONS "):], &receipt); cause != nil || receipt.PID <= 0 || receipt.Code != 0 {
		t.Fatal("invalid native recovery receipt", cause)
	}
	counts := map[string]uint64{}
	for _, row := range receipt.Rows {
		counts[row.ID] += row.Hits
	}
	if len(counts) != 3 || counts[observed[0]] != 1 || counts[observed[1]] != 2 || counts[observed[2]] != 2 {
		t.Fatalf("incomplete panic evaluations were fabricated or decisions were lost: %v", counts)
	}
}

// TestTraceRecoverSpans rejects direct calls in closures the collector would add, including typed standalone roots.
func TestTraceRecoverSpans(t *testing.T) {
	for _, input := range []string{
		"package main; func F()bool { return recover()!=nil }",
		"package main; func F() { defer func(){ if recover()!=nil {} }() }",
		"package main; func F() { for recover()!=nil {} }",
	} {
		if _, _, cause := instrument("unsafe.go", []byte(input)); cause == nil || cause.Error() != "trace-reserved-or-recover" {
			t.Fatalf("wrapped direct recovery was accepted: %s %v", input, cause)
		}
	}
	input := []byte("package main; func F() { value := recover()!=nil; _ = value }")
	inventory, cause := scan("typed.go", input)
	if cause != nil || len(inventory.Decisions) != 1 {
		t.Fatal("typed recovery fixture lost its decision", cause)
	}
	if _, _, cause := instrument("typed.go", input); cause != nil {
		t.Fatal("unchanged unsupported syntax was rejected despite having no added closure", cause)
	}
	if _, _, cause := rewrite("typed.go", input, map[string]string{inventory.Decisions[0].ID: "bool"}); cause == nil || cause.Error() != "trace-reserved-or-recover" {
		t.Fatal("typed wrapped recovery was accepted", cause)
	}
}
