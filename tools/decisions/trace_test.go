// Challenge diagnostic overlays with actual execution, short-circuit effects and rejected input boundaries.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestTrace executes rewritten expressions and checks native vectors against independent truth/effect tables.
func TestTrace(t *testing.T) {
	input := []byte(`package main
type Flag bool
var calls []int
func term(id int, value Flag) Flag { calls=append(calls,id); return value }
func decide(a,b,c Flag) bool { return term(0,a) && (!term(1,b) || term(2,c)) }
func nested(a,b bool) bool { return func() bool { if a { return b }; return false }() || a }
func raising() bool { panic("original") }
func panics() bool { return raising() && raising() }
func main() {
 for _,item:=range []struct{a,b,c Flag; want bool; calls []int}{
 {false,false,false,false,[]int{0}}, {true,false,false,true,[]int{0,1}},
 {true,true,false,false,[]int{0,1,2}}, {true,true,true,true,[]int{0,1,2}},
 } { calls=nil; if decide(item.a,item.b,item.c)!=item.want || !reflect.DeepEqual(calls,item.calls) { panic("evaluation semantics") } }
 for _,a:=range []bool{false,true} { for _,b:=range []bool{false,true} { if nested(a,b)!=a { panic("nested") } } }
 func(){ defer func(){ if recover()!="original" { panic("panic changed") } }(); panics() }()
 var group sync.WaitGroup; for range 100 { group.Go(func(){ if !nested(true,true) { panic("parallel") } }) }; group.Wait()
 // Capacity, overflow and terminal guards must fail visibly instead of dropping observations.
 rejects:=func(want string, action func()) { defer func(){ if recover()!=want { panic("recorder guard changed") } }(); action(); panic("guard absent") }
 astraProbeState.total=65536
 rejects("decision trace capacity",func(){ astraProbeRecord("capacity",[]byte{1},false) })
 delete(astraProbeState.rows,"capacity"); astraProbeState.total=0
 astraProbeState.rows["overflow"]=map[string]uint64{"10":^uint64(0)}
 rejects("decision trace counter overflow",func(){ astraProbeRecord("overflow",[]byte{1},false) })
 delete(astraProbeState.rows,"overflow")
 astraProbeState.closed=true
 rejects("decision trace after terminal report",func(){ astraProbeRecord("closed",[]byte{1},false) })
 astraProbeState.closed=false
 astraProbeFinish(0)
}
`)
	// The harness stays untouched: recover must remain a direct call in its own deferred function.
	start := strings.Index(string(input), "func main()")
	changed, observed, err := instrument("state.go", input[:start])
	if err != nil || len(observed) == 0 {
		t.Fatal("rewrite failed", err)
	}
	root := t.TempDir()
	files := map[string][]byte{"go.mod": []byte("module probe\ngo 1.25\n"), "state.go": changed,
		"runtime.go": []byte(strings.Replace(traceRuntime, "package probe", "package main", 1)),
		"main.go":    []byte("package main\nimport (\"reflect\"; \"sync\")\n" + string(input[start:]))}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-race", ".")
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil || ctx.Err() != nil || !strings.HasPrefix(string(output), "GO-DECISIONS ") {
		t.Fatalf("native semantic check failed: %v %s", err, output)
	}
	var receipt struct {
		PID  int `json:"pid"`  // The actual child process emitted the receipt.
		Code int `json:"code"` // The harness completed all independent checks.
		Rows []struct {
			ID     string `json:"id"`     // Original decision identity.
			Values string `json:"values"` // Unevaluated/false/true vector.
			Result bool   `json:"result"` // Actual decision output.
			Hits   uint64 `json:"hits"`   // Actual completed calls.
		} `json:"rows"`
	}
	if err := json.Unmarshal(output[len("GO-DECISIONS "):], &receipt); err != nil || receipt.PID <= 0 || receipt.Code != 0 {
		t.Fatal("bad native receipt", err)
	}
	inventory, err := scan("state.go", input[:start])
	if err != nil {
		t.Fatal(err)
	}
	id, panicking := "", ""
	for _, item := range inventory.Decisions {
		if item.Text == "term(0, a) && (!term(1, b) || term(2, c))" {
			id = item.ID
		}
		if item.Text == "raising() && raising()" {
			panicking = item.ID
		}
	}
	if id == "" || panicking == "" {
		t.Fatal("fixture inventory is empty")
	}
	states := map[string]bool{}
	var parallel uint64
	for _, row := range receipt.Rows {
		if row.Hits == 0 || row.ID == panicking {
			t.Fatal("fabricated incomplete observation")
		}
		if row.ID == id {
			if row.Hits != 1 {
				t.Fatal("duplicate evaluation")
			}
			states[row.Values] = row.Result
		}
		parallel = max(parallel, row.Hits)
	}
	if !reflect.DeepEqual(states, map[string]bool{"100": false, "210": true, "221": false, "222": true}) || parallel < 100 {
		t.Fatalf("short-circuit vectors or concurrent observations lost: %v %d", states, parallel)
	}
}

// TestTraceRejection prevents altered recover semantics, reserved-symbol capture and silent trace truncation.
func TestTraceRejection(t *testing.T) {
	for _, input := range []string{
		"package example; func F()bool { return recover()!=nil }",
		"package example; var astraProbeValues0 bool; func F()bool { return astraProbeValues0 }",
		"package example; func F(a bool)bool { return " + strings.Repeat("a && ", 64) + "a }",
		"package example; func invalid(",
	} {
		if _, _, err := instrument("invalid.go", []byte(input)); err == nil {
			t.Fatalf("unsafe fixture accepted: %s", input)
		}
	}
}

// TestTraceScope preserves unsupported roots, package source identity and exclusive output ownership.
func TestTraceScope(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "component")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	input := []byte("package example\nfunc F(a,b bool)bool { v:=a&&b; if v { return true }; return false }\n")
	path := filepath.Join(directory, "state.go")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	item, err := scan("component/state.go", input)
	if err != nil {
		t.Fatal(err)
	}
	collection := report{SourceSHA256: strings.Repeat("a", 64), Files: []inventory{item}}
	output := filepath.Join(root, "overlay")
	if err := trace(root, "component", output, collection); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Observed []string    `json:"observed"` // Only supported roots may appear here.
		Files    []inventory `json:"files"`    // Unsupported decisions stay in the denominator.
	}
	data, err := os.ReadFile(filepath.Join(output, "trace.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil || len(manifest.Observed) != 3 || len(manifest.Files) != 1 || len(manifest.Files[0].Decisions) != 4 {
		t.Fatal("unsupported Boolean root disappeared", err)
	}
	if err := trace(root, "component", output, collection); err == nil {
		t.Fatal("existing evidence overwritten")
	}
	if err := os.WriteFile(path, append(input, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := trace(root, "component", filepath.Join(root, "drift"), collection); err == nil {
		t.Fatal("source drift accepted")
	}
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	test := "component/state_test.go"
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(test)), []byte("package example\nfunc TestMain() {}"), 0600); err != nil {
		t.Fatal(err)
	}
	collection.Tests = []string{test}
	if err := trace(root, "component", filepath.Join(root, "main"), collection); err == nil {
		t.Fatal("existing TestMain bypassed")
	}
}
