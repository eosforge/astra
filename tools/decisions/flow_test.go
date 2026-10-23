// Check control-flow probes against unchanged native evaluation, channel selection and deferred cleanup.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestFlowInventory requires every explicit arm to resolve to its original enclosing control.
func TestFlowInventory(t *testing.T) {
	// The tagless switch still has an observable default even though its case expressions are Boolean decisions.
	input := []byte("package p\nfunc F(v any, c chan int) {switch {case v == nil:return; default:}; switch v {case 1:return; default:}; switch v.(type) {case int:return; default:}; select {case <-c:return; default:}}\n")
	declarations, err := scan("state.go", input)
	if err != nil {
		t.Fatal(err)
	}
	_, edges, err := flow("state.go", input)
	if err != nil || len(edges) != 8 {
		t.Fatal("explicit arm inventory lost", len(edges), err)
	}
	parents := map[string]string{}
	for _, control := range declarations.Controls {
		parents[fmt.Sprintf("state.go:%d", control.Begin.Offset)] = control.Kind
	}
	for index, edge := range edges {
		want := []string{"switch", "switch", "type-switch", "select"}[index/2]
		if parents[edge.Parent] != want || edge.Begin.Offset <= declarations.Controls[index/2].Begin.Offset || edge.End.Offset >= declarations.Controls[index/2].End.Offset {
			t.Fatal("arm lost its containing source control", edge, parents)
		}
	}
	if len(declarations.Decisions) != 1 || declarations.Decisions[0].Kind != "case" || declarations.Decisions[0].Text != "v == nil" {
		t.Fatal("tagless case decision was removed or duplicated", declarations.Decisions)
	}
}

// TestFlow compares native behavior and exact exhaustion, early exits and switch/loop ownership.
func TestFlow(t *testing.T) {
	input := []byte(`package main
var calls int
var marks []int
func input(values []int) []int { calls++; return values }
func walk(values []int, stop bool) (total int) {
 defer func(){ marks=append(marks,9) }()
 for _,v:=range input(values) { marks=append(marks,v); if v<0 {continue}; if stop && v==2 {return}; total+=v }
 return
}
func count(limit int) int { total:=0; for i:=0;i<limit;i++ {total+=i}; return total }
func forever() int { for { return 7 } }
func receive(channel <-chan int) int { select {case value:=<-channel: return value; default: return -1} }
func send(channel chan<-int) bool { select {case channel<-7: return true; default: return false} }
func sequence(yield func(int)bool) { if !yield(3) {return}; yield(4) }
func generated() int { total:=0; for value:=range sequence {total+=value; return total}; return total }
func nested() int { total:=0; for i:=range 3 {for j:=range i {total+=j}}; return total }
func failure(early bool) []int {if early {panic("input")}; return []int{1}}
func interrupted(early bool) {for range failure(early) {panic("body")}}
func stop(values []int) int {total:=0; for _,value:=range values {total+=value; break}; return total}
func bounded(limit int) int {total:=0; for i:=0;i<limit;i++ {if i==1 {break}; total++}; return total}
func cycle() int {for {break}; return 9}
func branch(value int) int {total:=0; for range 3 {switch value {case 1:total++; break; case 2:continue; default:total+=3}; total+=10}; return total}
func classify(value any) int {switch item:=value.(type) {case int:return item; case string:return len(item); default:return -1}}
var conditions []int
func condition(value, match int) bool {conditions=append(conditions,match); return value==match}
func choose(value int) int {switch {case condition(value,1),condition(value,2):return 5; default:return 7}}
func nestedBreak() int {total:=0; for range 2 {for range 3 {total++; break}}; return total}
func generatedBreak() int {total:=0; for value:=range sequence {total+=value; break}; return total}
func selectedBreak() int {total:=0; for range 2 {select {default:break}; total++}; return total}
func closureBreak() int {total:=0; for range 2 {func(){for range 3 {total++; break}}()}; return total}
`)
	changed, edges, err := flow("state.go", input)
	if err != nil || len(edges) != 30 {
		t.Fatal("control inventory changed", err, edges)
	}
	harness := `package main
import ("fmt"; "reflect"; "sync")
func caught(early bool) {defer func(){if recover()==nil {panic("missing failure")}}(); interrupted(early)}
func main(){
 if walk(nil,false)!=0 || walk([]int{-1,1,2},false)!=3 || walk([]int{1,2,3},true)!=1 || calls!=3 {panic("range evaluation")}
 if !reflect.DeepEqual(marks,[]int{9,-1,1,2,9,1,2,9}) {panic("defer/continue ordering")}
 if count(0)!=0 || count(3)!=3 || forever()!=7 || generated()!=3 || nested()!=1 {panic("loop return")}
 if stop(nil)!=0 || stop([]int{4,8})!=4 || bounded(0)!=0 || bounded(1)!=1 || bounded(3)!=1 || cycle()!=9 {panic("break semantics")}
 if branch(1)!=33 || branch(2)!=0 || branch(0)!=39 || classify(17)!=17 || classify("abc")!=3 || classify(nil)!=-1 {panic("switch semantics")}
 if choose(2)!=5 || choose(0)!=7 || !reflect.DeepEqual(conditions,[]int{1,2,1,2}) {panic("case evaluation")}
 if nestedBreak()!=2 || generatedBreak()!=3 || selectedBreak()!=2 || closureBreak()!=2 {panic("break target")}
 caught(true); caught(false)
 channel:=make(chan int,1)
 if receive(channel)!=-1 || !send(channel) || send(channel) || receive(channel)!=7 {panic("select effects")}
 var group sync.WaitGroup
 for range 100 {group.Go(func(){if count(3)!=3 {panic("concurrent loop")}})}
 group.Wait()
 fmt.Println("SEMANTICS range/defer/continue/return/select/generator/concurrency")
 astraProbeFinish(0)
}
`
	for _, variant := range []struct {
		name string // Separate native working directory and evidence identity.
		data []byte // Original or rewritten production fixture.
	}{{"original", input}, {"instrumented", changed}} {
		directory := filepath.Join(t.TempDir(), variant.name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		runtime := strings.Replace(strings.Replace(traceRuntime, "package probe", "package main", 1), "GO-DECISIONS", "GO-CONTROLS", 1)
		for name, data := range map[string][]byte{"go.mod": []byte("module probe\ngo 1.25\n"), "state.go": variant.data, "main.go": []byte(harness), "runtime.go": []byte(runtime)} {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		command := exec.CommandContext(ctx, "go", "run", "-race", ".")
		command.Dir = directory
		command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s native flow check failed: %v %s", variant.name, err, output)
		}
		lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
		if len(lines) != 2 || string(lines[0]) != "SEMANTICS range/defer/continue/return/select/generator/concurrency" || !bytes.HasPrefix(lines[1], []byte("GO-CONTROLS ")) {
			t.Fatalf("unexpected native output: %s", output)
		}
		var receipt struct {
			PID  int `json:"pid"`  // Actual child identity.
			Code int `json:"code"` // Native semantic harness outcome.
			Rows []struct {
				ID     string `json:"id"`     // Original loop or arm identity.
				Values string `json:"values"` // Body/exhaustion pair or selected arm marker.
				Result bool   `json:"result"` // Exhaustion, or true for a selected arm.
				Hits   uint64 `json:"hits"`   // Actual completions, including concurrent calls.
			} `json:"rows"`
		}
		if err := json.Unmarshal(lines[1][len("GO-CONTROLS "):], &receipt); err != nil || receipt.PID <= 0 || receipt.Code != 0 {
			t.Fatal("invalid native flow receipt", err)
		}
		actual := map[string]map[string]uint64{}
		for _, row := range receipt.Rows {
			if row.Hits == 0 || row.Result != strings.HasSuffix(row.Values, "2") {
				t.Fatal("invalid completion state", row)
			}
			if actual[row.ID] == nil {
				actual[row.ID] = map[string]uint64{}
			}
			if actual[row.ID][row.Values] != 0 {
				t.Fatal("duplicate native vector", row)
			}
			actual[row.ID][row.Values] = row.Hits
		}
		want := map[string]map[string]uint64{}
		if variant.name == "instrumented" {
			for index, states := range []map[string]uint64{
				{"12": 1, "22": 1, "21": 1}, {"12": 1, "22": 101}, {"21": 1}, {"2": 1}, {"2": 1}, {"2": 1}, {"2": 1}, {"21": 1}, {"22": 1}, {"12": 1, "22": 2}, {"11": 1, "21": 1},
				{"12": 1, "21": 1}, {"12": 1, "22": 1, "21": 1}, {"21": 1}, {"22": 3}, {"2": 3}, {"2": 3}, {"2": 3}, {"2": 1}, {"2": 1}, {"2": 1}, {"2": 1}, {"2": 1},
				{"22": 1}, {"21": 2}, {"21": 1}, {"22": 1}, {"2": 2}, {"22": 1}, {"21": 2},
			} {
				want[edges[index].ID] = states
			}
		}
		if !reflect.DeepEqual(actual, want) {
			t.Fatalf("%s control observations differ: got %v want %v", variant.name, actual, want)
		}
	}
}

// TestFlowRejection refuses syntax/control forms whose completion semantics the probe does not support.
func TestFlowRejection(t *testing.T) {
	for _, input := range []string{
		"package p; func F(){outer: for {break outer}}",
		"package p; func F(){outer: for {continue outer}}",
		"package p; func F(){goto done; done: return}",
		"package p; func F(v int){switch v {case 1:return}}",
		"package p; func F(v any){switch v.(type) {case int:return}}",
		"package p; func F(v int){switch v {case 1:fallthrough; default:return}}",
		"package p; func F(){break}",
		"package p; func F(){for {func(){break}()}}",
		"package p; func F(){select{}}",
		"package p; func F(){defer func(){recover()}(); for {return}}",
		"package p; func F(){var astraProbeLoop1 int; for {return}}",
		"package p; func invalid(",
	} {
		if _, _, err := flow("invalid.go", []byte(input)); err == nil {
			t.Fatalf("unsupported flow accepted: %s", input)
		}
	}
}

// TestFlowScope keeps source identities, unsupported forms and exclusive overlay ownership visible.
func TestFlowScope(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "component"), 0700); err != nil {
		t.Fatal(err)
	}
	input := []byte("package example\nfunc F(values []int){for range values {}}\n")
	path := filepath.Join(root, "component/state.go")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	item, err := scan("component/state.go", input)
	if err != nil {
		t.Fatal(err)
	}
	collection := report{SourceSHA256: strings.Repeat("a", 64), Files: []inventory{item}}
	destination := filepath.Join(root, "overlay")
	if err := prepareTrace(root, "component", destination, collection, &typing{}, true); err == nil {
		t.Fatal("mixed evidence accepted")
	}
	if err := prepareTrace(root, "component", destination, collection, nil, true); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Observed []string `json:"observed"` // Each registered control has a source-bound identity.
		Edges    []edge   `json:"edges"`    // Declared flow scope, not a Boolean decision manifest.
	}
	data, err := os.ReadFile(filepath.Join(destination, "flow.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil || len(manifest.Edges) != 1 || !reflect.DeepEqual(manifest.Observed, []string{manifest.Edges[0].ID}) {
		t.Fatal("flow inventory omitted", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "trace.json")); !os.IsNotExist(err) {
		t.Fatal("flow mislabeled as Boolean evidence")
	}
	if err := prepareTrace(root, "component", destination, collection, nil, true); err == nil {
		t.Fatal("flow evidence overwritten")
	}
	if err := os.WriteFile(path, append(input, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareTrace(root, "component", filepath.Join(root, "drift"), collection, nil, true); err == nil {
		t.Fatal("flow source drift accepted")
	}
}
