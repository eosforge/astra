// Verify native platform selection without removing inactive source or granting it typed observations.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// partitionFixture retains original files and native metadata while one test owns its temporary module.
type partitionFixture struct {
	root     string            // Actual module root selected by the native compiler.
	source   string            // Bound manifest consumed through the existing collector CLI.
	exports  string            // Original native go-list output, never synthesized for the positive case.
	files    map[string][]byte // Exact independent fixture source, including every platform.
	metadata []byte            // Complete native package/export output.
}

// partitionCommand executes one bounded offline native child and preserves its original output in the parent stream.
func partitionCommand(t *testing.T, root string, cache string, arguments ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir = root
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
	if cache != "" {
		command.Env = append(command.Env, "GOCACHE="+cache)
	}
	command.WaitDelay = time.Second
	output, cause := command.CombinedOutput()
	t.Logf("PARTITION-NATIVE argv=%q output=%s", arguments, output)
	if cause != nil || ctx.Err() != nil {
		t.Fatalf("native partition fixture failed: %v %s", cause, output)
	}
	return output
}

// newPartitionFixture prescribes a four-row Boolean truth table and mutually exclusive platform inputs.
func newPartitionFixture(t *testing.T) partitionFixture {
	t.Helper()
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Fatal("this native partition control requires an included target platform")
	}
	fixture := partitionFixture{root: t.TempDir(), files: map[string][]byte{
		"go.mod":             []byte("module fixture\ngo 1.27.0\n"),
		"dependency/flag.go": []byte("package dependency\n// Flag retains a distinct Boolean type across the compiler export boundary.\ntype Flag bool\n"),
		"unit/state.go": []byte(`package unit
import "fixture/dependency"
const Stable = 1 < 2
var Last dependency.Flag
func Choose(a,b dependency.Flag) dependency.Flag { Last=a!=b; return a&&b }
func Recover(callback func()) (panicked bool) {
 panicked=true
 defer func(){ _=recover() }()
 callback()
 return false
}
`),
		"unit/platform_windows.go": []byte("//go:build windows\n\npackage unit\nfunc Platform(flag bool)bool{return flag&&true}\n"),
		"unit/platform_linux.go":   []byte("//go:build linux\n\npackage unit\nfunc Platform(flag bool)bool{return flag&&true}\n"),
		"unit/platform_other.go":   []byte("//go:build !windows && !linux\n\npackage unit\nfunc Platform(flag bool)bool{defer func(){}();return flag&&missing}\n"),
		"unit/state_test.go": []byte(`package unit
import ("testing"; "fixture/dependency")
func TestValues(t *testing.T) {
 for _,item:=range []struct{a,b,want,last dependency.Flag}{
 {false,false,false,false},{false,true,false,true},{true,false,false,true},{true,true,true,false},
 } {
  var actual dependency.Flag=Choose(item.a,item.b)
  if actual!=item.want || Last!=item.last || !Stable {t.Fatal("prescribed named Boolean result changed")}
 }
 if !Platform(true) || Platform(false) {t.Fatal("wrong native platform selected")}
 if Recover(func(){}) || !Recover(func(){panic("original")}) || !Recover(func(){panic(nil)}) {t.Fatal("direct deferred recovery changed")}
}
`),
	}}
	manifest := source{Files: []input{}, Status: "isolated native compiler fixture"}
	names := []string{}
	for name := range fixture.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := fixture.files[name]
		path := filepath.Join(fixture.root, filepath.FromSlash(name))
		if cause := os.MkdirAll(filepath.Dir(path), 0700); cause != nil {
			t.Fatal(cause)
		}
		if cause := os.WriteFile(path, data, 0600); cause != nil {
			t.Fatal(cause)
		}
		digest := sha256.Sum256(data)
		value := hex.EncodeToString(digest[:])
		manifest.Files = append(manifest.Files, input{Path: name, SHA256: &value})
	}
	encoded, cause := json.Marshal(manifest)
	if cause != nil {
		t.Fatal(cause)
	}
	fixture.source = filepath.Join(fixture.root, "source.json")
	fixture.exports = filepath.Join(fixture.root, "exports.json")
	if cause := os.WriteFile(fixture.source, encoded, 0600); cause != nil {
		t.Fatal(cause)
	}
	fixture.metadata = partitionCommand(t, fixture.root, filepath.Join(fixture.root, "build/cache/go"), "list", "-deps", "-export", "-json", "./unit")
	if cause := os.WriteFile(fixture.exports, fixture.metadata, 0600); cause != nil {
		t.Fatal(cause)
	}
	return fixture
}

// arguments keeps fixture controls on the unchanged public CLI so the original tool can execute the red test.
func (fixture partitionFixture) arguments(output string) []string {
	return []string{"-root", fixture.root, "-source", fixture.source, "-trace", "unit", "-output", output, "-export", fixture.exports}
}

// TestPartitionNative requires the current native platform, retained inactive geometry and unchanged runtime values.
func TestPartitionNative(t *testing.T) {
	fixture := newPartitionFixture(t)
	partitionCommand(t, fixture.root, "", "test", "-json", "-count=1", "-p=2", "-parallel=2", "-timeout=60s", "./unit")
	var out, diagnostics bytes.Buffer
	if cause := run(fixture.arguments(filepath.Join(fixture.root, "old")), &out, &diagnostics); cause == nil || !strings.Contains(cause.Error(), "typing-inactive-decisions") {
		t.Fatal("typed v2 no longer preserves its inactive-decision rejection", cause)
	}
	output := filepath.Join(fixture.root, "overlay")
	out.Reset()
	if cause := run(append(fixture.arguments(output), "-partition"), &out, &diagnostics); cause != nil {
		t.Fatalf("typed native platform partition rejected: %v", cause)
	}
	var collection report
	if cause := json.Unmarshal(out.Bytes(), &collection); cause != nil || len(collection.Files) != 5 {
		t.Fatal("complete fixture syntax inventory changed", cause)
	}
	var manifest struct {
		Version       int         `json:"version"`       // New evidence format is explicitly distinct from v2.
		Partition     string      `json:"partition"`     // Exact native-platform interpretation.
		Qualification string      `json:"qualification"` // Raw diagnostics grant no semantic qualification.
		Files         []inventory `json:"files"`         // All four unit sources, with their original geometry.
		Observed      []string    `json:"observed"`      // Only active nonconstant Boolean roots.
		Typing        typing      `json:"typing"`        // Native source and consumed export identities.
	}
	data, cause := os.ReadFile(filepath.Join(output, "trace.json"))
	if cause != nil || json.Unmarshal(data, &manifest) != nil || manifest.Version != 3 || manifest.Partition != "native-go-files" || manifest.Qualification != "not-evaluated" {
		t.Fatal("platform-partition trace lost its explicit evidence boundary", cause)
	}
	t.Logf("PARTITION-MANIFEST %s", data)
	wanted := []string{"unit/platform_" + runtime.GOOS + ".go", "unit/state.go"}
	if !equalStrings(manifest.Typing.Files, wanted) || len(manifest.Typing.Inactive) != 2 || len(manifest.Files) != 4 || len(manifest.Typing.Constants) != 1 || len(manifest.Typing.Exports) != 1 {
		t.Fatalf("native platform/type/constant/export partition changed: %+v", manifest.Typing)
	}
	active, inactive := map[string]bool{}, map[string]bool{}
	for _, name := range manifest.Typing.Files {
		active[name] = true
	}
	for _, name := range manifest.Typing.Inactive {
		inactive[name] = true
	}
	for _, file := range manifest.Files {
		original, cause := scan(file.File, fixture.files[file.File])
		left, _ := json.Marshal(original)
		right, _ := json.Marshal(file)
		if cause != nil || !bytes.Equal(left, right) || len(file.Decisions) == 0 {
			t.Fatal("platform source denominator was altered", file.File, cause)
		}
		if inactive[file.File] {
			copy, cause := os.ReadFile(filepath.Join(output, filepath.Base(file.File)))
			if cause != nil || !bytes.Equal(copy, fixture.files[file.File]) {
				t.Fatal("inactive source was rewritten", file.File, cause)
			}
			for _, decision := range file.Decisions {
				if manifest.Typing.Results[decision.ID] != "" {
					t.Fatal("inactive source received a type result")
				}
			}
		} else if !active[file.File] {
			t.Fatal("owned source has no platform partition")
		}
	}
	observed := map[string]bool{}
	for _, id := range manifest.Observed {
		if manifest.Typing.Results[id] == "" {
			t.Fatal("untyped or inactive root was selected for execution")
		}
		observed[id] = true
	}
	if len(observed) != len(manifest.Typing.Results) {
		t.Fatal("active runtime root disappeared")
	}
	native := partitionCommand(t, fixture.root, "", "test", "-json", "-count=1", "-p=2", "-parallel=2", "-timeout=60s", "-overlay="+filepath.Join(output, "overlay.json"), "./unit")
	var stream strings.Builder
	for _, line := range bytes.Split(bytes.TrimSpace(native), []byte("\n")) {
		var event struct {
			Action  string // Native go-test event.
			Package string // Exact isolated root-package identity.
			Output  string // Original chunk, including recorder output.
		}
		if json.Unmarshal(line, &event) != nil || event.Package != "fixture/unit" || event.Action == "fail" || event.Action == "skip" {
			t.Fatal("incomplete native overlay execution")
		}
		stream.WriteString(event.Output)
	}
	count := 0
	for _, line := range strings.Split(stream.String(), "\n") {
		if !strings.HasPrefix(line, "GO-DECISIONS ") {
			continue
		}
		var receipt struct {
			Code int `json:"code"` // Completed native fixture status.
			Rows []struct {
				ID   string `json:"id"`   // Original decision identity.
				Hits uint64 `json:"hits"` // Native completed evaluations.
			} `json:"rows"`
		}
		if cause := json.Unmarshal([]byte(strings.TrimPrefix(line, "GO-DECISIONS ")), &receipt); cause != nil || receipt.Code != 0 {
			t.Fatal("invalid partition runtime receipt", cause)
		}
		for _, row := range receipt.Rows {
			if _, selected := observed[row.ID]; !selected || row.Hits == 0 {
				t.Fatal("inactive, constant or unowned execution was fabricated")
			}
			observed[row.ID] = false
		}
		count++
	}
	if count != 1 {
		t.Fatal("missing or duplicate native trace terminal")
	}
	for id, missing := range observed {
		if missing {
			t.Fatal("active fixture decision was not exercised", id)
		}
	}
	for name, before := range fixture.files {
		after, cause := os.ReadFile(filepath.Join(fixture.root, filepath.FromSlash(name)))
		if cause != nil || !bytes.Equal(before, after) {
			t.Fatal("collector modified an original source", name, cause)
		}
	}
}

// equalStrings compares independently prescribed native selections in their canonical order.
func equalStrings(actual, wanted []string) bool {
	if len(actual) != len(wanted) {
		return false
	}
	for index := range wanted {
		if actual[index] != wanted[index] {
			return false
		}
	}
	return true
}

// TestPartitionArguments rejects unsupported mode combinations before exposing a usable overlay.
func TestPartitionArguments(t *testing.T) {
	fixture := newPartitionFixture(t)
	for index, tail := range [][]string{
		{"-partition"}, {"-partition", "-trace", "unit"},
		{"-partition", "-trace", "unit", "-output", filepath.Join(fixture.root, "missing-exports")},
		{"-partition", "-trace", "unit", "-output", filepath.Join(fixture.root, "controls"), "-export", fixture.exports, "-controls"},
	} {
		arguments := append([]string{"-root", fixture.root, "-source", fixture.source}, tail...)
		var out, diagnostics bytes.Buffer
		if cause := run(arguments, &out, &diagnostics); cause == nil || cause.Error() != "trace-arguments" || out.Len() != 0 {
			t.Fatalf("invalid platform-partition mode %d was not explicitly rejected: %v", index, cause)
		}
	}
}
