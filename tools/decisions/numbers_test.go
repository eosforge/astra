// Challenge numerical enumeration independently and retain the complete native Storage compiler boundary.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNumbers checks operation classes, byte positions, named ownership, determinism and labels without numerical types.
func TestNumbers(t *testing.T) {
	input := `package main
// Unicode does not change the collector's byte coordinates: λ.
type Count uint64
var total Count
func compute(values []int) int {
 result := 0
 for index, value := range values {
  result += value
  values[index]++
  if index > 0 { result-- }
 }
 _ = values[1:]
 return result + int(total)
}
`
	root, collection, metadata := typedFixture(t, input)
	actual, err := numbers(root, "unit", metadata, collection)
	if err != nil || actual.Scanned == 0 || len(actual.Nodes) == 0 || actual.Qualification != "not-evaluated" {
		t.Fatalf("native numeric fixture failed: %+v %v", actual, err)
	}
	wanted := map[string]bool{"assignment:+=": false, "increment:++": false, "increment:--": false, "range": false, "slice": false, "comparison": false}
	for _, row := range actual.Nodes {
		if row.Begin < 0 || row.End <= row.Begin || row.End > len(input) || row.Text != input[row.Begin:row.End] || row.File != "unit/state.go" {
			t.Fatalf("source coordinates changed: %+v", row)
		}
		if row.Scope != "<package>" && row.Scope != "compute" {
			t.Fatalf("numeric owner lost: %+v", row)
		}
		if _, ok := wanted[row.Kind]; ok {
			wanted[row.Kind] = true
		}
	}
	for kind, present := range wanted {
		if !present {
			t.Fatalf("implicit numeric operation omitted: %s", kind)
		}
	}
	first, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		second, err := numbers(root, "unit", metadata, collection)
		encoded, encoding := json.Marshal(second)
		if err != nil || encoding != nil || string(first) != string(encoded) {
			t.Fatal("numeric enumeration depends on map iteration", err, encoding)
		}
	}
	// Labels deliberately have no Go type and must not cause a nil-type panic or a numerical finding.
	plain := "package main\nfunc empty(value bool) { label: for value { break label } }\n"
	root, collection, metadata = typedFixture(t, plain)
	if actual, err := numbers(root, "unit", metadata, collection); err != nil || actual.Scanned == 0 || len(actual.Nodes) != 0 {
		t.Fatalf("non-numeric labels rejected: %+v %v", actual, err)
	}
}

// TestNumberControls supplies valid independent integer, floating, complex and implicit-use counterexamples.
func TestNumberControls(t *testing.T) {
	controls := []string{
		"var value uint64",
		"var value *int",
		"var value [1]string",
		"var value map[int]string",
		"type Count = rune",
		"type Count uint64",
		"const value uint64 = 18446744073709551615",
		"const value int64 = -9223372036854775808",
		"const value = 1e300",
		"const value = 1i",
		"func call(value string) int { return len(value) }",
		"func call(value []string) { for index := range value { _ = index } }",
		"func call(value string) float64 { return float64(len(value)) }",
		"func call(value string) { count := len(value); count /= 1 }",
		"var value = complex(1.0, 2.0)",
		"func call(value string) uintptr { return uintptr(len(value)) }",
		"func call(value string) uint8 { return uint8(len(value)) }",
		"const (first = iota; second)",
		"func call(value []string) string { return value[0] }",
		"func call(value []string) []string { return value[1:] }",
		"func call(value int) bool { return value > 0 }",
		"func call(value int) { value++; value-- }",
		"func call(value int) int { return value & 7 }",
	}
	for index, input := range controls {
		root, collection, metadata := typedFixture(t, "package main\n"+input+"\n")
		actual, err := numbers(root, "unit", metadata, collection)
		if err != nil || actual.Scanned == 0 || len(actual.Nodes) == 0 {
			t.Fatalf("valid numerical counterexample %d escaped: %+v %v", index, actual, err)
		}
		t.Logf("NUMERIC-CONTROL %d nodes=%d", index, len(actual.Nodes))
	}
	root, collection, metadata := typedFixture(t, "package main\nfunc call(value string) string { return value + \"\" }\n")
	if actual, err := numbers(root, "unit", metadata, collection); err != nil || actual.Scanned == 0 || len(actual.Nodes) != 0 {
		t.Fatalf("plain string wrongly classified: %+v %v", actual, err)
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"STORAGE-NUMERIC-CONTROLS","hits":%d}`, len(controls)+1)
}

// TestStorageNumbers uses actual offline compiler exports; no mock declarations replace dependency APIs.
func TestStorageNumbers(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Storage numerical qualification requires Linux/amd64/cgo")
	}
	if os.Getenv("CGO_ENABLED") != "1" || os.Getenv("GOPROXY") != "off" || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Fatal("native offline cgo environment missing")
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("native collector source location missing")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "../.."))
	directory := "polaris/internal/storage"
	entries, err := os.ReadDir(filepath.Join(root, directory))
	if err != nil {
		t.Fatal(err)
	}
	manifest := source{Files: []input{}}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		name := directory + "/" + entry.Name()
		path, err := inside(root, name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := read(path, 32<<20)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		text := hex.EncodeToString(digest[:])
		manifest.Files = append(manifest.Files, input{name, &text})
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := collect(root, data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-p=2", "-deps", "-export", "-json", "./"+directory)
	command.Dir = root
	metadata, err := command.Output()
	if err != nil {
		t.Fatal("native export collection failed", err)
	}
	actual, err := numbers(root, directory, metadata, collection)
	if err != nil || actual.Scanned == 0 || len(actual.Nodes) == 0 || actual.Typing.Package != "github.com/eosforge/astra/"+directory || len(actual.Typing.Exports) == 0 {
		t.Fatalf("native Storage numeric inventory failed: %+v %v", actual, err)
	}
	header := map[string]any{"kind": "header", "version": actual.Version, "source": manifest, "source_sha256": actual.SourceSHA256, "os": actual.OS, "architecture": actual.Architecture, "runtime": actual.Runtime, "typing": actual.Typing, "scanned": actual.Scanned, "nodes": len(actual.Nodes), "qualification": actual.Qualification}
	encoded, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("STORAGE-NUMERIC-SOURCE %s", encoded)
	// Bound each line below the Go JSON transport's split threshold and retain original metadata for independent parsing.
	for offset, index := 0, 0; offset < len(metadata); offset, index = offset+4096, index+1 {
		encoded, err := json.Marshal(map[string]any{"kind": "metadata", "index": index, "data": base64.StdEncoding.EncodeToString(metadata[offset:min(offset+4096, len(metadata))])})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("STORAGE-NUMERIC-SOURCE %s", encoded)
	}
	for index, row := range actual.Nodes {
		encoded, err := json.Marshal(map[string]any{"kind": "node", "index": index, "value": row})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("STORAGE-NUMERIC-SOURCE %s", encoded)
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"STORAGE-NUMERIC-SOURCE","hits":%d}`, len(actual.Nodes))
}
