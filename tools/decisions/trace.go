// Prepare isolated Boolean trace overlays; never change production source or claim coverage qualification.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// insertion wraps an original byte span without moving expressions or evaluating skipped operands.
type insertion struct {
	begin, end int    // Half-open original source interval.
	order      int    // Equal spans put a decision outside its atom.
	prefix     string // Opening source fragment.
	suffix     string // Closing source fragment.
}

// instrument observes Boolean control roots and literal-bool returns, keeping other decisions in the inventory.
// Its extra calls/allocations preclude timing, allocation-failure and native weak-memory qualification.
func instrument(name string, data []byte) ([]byte, []string, error) {
	return rewrite(name, data, nil)
}

// rewrite uses checked result types when supplied, while the original syntax-only mode stays explicit.
func rewrite(name string, data []byte, annotations map[string]string) ([]byte, []string, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, data, parser.AllErrors)
	if err != nil {
		return nil, nil, err
	}
	// Reserved identifiers are unsafe anywhere; recover is unsafe only inside a wrapped expression.
	unsafe := false
	recoveries := []int{}
	ast.Inspect(file, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok {
			unsafe = unsafe || strings.HasPrefix(id.Name, "astraProbe")
			if id.Name == "recover" {
				recoveries = append(recoveries, positions.PositionFor(id.Pos(), false).Offset)
			}
		}
		return true
	})
	if unsafe {
		return nil, nil, errors.New("trace-reserved-or-recover")
	}
	inventory, err := scan(name, data)
	if err != nil {
		return nil, nil, err
	}
	wraps, observed := []insertion{}, []string{}
	for number, item := range inventory.Decisions {
		spelling := "bool"
		if annotations != nil {
			spelling = annotations[item.ID]
			if spelling == "" {
				if item.Kind != "boolean" {
					return nil, nil, errors.New("trace-missing-result-type")
				}
				continue // Standalone constant roots stay visible but cannot accept runtime calls.
			}
		} else if item.Kind == "boolean" {
			continue // These roots need type/constant-context analysis before rewriting.
		}
		// An added closure cannot surround recover: it would no longer be called directly by its original deferred function.
		for _, offset := range recoveries {
			if item.Begin.Offset <= offset && offset < item.End.Offset {
				return nil, nil, errors.New("trace-reserved-or-recover")
			}
		}
		if len(item.Atoms) > 64 {
			return nil, nil, errors.New("trace-atom-capacity")
		}
		state, result := fmt.Sprintf("astraProbeValues%d", number), fmt.Sprintf("astraProbeResult%d", number)
		wraps = append(wraps, insertion{item.Begin.Offset, item.End.Offset, 0,
			fmt.Sprintf("func() %s { var %s [%d]byte; %s := bool(", spelling, state, len(item.Atoms), result),
			fmt.Sprintf("); astraProbeRecord(%s, %s[:], %s); return %s(%s) }()", strconv.Quote(item.ID), state, result, spelling, result)})
		for index, atom := range item.Atoms {
			wraps = append(wraps, insertion{atom.Begin.Offset, atom.End.Offset, 1,
				fmt.Sprintf("astraProbeAtom(&%s[%d], (", state, index), "))"})
		}
		observed = append(observed, item.ID)
	}
	// Parsed expression spans are nested or disjoint. Reject crossings instead of guessing insertion precedence.
	sort.Slice(wraps, func(a, b int) bool {
		left, right := wraps[a], wraps[b]
		if left.begin != right.begin {
			return left.begin < right.begin
		}
		if left.end != right.end {
			return left.end > right.end
		}
		return left.order < right.order
	})
	var output bytes.Buffer
	stack, cursor := []insertion{}, 0
	for _, item := range wraps {
		for len(stack) != 0 && stack[len(stack)-1].end <= item.begin {
			last := stack[len(stack)-1]
			output.Write(data[cursor:last.end])
			output.WriteString(last.suffix)
			cursor, stack = last.end, stack[:len(stack)-1]
		}
		if item.begin < cursor || item.end > len(data) || len(stack) != 0 && item.end > stack[len(stack)-1].end {
			return nil, nil, errors.New("trace-crossing-span")
		}
		output.Write(data[cursor:item.begin])
		output.WriteString(item.prefix)
		cursor, stack = item.begin, append(stack, item)
	}
	for len(stack) != 0 {
		last := stack[len(stack)-1]
		output.Write(data[cursor:last.end])
		output.WriteString(last.suffix)
		cursor, stack = last.end, stack[:len(stack)-1]
	}
	output.Write(data[cursor:])
	formatted, err := format.Source(output.Bytes())
	return formatted, observed, err
}

// trace prepares a fresh Go overlay and an explicit denominator from already verified source inputs.
func trace(root, directory, destination string, collection report) error {
	return typedTrace(root, directory, destination, collection, nil)
}

// typedTrace records explicit typing evidence without upgrading diagnostic observations to qualification.
func typedTrace(root, directory, destination string, collection report, annotations *typing) error {
	return prepareTrace(root, directory, destination, collection, annotations, false)
}

// prepareTrace shares source/overlay ownership while keeping Boolean and control-flow evidence distinct.
func prepareTrace(root, directory, destination string, collection report, annotations *typing, controls bool) error {
	if controls && annotations != nil {
		return errors.New("trace-mixed-controls")
	}
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("trace-output-invalid")
	}
	path, err := inside(root, directory)
	if err != nil {
		return err
	}
	// The generated TestMain owns terminal emission. Existing harnesses require an explicit integration instead.
	for _, name := range collection.Tests {
		if filepath.ToSlash(filepath.Dir(name)) != directory {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, data, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "TestMain" {
				return errors.New("trace-existing-main")
			}
		}
	}
	files, replacements, observed := map[string][]byte{}, map[string]string{}, []string{}
	selected, packageName := []inventory{}, ""
	edges := []edge{}
	inactive := map[string]bool{}
	if annotations != nil && annotations.partition {
		for _, name := range annotations.Inactive {
			inactive[name] = true
		}
	}
	for _, item := range collection.Files {
		if filepath.ToSlash(filepath.Dir(item.File)) != directory {
			continue
		}
		input := filepath.Join(root, filepath.FromSlash(item.File))
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != item.SHA256 {
			return errors.New("trace-source-drift")
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), item.File, data, parser.PackageClauseOnly)
		if err != nil || packageName != "" && packageName != parsed.Name.Name {
			return errors.New("trace-package-mismatch")
		}
		packageName = parsed.Name.Name
		var checked map[string]string
		if annotations != nil {
			checked = annotations.Results
		}
		var value []byte
		var ids []string
		if inactive[item.File] {
			value = data // Retain byte-exact inactive sources without typed runtime rewriting.
		} else if controls {
			var items []edge
			value, items, err = flow(item.File, data)
			for _, item := range items {
				ids = append(ids, item.ID)
			}
			edges = append(edges, items...)
		} else {
			value, ids, err = rewrite(item.File, data, checked)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", item.File, err)
		}
		files[filepath.Base(input)] = value
		replacements[input] = filepath.Join(destination, filepath.Base(input))
		observed = append(observed, ids...)
		selected = append(selected, item)
	}
	if len(selected) == 0 || len(observed) == 0 {
		return errors.New("trace-empty")
	}
	runtime := traceRuntime
	if controls {
		runtime = strings.Replace(runtime, "GO-DECISIONS", "GO-CONTROLS", 1)
	}
	for name, source := range map[string]string{"zz_astra_probe.go": strings.Replace(runtime, "package probe", "", 1), "zz_astra_probe_test.go": traceMain} {
		input := filepath.Join(path, name)
		if _, err := os.Lstat(input); !errors.Is(err, os.ErrNotExist) {
			return errors.New("trace-helper-exists")
		}
		value, err := format.Source([]byte("package " + packageName + "\n" + source))
		if err != nil {
			return err
		}
		files[name], replacements[input] = value, filepath.Join(destination, name)
	}
	// Write the usable overlay last; an interrupted generation cannot masquerade as a complete overlay.
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(destination, name), value, 0600); err != nil {
			return err
		}
	}
	manifest := map[string]any{"version": 1, "source_sha256": collection.SourceSHA256, "qualification": "not-evaluated", "files": selected, "observed": observed,
		"basis": "Control roots and literal-bool returns only; standalone Boolean expressions and non-Boolean controls remain unqualified. Values: 0=not evaluated, 1=false, 2=true. Added calls, allocations and locking change schedules. Killed children emit no terminal trace; no timing, allocation-fault, native-race or MC/DC qualification."}
	if annotations != nil {
		manifest["version"], manifest["typing"] = 2, annotations
		manifest["basis"] = "Type-checked runtime roots of the unchanged syntactic inventory; constant standalone roots and other controls remain explicit. Values: 0=not evaluated, 1=false, 2=true. Instrumentation changes schedules; no native race, timing, allocation-fault or MC/DC qualification."
		if annotations.partition {
			manifest["version"], manifest["partition"] = 3, "native-go-files"
			manifest["basis"] = "Native compiler selection partitions the complete unchanged syntactic inventory. Only active runtime roots receive types and observations; inactive source bytes, decisions and controls remain explicit without execution credit. Constants remain uninstrumented. Values: 0=not evaluated, 1=false, 2=true. No native race, timing, allocation-fault, cross-platform exclusion or MC/DC qualification."
		}
	}
	filename := "trace.json"
	if controls {
		filename = "flow.json"
		manifest["edges"] = edges
		manifest["basis"] = "Loop vectors record body entry and exhaustion (1=no, 2=yes); unlabeled break is not exhaustion. Select and explicit switch/type-switch arms record 2/true. Labels, fallthrough and implicit switch defaults are unsupported. Diagnostic defers, calls and locking alter scheduling/resources. No Boolean, timing, allocation-fault, native-race or MC/DC qualification."
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(destination, filename), data, 0600); err != nil {
		return err
	}
	data, err = json.Marshal(map[string]any{"Replace": replacements})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destination, "overlay.json"), data, 0600)
}

// traceRuntime is test-overlay-only code with bounded, synchronized state and exact per-invocation vectors.
//
//go:embed runtime.go.in
var traceRuntime string

// traceMain emits after native tests and cleanups; killed or prematurely exiting children have no receipt.
const traceMain = `
import ("os"; "testing")
// TestMain binds the trace to the actual native test exit, including failed tests.
func TestMain(m *testing.M) { code:=m.Run(); astraProbeFinish(code); os.Exit(code) }
`
