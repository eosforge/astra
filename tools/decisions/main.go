// Read a frozen source manifest and emit a syntactic Go decision inventory using only the standard library.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// input identifies actual registered bytes; deleted files retain a nil digest.
type input struct {
	Path   string  `json:"path"`   // Canonical root-relative Git input.
	SHA256 *string `json:"sha256"` // Exact source digest, or nil for a deletion.
}

// source matches the collector's complete workspace identity without ignoring index/dirty state.
type source struct {
	Commit *string `json:"commit"` // An isolated mirror may have no commit.
	Status string  `json:"status"` // Actual native Git status retained in the bound manifest.
	Files  []input `json:"files"`  // Registered tracked and untracked inputs.
}

// report distinguishes a complete syntactic collection from semantic qualification and omitted input kinds.
type report struct {
	Version       int         `json:"version"`       // Native report format.
	SourceSHA256  string      `json:"source_sha256"` // Digest of the manifest actually consumed.
	Qualification string      `json:"qualification"` // Always not-evaluated; no observed coverage is collected here.
	Basis         string      `json:"basis"`         // Explicit syntax limits; named bool aliases need typed follow-up.
	Files         []inventory `json:"files"`         // Every owned Go implementation, including inactive platform files.
	Generated     []string    `json:"generated"`     // Generated marker inputs remain separately visible.
	Tests         []string    `json:"tests"`         // Native _test.go inputs remain separately visible.
}

// read enforces the declared byte budget without allocating an unbounded external file.
func read(path string, maximum int64) ([]byte, error) {
	stream, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, maximum+1))
	if err == nil && int64(len(data)) > maximum {
		err = errors.New("input-size")
	}
	return data, err
}

// shape rejects duplicate JSON keys and excessive nesting before typed manifest decoding.
func shape(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("json-depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	keys := map[string]bool{}
	if delimiter != '{' && delimiter != '[' {
		return errors.New("json-shape")
	}
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("duplicate-key")
			}
			keys[name] = true
		}
		if err := shape(decoder, depth+1); err != nil {
			return err
		}
	}
	last, err := decoder.Token()
	if err != nil {
		return err
	}
	if last != json.Delim('}') && delimiter == '{' || last != json.Delim(']') && delimiter == '[' {
		return errors.New("json-shape")
	}
	return nil
}

// decode rejects unknown and missing identity fields in addition to malformed or duplicate JSON.
func decode(data []byte) (source, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := shape(decoder, 0); err != nil {
		return source{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return source{}, errors.New("json-trailing")
	}
	var required map[string]json.RawMessage
	if err := json.Unmarshal(data, &required); err != nil || len(required) != 3 || required["commit"] == nil || required["status"] == nil || required["files"] == nil {
		return source{}, errors.New("source-fields")
	}
	var result source
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return source{}, err
	}
	if len(result.Files) == 0 {
		return source{}, errors.New("source-empty")
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(required["files"], &files); err != nil {
		return source{}, err
	}
	for _, item := range files {
		if len(item) != 2 || item["path"] == nil || item["sha256"] == nil {
			return source{}, errors.New("source-file-fields")
		}
	}
	return result, nil
}

// inside rejects path traversal, aliases and symlink components before consuming registered source bytes.
func inside(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\:") || strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", errors.New("path-invalid")
	}
	current := root
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("path-invalid")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("path-symlink")
		}
	}
	return current, nil
}

// collect verifies every input identity before parsing; no test execution or dependency import is needed.
func collect(root string, data []byte) (report, error) {
	manifest, err := decode(data)
	if err != nil {
		return report{}, err
	}
	digest := sha256.Sum256(data)
	result := report{Version: 1, SourceSHA256: hex.EncodeToString(digest[:]), Qualification: "not-evaluated", Files: []inventory{}, Generated: []string{}, Tests: []string{},
		Basis: "Syntactic if/for/case, comparisons/logical operators and literal-bool returns; tagged/type switches, select/range, unconditional loops, go/defer remain separate. Named bool aliases and simple Boolean values outside these roots require typed follow-up. No execution or MC/DC claim."}
	marker := regexp.MustCompile(`(?m)^// Code generated [^\r\n]+ DO NOT EDIT\.\r?$`)
	packageLine := regexp.MustCompile(`(?m)^package[ \t]`)
	seen := map[string]bool{}
	for _, item := range manifest.Files {
		if seen[item.Path] || item.Path == "" {
			return report{}, errors.New("source-duplicate")
		}
		seen[item.Path] = true
		if !strings.HasSuffix(item.Path, ".go") || item.SHA256 == nil {
			continue
		}
		path, err := inside(root, item.Path)
		if err != nil {
			return report{}, err
		}
		original, err := read(path, 32<<20)
		if err != nil {
			return report{}, err
		}
		actual := sha256.Sum256(original)
		if hex.EncodeToString(actual[:]) != *item.SHA256 {
			return report{}, errors.New("source-drift: " + item.Path)
		}
		prefix := original
		if declaration := packageLine.FindIndex(original); declaration != nil {
			prefix = original[:declaration[0]]
		}
		if strings.HasSuffix(item.Path, "_test.go") {
			result.Tests = append(result.Tests, item.Path)
		} else if marker.Match(prefix) {
			result.Generated = append(result.Generated, item.Path)
		} else {
			value, err := scan(item.Path, original)
			if err != nil {
				return report{}, err
			}
			result.Files = append(result.Files, value)
		}
	}
	if len(result.Files) == 0 {
		return report{}, errors.New("go-source-empty")
	}
	sort.Slice(result.Files, func(left, right int) bool { return result.Files[left].File < result.Files[right].File })
	sort.Strings(result.Generated)
	sort.Strings(result.Tests)
	return result, nil
}

// run validates explicit paths and emits native JSON; commands never mutate the parsed source tree.
func run(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("decisions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "Absolute frozen source root")
	manifest := flags.String("source", "", "Bound collector source manifest")
	packagePath := flags.String("trace", "", "Optional root-relative package for an isolated diagnostic overlay")
	destination := flags.String("output", "", "Fresh absolute overlay directory; requires -trace")
	exports := flags.String("export", "", "Optional native offline go-list metadata for a typed trace; requires -trace")
	controls := flags.Bool("controls", false, "Observe loops/select arms instead of Boolean roots; requires -trace and forbids -export")
	partition := flags.Bool("partition", false, "Retain inactive platform decisions in a v3 typed Boolean trace; requires -trace and -export")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if len(flags.Args()) != 0 || !filepath.IsAbs(*root) || !filepath.IsAbs(*manifest) || filepath.Clean(*root) != *root {
		return errors.New("arguments-invalid")
	}
	actual, err := filepath.EvalSymlinks(*root)
	if err != nil || actual != *root {
		return errors.New("root-identity")
	}
	data, err := read(*manifest, 8<<20)
	if err != nil {
		return err
	}
	result, err := collect(*root, data)
	if err != nil {
		return err
	}
	if *packagePath != "" || *destination != "" || *exports != "" || *controls || *partition {
		if *packagePath == "" || *destination == "" || *controls && *exports != "" || *partition && (*exports == "" || *controls) {
			return errors.New("trace-arguments")
		}
		var annotations *typing
		if *exports != "" {
			metadata, err := readExports(*exports)
			if err != nil {
				return err
			}
			checked, err := inspectTypes(*root, *packagePath, metadata, result, *partition, nil)
			if err != nil {
				return err
			}
			annotations = &checked
		}
		if err := prepareTrace(*root, *packagePath, *destination, result, annotations, *controls); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

// main exposes only explicit read/parse operations; native failure cannot produce a partial success report.
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
