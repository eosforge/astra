// Bind optional diagnostic result types to frozen source and the native compiler's export archives.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// exported describes required native go-list facts; other compiler metadata is not application policy.
type exported struct {
	ImportPath     string            // Canonical compiler import identity.
	Dir            string            // Actual selected source directory.
	Name           string            // Package declaration.
	Export         string            // Native gc export archive.
	GoFiles        []string          // Active ordinary implementation sources.
	IgnoredGoFiles []string          // Native inactive platform sources remain in the inventory.
	CgoFiles       []string          // Active cgo implementation sources.
	ImportMap      map[string]string // Native canonicalization of dependency imports.
	Incomplete     bool              // Missing compilation cannot provide typing evidence.
	Error          json.RawMessage   // Native package failure; absent or null only.
	DepsErrors     []json.RawMessage // Failed dependencies must also block.
}

// archive binds one actually consumed compiler export archive.
type archive struct {
	Path   string `json:"path"`   // Canonical absolute compiler cache path.
	SHA256 string `json:"sha256"` // Content read by this type checker.
	Bytes  int    `json:"bytes"`  // Bounded actual archive length.
}

// typing refines existing roots without declaring semantic independence or complete coverage.
type typing struct {
	MetadataSHA256 string             `json:"metadata_sha256"` // Exact original go-list output.
	Package        string             `json:"package"`         // Checked import path.
	Files          []string           `json:"files"`           // All owned selected implementation inputs.
	Inactive       []string           `json:"inactive"`        // Native inactive inputs; v2 requires rootless stubs, v3 retains all geometry.
	Results        map[string]string  `json:"results"`         // Root ID to safe source spelling of Boolean result type.
	Constants      []string           `json:"constants"`       // Standalone constant roots remain unsupported by tracing.
	Exports        map[string]archive `json:"exports"`         // Only archives actually imported by go/types.
	partition      bool               // Explicit CLI mode; the trace format carries its public declaration.
}

// annotate preserves Boolean tracing while sharing the native source/export checks with numerical collection.
func annotate(root, directory string, metadata []byte, collection report) (typing, error) {
	return inspectTypes(root, directory, metadata, collection, false, nil)
}

// inspectTypes validates the complete native selection before exposing typed facts to one collector.
func inspectTypes(root, directory string, metadata []byte, collection report, partition bool, inspect func(*token.FileSet, map[string]*ast.File, *types.Info) error) (typing, error) {
	result := typing{Files: []string{}, Inactive: []string{}, Results: map[string]string{}, Constants: []string{}, Exports: map[string]archive{}, partition: partition}
	digest := sha256.Sum256(metadata)
	result.MetadataSHA256 = hex.EncodeToString(digest[:])
	if len(metadata) == 0 || len(metadata) > 32<<20 {
		return typing{}, errors.New("typing-metadata-size")
	}
	packages := map[string]exported{}
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	for {
		var value exported
		if err := decoder.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return typing{}, err
		}
		if value.ImportPath == "" || value.Name == "" || packages[value.ImportPath].ImportPath != "" || value.Incomplete || len(value.DepsErrors) != 0 || len(value.Error) != 0 && string(value.Error) != "null" {
			return typing{}, errors.New("typing-package-metadata")
		}
		packages[value.ImportPath] = value
		if len(packages) > 4096 {
			return typing{}, errors.New("typing-package-capacity")
		}
	}
	path, err := inside(root, directory)
	if err != nil {
		return typing{}, err
	}
	selected, matches := exported{}, 0
	for _, value := range packages {
		if value.Dir == path {
			selected, matches = value, matches+1
		}
	}
	if matches != 1 || len(selected.CgoFiles) != 0 {
		return typing{}, errors.New("typing-selection-unsupported")
	}
	result.Package = selected.ImportPath
	active := map[string]bool{}
	inactive := map[string]bool{}
	for _, name := range selected.GoFiles {
		if filepath.Base(name) != name || active[name] || !strings.HasSuffix(name, ".go") {
			return typing{}, errors.New("typing-file-selection")
		}
		active[name] = true
	}
	for _, name := range selected.IgnoredGoFiles {
		if filepath.Base(name) != name || inactive[name] || active[name] || !strings.HasSuffix(name, ".go") {
			return typing{}, errors.New("typing-file-selection")
		}
		if !strings.HasSuffix(name, "_test.go") {
			inactive[name] = true
		}
	}
	positions := token.NewFileSet()
	parsed := map[string]*ast.File{}
	files := []*ast.File{}
	for _, item := range collection.Files {
		if filepath.ToSlash(filepath.Dir(item.File)) != directory {
			continue
		}
		name := filepath.Base(item.File)
		if !active[name] && !inactive[name] {
			return typing{}, errors.New("typing-inactive-source")
		}
		data, err := read(filepath.Join(root, filepath.FromSlash(item.File)), 32<<20)
		if err != nil {
			return typing{}, err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != item.SHA256 {
			return typing{}, errors.New("typing-source-drift")
		}
		file, err := parser.ParseFile(positions, item.File, data, parser.AllErrors)
		if err != nil || file.Name.Name != selected.Name {
			return typing{}, errors.New("typing-source-package")
		}
		if inactive[name] {
			if !partition && (len(item.Decisions) != 0 || len(item.Controls) != 0) {
				return typing{}, errors.New("typing-inactive-decisions")
			}
			delete(inactive, name)
			result.Inactive = append(result.Inactive, item.File)
			continue
		}
		delete(active, name)
		parsed[item.File], files = file, append(files, file)
		result.Files = append(result.Files, item.File)
	}
	if len(files) == 0 || len(active) != 0 || len(inactive) != 0 {
		return typing{}, errors.New("typing-denominator")
	}
	total := 0
	loader := importer.ForCompiler(positions, "gc", func(name string) (io.ReadCloser, error) {
		if canonical := selected.ImportMap[name]; canonical != "" {
			name = canonical
		}
		value, ok := packages[name]
		if !ok || value.Export == "" || !filepath.IsAbs(value.Export) || filepath.Clean(value.Export) != value.Export {
			return nil, errors.New("typing-export-missing: " + name)
		}
		relative, err := filepath.Rel(filepath.Join(root, "build", "cache", "go"), value.Export)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, errors.New("typing-export-outside-cache")
		}
		data, err := read(value.Export, 64<<20)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > 256<<20 {
			return nil, errors.New("typing-export-budget")
		}
		digest := sha256.Sum256(data)
		bound := archive{Path: value.Export, SHA256: hex.EncodeToString(digest[:]), Bytes: len(data)}
		if previous, exists := result.Exports[name]; exists && previous != bound {
			return nil, errors.New("typing-export-drift")
		}
		result.Exports[name] = bound
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}}
	checker := types.Config{Importer: loader, Sizes: types.SizesFor("gc", runtime.GOARCH)}
	checked, err := checker.Check(selected.ImportPath, positions, files, info)
	if err != nil {
		return typing{}, fmt.Errorf("typing-check: %w", err)
	}
	if inspect != nil {
		if err := inspect(positions, parsed, info); err != nil {
			return typing{}, err
		}
		sort.Strings(result.Files)
		sort.Strings(result.Inactive)
		return result, nil
	}
	// Generated helpers use builtin bool. A source declaration may not silently change that spelling.
	for identifier, object := range info.Defs {
		if identifier.Name == "bool" && object != nil {
			return typing{}, errors.New("typing-builtin-shadow")
		}
	}
	for _, item := range collection.Files {
		file := parsed[item.File]
		if file == nil {
			continue
		}
		aliases := map[string]string{}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return typing{}, err
			}
			if canonical := selected.ImportMap[path]; canonical != "" {
				path = canonical
			}
			name := packages[path].Name
			if imported.Name != nil {
				name = imported.Name.Name
			}
			if name == "" || aliases[path] != "" {
				return typing{}, errors.New("typing-import-alias")
			}
			aliases[path] = name
		}
		expressions := map[int]ast.Expr{}
		ast.Inspect(file, func(node ast.Node) bool {
			if value, ok := node.(ast.Expr); ok {
				offset := positions.PositionFor(value.Pos(), false).Offset
				if previous := expressions[offset]; previous == nil || value.End() > previous.End() {
					expressions[offset] = value
				}
			}
			return true
		})
		for _, decision := range item.Decisions {
			expression := expressions[decision.Begin.Offset]
			value, ok := info.Types[expression]
			if expression == nil || !ok || positions.PositionFor(expression.End(), false).Offset != decision.End.Offset || value.Type == nil {
				return typing{}, errors.New("typing-root-unresolved")
			}
			basic, ok := value.Type.Underlying().(*types.Basic)
			if !ok || basic.Info()&types.IsBoolean == 0 {
				return typing{}, errors.New("typing-root-not-boolean")
			}
			if decision.Kind == "boolean" && value.Value != nil {
				result.Constants = append(result.Constants, decision.ID)
				continue
			}
			resolved := value.Type
			if basic.Kind() == types.UntypedBool {
				resolved = types.Typ[types.Bool]
			}
			missing := false
			spelling := types.TypeString(resolved, func(imported *types.Package) string {
				if imported == checked {
					return ""
				}
				name := aliases[imported.Path()]
				if name == "." {
					return ""
				}
				if name == "" || name == "_" {
					missing = true
				}
				return name
			})
			if missing {
				return typing{}, errors.New("typing-result-spelling")
			}
			result.Results[decision.ID] = spelling
		}
	}
	sort.Strings(result.Files)
	sort.Strings(result.Inactive)
	sort.Strings(result.Constants)
	return result, nil
}

// readExports accepts only a canonical metadata file, never a shell command or executable package generator.
func readExports(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("typing-metadata-path")
	}
	return read(path, 32<<20)
}
