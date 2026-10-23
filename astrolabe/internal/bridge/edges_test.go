// Verify malformed configuration endings and worker retirement for a valid empty metrics directory.
package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestTargetsClosing refuses truncated or mismatched object endings without publishing parsed prefixes.
func TestTargetsClosing(t *testing.T) {
	for _, input := range []struct {
		name string // Named malformed final delimiter.
		data string // Exact local configuration bytes.
	}{
		{"empty", `{]`},
		{"prefix", `{"127.0.0.1:1":"http://127.0.0.1:2/metrics"]`},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			path := filepath.Join(t.TempDir(), "targets.json")
			check(os.WriteFile(path, []byte(input.data), 0600) == nil, "could not prepare target fixture")
			values, err := Targets(path)
			check(err != nil && values == nil, "bad final delimiter returned a usable metrics target")
		})
	}
}

// TestEmptyMetrics requires the owned workers to drain without manufacturing a sample or observation.
func TestEmptyMetrics(t *testing.T) {
	check := counter(t)
	backend := &Backend{}
	backend.sample(context.Background(), &http.Client{}, map[string]string{})
	data, err := json.Marshal(backend.Metrics())
	check(err == nil && string(data) == `{"samples":[]}`, "empty directory manufactured a metrics result")
	check(backend.metrics == nil && backend.observed.IsZero() && backend.target == nil, "empty sampling changed backend ownership")
}
