// Exercise deployment-path substitution at the actual inspect/open boundary without racing a scheduler.
package admission

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLoadReplacement rejects a different inode before reading, then permits the restored material.
func TestLoadReplacement(t *testing.T) {
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "admission.pub", "login.json"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t, "ADMISSION-IDENTITY-FAULT")
			directory := material(t)
			path := filepath.Join(directory, name)
			original, err := os.ReadFile(path)
			check(err == nil, "could not read replacement fixture")
			held := path + ".held"
			var stream *opened
			open := func(current string) (file, error) {
				if current != path {
					return Acquire(current)
				}
				if err := os.Rename(path, held); err != nil {
					return nil, err
				}
				if err := os.WriteFile(path, original, 0600); err != nil {
					return nil, err
				}
				input, err := Acquire(path)
				if err != nil {
					return nil, err
				}
				stream = &opened{file: input}
				t.Cleanup(func() { _ = input.Close() })
				return stream, nil
			}
			value, err := load(directory, "127.0.0.1:7443", os.Lstat, open)
			check(errors.Is(err, ErrIdentity) && value == nil, "replacement material published an identity")
			check(stream != nil && stream.stats == 1 && stream.reads == 0 && stream.closes == 1, "replacement was read or retained")
			_, err = stream.file.Stat()
			check(errors.Is(err, os.ErrClosed), "replacement handle remains open")
			check(os.Remove(path) == nil && os.Rename(held, path) == nil, "could not restore deployment fixture")
			value, err = Load(directory, "127.0.0.1:7443")
			check(err == nil && value != nil, "restored material did not recover")
		})
	}
}

// TestOpen keeps symlink refusal and nonblocking FIFO acquisition at the native Linux boundary.
func TestOpen(t *testing.T) {
	check := counter(t, "ADMISSION-IDENTITY-FILES")
	directory := t.TempDir()
	path := filepath.Join(directory, "material")
	check(os.WriteFile(path, []byte("fixture"), 0600) == nil, "could not prepare regular material")
	link := filepath.Join(directory, "link")
	check(os.Symlink(path, link) == nil, "could not prepare final symlink")
	input, err := Acquire(link)
	if input != nil {
		_ = input.Close()
	}
	check(err != nil && input == nil, "acquisition followed a final symlink")
	fifo := filepath.Join(directory, "fifo")
	check(syscall.Mkfifo(fifo, 0600) == nil, "could not prepare FIFO")
	input, err = Acquire(fifo)
	check(err == nil && input != nil, "nonblocking candidate acquisition failed")
	t.Cleanup(func() { _ = input.Close() })
	info, err := input.Stat()
	check(err == nil && info.Mode()&os.ModeNamedPipe != 0, "FIFO identity changed")
	check(input.Close() == nil, "candidate handle did not close")
}
