package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func stores(t *testing.T) map[string]Storage {
	t.Helper()
	return map[string]Storage{"memory": MemoryStorage(), "file": FileStorage(t.TempDir())}
}

func TestStorageContract(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Get("acme/cert/a.example.com"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("missing key: %v", err)
			}
			if err := s.Delete("missing/key"); err != nil {
				t.Fatal(err)
			}
			input := []byte("certificate")
			if err := s.Put("acme/cert/a.example.com", input); err != nil {
				t.Fatal(err)
			}
			input[0] = 'X'
			got, err := s.Get("acme/cert/a.example.com")
			if err != nil || string(got) != "certificate" {
				t.Fatalf("get = %q, %v", got, err)
			}
			got[0] = 'X'
			got, err = s.Get("acme/cert/a.example.com")
			if err != nil || string(got) != "certificate" {
				t.Fatalf("alias: %q, %v", got, err)
			}
			if err := s.Put("acme/cert/a.example.com", []byte("replacement")); err != nil {
				t.Fatal(err)
			}
			got, err = s.Get("acme/cert/a.example.com")
			if err != nil || string(got) != "replacement" {
				t.Fatalf("replace: %q, %v", got, err)
			}
			if err := s.Put("empty", nil); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Get("empty"); err != nil || len(got) != 0 {
				t.Fatalf("empty: %q, %v", got, err)
			}
			if err := s.Delete("acme/cert/a.example.com"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get("acme/cert/a.example.com"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("deleted: %v", err)
			}
		})
	}
}

func TestStorageInvalidKeys(t *testing.T) {
	keys := []string{"", "/absolute", "../escape", "a/../b", "a/./b", "a//b", "a/", "a\\b", "a\x00b", "a b", "a:stream", strings.Repeat("a", 256)}
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			for _, key := range keys {
				if _, err := s.Get(key); err == nil {
					t.Errorf("Get accepted %q", key)
				}
				if err := s.Put(key, nil); err == nil {
					t.Errorf("Put accepted %q", key)
				}
				if err := s.Delete(key); err == nil {
					t.Errorf("Delete accepted %q", key)
				}
			}
		})
	}
}

func TestStorageConcurrentAtomicValues(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			for i := range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					value := bytes.Repeat([]byte{byte(i)}, 2048)
					for range 15 {
						if err := s.Put("shared", value); err != nil {
							t.Error(err)
							return
						}
						got, err := s.Get("shared")
						if err != nil {
							t.Error(err)
							return
						}
						if len(got) != len(value) || !bytes.Equal(got, bytes.Repeat(got[:1], len(got))) {
							t.Error("torn value")
							return
						}
						key := fmt.Sprintf("worker/%d", i)
						if err := s.Put(key, value); err != nil {
							t.Error(err)
							return
						}
						if err := s.Delete(key); err != nil {
							t.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestFileStoragePersistenceAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	s := FileStorage(dir)
	if err := s.Put("creds/privkey", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	got, err := FileStorage(dir).Get("creds/privkey")
	if err != nil || string(got) != "secret" {
		t.Fatalf("reopen: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		for name, want := range map[string]fs.FileMode{dir: 0700, filepath.Join(dir, "creds"): 0700, filepath.Join(dir, "creds", "privkey"): 0600} {
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s: mode %o want %o", name, info.Mode().Perm(), want)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "creds"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file leak: %v %v", entries, err)
	}
}

func TestFileStorageSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink setup requires privileges on Windows")
	}
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	s := FileStorage(dir)
	if _, err := s.Get("escape/victim"); err == nil {
		t.Fatal("read escaped root")
	}
	if err := s.Put("escape/victim", []byte("changed")); err == nil {
		t.Fatal("write escaped root")
	}
	if err := s.Delete("escape/victim"); err == nil {
		t.Fatal("delete escaped root")
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("outside changed: %q %v", got, err)
	}
}

func TestFileStorageBadDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", filepath.Join(file, "child")} {
		s := FileStorage(dir)
		if _, err := s.Get("key"); err == nil {
			t.Fatal("Get accepted bad dir")
		}
		if err := s.Put("key", nil); err == nil {
			t.Fatal("Put accepted bad dir")
		}
		if err := s.Delete("key"); err == nil {
			t.Fatal("Delete accepted bad dir")
		}
	}
}
