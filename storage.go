package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
)

// Storage stores private credentials and ACME state. Get must return an error
// wrapping fs.ErrNotExist for absent keys. Delete is idempotent. Put replaces
// a value atomically. Implementations must support concurrent callers and must
// not retain or expose mutable aliases to the supplied/returned byte slices.
// There is no compare-and-swap: initialize an identity before sharing its store
// between processes. Treat all stored data as secret.
type Storage interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

func validateKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00") {
		return fmt.Errorf("invalid storage key %q", key)
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return fmt.Errorf("invalid storage key %q", key)
		}
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("._-", c) {
				return fmt.Errorf("invalid storage key %q", key)
			}
		}
	}
	return nil
}

// MemoryStorage returns an independent, concurrency-safe, non-durable store.
func MemoryStorage() Storage { return &memoryStorage{values: make(map[string][]byte)} }

type memoryStorage struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func (s *memoryStorage) Get(key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[key]
	if !ok {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
	}
	return append([]byte{}, value...), nil
}

func (s *memoryStorage) Put(key string, value []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = append([]byte{}, value...)
	return nil
}

func (s *memoryStorage) Delete(key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

// FileStorage returns a store rooted at dir. Initialization errors are reported
// by the first operation, preserving the brief's FileStorage(dir) Storage API.
// New directories use 0700 and value files use 0600. Existing directory modes
// are not changed; callers must choose a private, trusted directory. Writes
// sync a temporary file, rename it atomically, then sync its parent directory.
// A sync failure can occur after a replacement has already become visible.
// Symlink traversal cannot escape the root (os.Root); untrusted users must not
// be permitted to modify the root itself. Stores under /tmp are not durable.
func FileStorage(dir string) Storage { return &fileStorage{dir: dir} }

type fileStorage struct{ dir string }

func (s *fileStorage) open() (*os.Root, error) {
	if s.dir == "" {
		return nil, errors.New("empty storage directory")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, fmt.Errorf("open storage root: %w", err)
	}
	return root, nil
}

func (s *fileStorage) Get(key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	root, err := s.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("read storage key %q: %w", key, err)
	}
	return data, nil
}

func syncDirectory(root *os.Root, dir string) error {
	f, err := root.Open(dir)
	if err != nil {
		return fmt.Errorf("open storage directory %q: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync storage directory %q: %w", dir, err)
	}
	return nil
}

func (s *fileStorage) Put(key string, value []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	root, err := s.open()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	// Build one level at a time so newly-created directory entries are durable.
	dir := path.Dir(key)
	current := "."
	if dir != "." {
		for _, component := range strings.Split(dir, "/") {
			next := path.Join(current, component)
			err := root.Mkdir(next, 0700)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("create storage subdirectory %q: %w", next, err)
			}
			if err == nil {
				if err := syncDirectory(root, current); err != nil {
					return err
				}
			}
			current = next
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate temporary storage nonce: %w", err)
	}
	temp := path.Join(dir, ".tmp-"+hex.EncodeToString(nonce[:]))
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temporary storage file %q: %w", temp, err)
	}
	defer func() { _ = root.Remove(temp) }()
	if _, err = f.Write(value); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temporary storage file %q: %w", temp, err)
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temporary storage file %q: %w", temp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temporary storage file %q: %w", temp, err)
	}
	if err = root.Rename(temp, key); err != nil {
		return fmt.Errorf("rename temporary storage file %q to %q: %w", temp, key, err)
	}
	return syncDirectory(root, dir)
}

func (s *fileStorage) Delete(key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	root, err := s.open()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	err = root.Remove(key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove storage key %q: %w", key, err)
	}
	return syncDirectory(root, path.Dir(key))
}
