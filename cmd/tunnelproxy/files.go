package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// OpenRoot confines access to the selected directory, including symlink
// resolution. A lexical path-prefix check alone would not provide this boundary.
func newFileHandler(directory string, browse, revealSymlinks bool) (http.Handler, func() error, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, err
	}
	var filesystem http.FileSystem = http.FS(root.FS())
	if !browse {
		filesystem = noListingFS{filesystem}
	}
	files := http.FileServer(filesystem)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		info, err := root.Stat(name)
		if err == nil && info.IsDir() && !browse {
			index, err := root.Stat(path.Join(name, "index.html"))
			if err != nil || index.IsDir() {
				http.NotFound(w, r)
				return
			}
		}
		if err == nil && info.IsDir() && browse && revealSymlinks && strings.HasSuffix(r.URL.Path, "/") {
			// Preserve FileServer's canonical index redirects and index precedence.
			if _, indexErr := root.Stat(path.Join(name, "index.html")); indexErr != nil {
				revealedDirectory(w, r, root, name)
				return
			}
		}
		files.ServeHTTP(w, r)
	})
	return handler, root.Close, nil
}

var revealedDirectoryPage = template.Must(template.New("directory").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Path}}</title></head><body><pre>
{{range .Entries}}<a href="{{.URL}}">{{.Name}}</a>{{if .Target}} → {{.Target}}{{end}}
{{end}}</pre></body></html>`))

func revealedDirectory(w http.ResponseWriter, r *http.Request, root *os.Root, name string) {
	entries, err := fs.ReadDir(root.FS(), name)
	if err != nil {
		http.Error(w, "Unable to read directory", http.StatusForbidden)
		return
	}
	type entry struct {
		Name, URL, Target string
	}
	listing := make([]entry, 0, len(entries))
	for _, file := range entries {
		item := entry{Name: file.Name()}
		if file.IsDir() {
			item.Name += "/"
		}
		item.URL = (&url.URL{Path: "./" + item.Name}).String()
		if file.Type()&fs.ModeSymlink != 0 {
			// Show the stored target only; never open or serve an outside target.
			item.Target, _ = root.Readlink(path.Join(name, file.Name()))
		}
		listing = append(listing, item)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_ = revealedDirectoryPage.Execute(w, struct {
		Path    string
		Entries []entry
	}{r.URL.Path, listing})
}

// Block listing at the filesystem boundary too, so an index disappearing
// between the preliminary check and FileServer's open cannot enable browsing.
type noListingFS struct{ http.FileSystem }

func (f noListingFS) Open(name string) (http.File, error) {
	file, err := f.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	return noListingFile{file}, nil
}

type noListingFile struct{ http.File }

func (f noListingFile) Readdir(int) ([]fs.FileInfo, error) {
	return nil, fs.ErrPermission
}

type accessResponse struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *accessResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *accessResponse) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *accessResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func accessLogged(next http.Handler, out io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		response := &accessResponse{ResponseWriter: w}
		next.ServeHTTP(response, r)
		if response.status == 0 {
			response.status = http.StatusOK
		}
		// Never log auth headers, cookies, request bodies or URL queries. JSON
		// escaping prevents caller-controlled strings from forging log lines.
		record, _ := json.Marshal(struct {
			Time     time.Time `json:"time"`
			Remote   string    `json:"remote"`
			Method   string    `json:"method"`
			Path     string    `json:"path"`
			Status   int       `json:"status"`
			Bytes    int64     `json:"bytes"`
			Duration float64   `json:"duration_seconds"`
		}{start.UTC(), r.RemoteAddr, r.Method, r.URL.Path, response.status, response.bytes, time.Since(start).Seconds()})
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintln(out, string(record))
	})
}
