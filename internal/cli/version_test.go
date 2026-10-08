package cli

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestVersionCommand(t *testing.T) {
	oldTag, oldRevision, oldDate := Tag, SourceRevision, BuildDate
	Tag, SourceRevision, BuildDate = "v1.2.3", "0123456789abcdef", "2026-01-02T03:04:05Z"
	t.Cleanup(func() { Tag, SourceRevision, BuildDate = oldTag, oldRevision, oldDate })
	root := &cobra.Command{Use: "tool", RunE: func(*cobra.Command, []string) error {
		t.Fatal("version started the application")
		return nil
	}}
	root.Flags().String("required", "", "required application flag")
	if err := root.MarkFlagRequired("required"); err != nil {
		t.Fatal(err)
	}
	AddVersion(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "tool\ntag: v1.2.3\nsrcrev: 0123456789abcdef\ncompile date: 2026-01-02T03:04:05Z\n"
	if out.String() != want {
		t.Fatalf("version output = %q, want %q", out.String(), want)
	}
}

type failingVersionWriter struct{ err error }

func (w failingVersionWriter) Write([]byte) (int, error) { return 0, w.err }

func TestVersionWriteError(t *testing.T) {
	want := errors.New("write failed")
	root := &cobra.Command{Use: "tool", SilenceErrors: true, SilenceUsage: true}
	AddVersion(root)
	root.SetOut(failingVersionWriter{want})
	root.SetArgs([]string{"version"})
	if err := root.Execute(); !errors.Is(err, want) {
		t.Fatalf("version write error = %v, want %v", err, want)
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	root := &cobra.Command{Use: "tool", SilenceErrors: true, SilenceUsage: true}
	AddVersion(root)
	root.SetArgs([]string{"version", "extra"})
	if err := root.Execute(); err == nil {
		t.Fatal("version accepted an extra argument")
	}
}
